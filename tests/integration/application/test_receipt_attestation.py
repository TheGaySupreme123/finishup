"""A receipt's workspace-provenance read happens before it writes, and never drops its block.

ADR-051: a claim-bound task's text and markdown receipts end with the client-attested block,
decided from the session's opening event. These drive the real ``Application`` facade over the
memory and SQLite ledgers of the respond/status/receipt harness.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Literal, cast

import pytest

from builders.ledger_adapters import MemoryObjects, ownership_fence
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.events import LedgerRecord, RedactionState
from finishup.domain.receipts import workspace_provenance_unknown_block
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import ReceiptRequest
from integration.application.test_respond_status_receipt import (  # pyright: ignore[reportPrivateUsage]
    _bootstrap_finding,  # pyright: ignore[reportPrivateUsage]
    _build_app,  # pyright: ignore[reportPrivateUsage]
    _receipt_wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio


class _OpeningObjectFails:
    """The task's real object store, except that opening one object raises ``failure``.

    It stands in for storage under a SQLite ledger's recovery: the session opening's payload
    object is missing (``KeyError``), fails verification (``ValueError``) or hits an
    environmental fault (``OSError``) while ``failure`` is set.
    """

    def __init__(self, objects: MemoryObjects, object_id: str, failure: Exception) -> None:
        self._objects = objects
        self._object_id = object_id
        self.failure: Exception | None = failure

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        return getattr(self._objects, name)

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        failure = self.failure
        if failure is None or ref.object_id != self._object_id:
            return self._objects.open_verified(ref)

        async def fail() -> AsyncIterator[bytes]:
            raise failure
            yield b""  # pragma: no cover - makes this an async generator

        return fail()


@pytest.mark.parametrize(
    "failure",
    [
        OSError(5, "input/output error"),
        KeyError("object_missing"),
        ValueError("object_verification_failed"),
    ],
    ids=["environmental", "missing", "unverifiable"],
)
async def test_an_opening_recovery_could_not_read_leaves_the_receipt_unknown_until_reopened(
    failure: Exception,
) -> None:
    """The real SQLite recovery keeps an opening payload it could not read as None (finding A6).

    The ledger holds that gap for as long as the task stays open, so no retry against it reads
    the object: the receipt is built and says the binding is unknown, never refused under a
    retryable flag, never with the section silently left out. Once the task is reopened and the
    object reads, a replay of the same request renders the binding the opening event records.
    """

    app, runtime, _ = _build_app(seed_offset=47, ledger_backend="sqlite")
    started, checked, _obligation = await _bootstrap_finding(app, seed=5400)
    ledger, objects = runtime.resources[started.task_id]
    opening = None
    async for record in ledger.load_events(started.session_id):
        if record.schema.name == "session_opened":
            opening = record
            break
    assert opening is not None
    generation = runtime.owners[(started.session_id, started.writer_id)]
    db = runtime.sqlite_connections[-1]

    def reopened(store: object) -> SqliteLedger:
        """A fresh ledger on the same bundle, so its first read runs the real recovery."""

        return SqliteLedger(
            db=db,
            task_id=started.task_id,
            ownership_fence=ownership_fence(generation=generation),
            clock=runtime.clock,
            ids=runtime.ids,
            objects=cast(Any, store),
        )

    storage = _OpeningObjectFails(objects, opening.payload_ref.object_id, failure)
    recovered = reopened(storage)
    runtime.resources[started.task_id] = (cast(Any, recovered), objects)
    recovered_opening = None
    async for record in recovered.load_events(started.session_id):
        if record.schema.name == "session_opened":
            recovered_opening = record
            break
    assert recovered_opening is not None
    assert recovered_opening.redaction is RedactionState.PRESENT
    assert recovered_opening.payload is None

    receipts_before = objects.refs_for_kind(ObjectKind.RECEIPT)
    wire = _receipt_wire(
        5410,
        task_id=started.task_id,
        session=started.session_id,
        writer=started.writer_id,
        frontier=checked.result_frontier,
    )
    request = ReceiptRequest.model_validate({**wire, "format": "text"})
    unknown_block = "\n\n" + workspace_provenance_unknown_block(markdown=False)

    recorded = await app.receipt(request)
    assert len(objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipts_before) + 1
    assert recorded.human_text is not None
    assert recorded.human_text.endswith(unknown_block)
    assert recorded.human_text.count("Workspace evidence") == 1

    # Storage reads normally again, but this ledger keeps the gap: a replay still cannot say.
    storage.failure = None
    replayed = await app.receipt(request)
    assert replayed.receipt_id == recorded.receipt_id
    assert replayed.human_text == recorded.human_text

    # Reopened, the task's recovery reads the opening: this task is not claim-bound, so the
    # replay of the same receipt carries no workspace-evidence section at all.
    runtime.resources[started.task_id] = (cast(Any, reopened(objects)), objects)
    healed = await app.receipt(request)
    assert healed.receipt_id == recorded.receipt_id
    assert healed.human_text is not None
    assert healed.human_text == recorded.human_text.removesuffix(unknown_block)
    assert "Workspace evidence" not in healed.human_text
    assert len(objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipts_before) + 1


class _AttestationReadFails:
    """A task ledger whose whole-session read (the attestation's) raises ``OSError`` while set.

    Every bounded read (``through=``) and every other method is the real ledger's, so the fault
    lands on the attestation read alone. A raised ``OSError`` is per call: the next read tries
    again, as a real environmental fault does.
    """

    def __init__(self, ledger: Any) -> None:  # noqa: ANN401
        self._ledger = ledger
        self.failing = True

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        return getattr(self._ledger, name)

    async def _events(self, session_id: str, **kwargs: Any) -> AsyncIterator[LedgerRecord]:  # noqa: ANN401
        if self.failing and kwargs.get("through") is None:
            raise OSError(5, "input/output error")
        async for record in self._ledger.load_events(session_id, **kwargs):
            yield record

    def load_events(self, session_id: str, **kwargs: Any) -> AsyncIterator[LedgerRecord]:  # noqa: ANN401
        return self._events(session_id, **kwargs)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_failed_attestation_read_refuses_the_receipt_before_any_write(
    backend: Literal["memory", "sqlite"],
) -> None:
    """The read comes before staging and append, so a refusal leaves nothing recorded."""

    app, runtime, _ = _build_app(seed_offset=49, ledger_backend=backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5600)
    ledger, objects = runtime.resources[started.task_id]
    faulty = _AttestationReadFails(ledger)
    runtime.resources[started.task_id] = (cast(Any, faulty), objects)
    receipts_before = objects.refs_for_kind(ObjectKind.RECEIPT)
    payloads_before = objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)
    head_before = await ledger.load_frontier()
    wire = _receipt_wire(
        5610,
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

    # The fault clears, and the same request records the receipt.
    faulty.failing = False
    recorded = await app.receipt(request)
    assert len(objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipts_before) + 1
    assert recorded.human_text is not None
    assert "Workspace evidence" not in recorded.human_text

    # Its replay reads the event too, and refuses the same way rather than drop the block.
    faulty.failing = True
    with pytest.raises(PublicOperationError) as replay_refused:
        await app.receipt(request)
    assert replay_refused.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert replay_refused.value.retryable is True
    faulty.failing = False
    replayed = await app.receipt(request)
    assert replayed.receipt_id == recorded.receipt_id
    assert replayed.human_text == recorded.human_text


@pytest.mark.parametrize("receipt_format", ["text", "markdown", "json"])
async def test_an_unknown_binding_ends_a_human_receipt_with_the_fixed_unknown_block(
    receipt_format: Literal["text", "markdown", "json"], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A redacted or unreadable opening event never leaves the section out silently."""

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
