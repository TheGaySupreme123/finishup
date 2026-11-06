"""A receipt's workspace-provenance read never refuses the receipt and never drops its block.

ADR-051: a claim-bound task's text and markdown receipts end with the client-attested block,
decided from the session's opening event. Decision D4: when that event cannot be read, the
receipt is still built and its section says what happened, why it matters and what to do; a
retry once the read succeeds renders the binding. These drive the real ``Application`` facade
over the memory and SQLite ledgers of the respond/status/receipt harness.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any, Literal, cast

import pytest

from builders.ledger_adapters import MemoryObjects, ownership_fence
from builders.start_application import start_request
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.application.service import (
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectionRenderMode,
)
from finishup.domain.events import LedgerRecord, RedactionState
from finishup.domain.receipts import (
    CLIENT_ATTESTED_WORKSPACE_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    client_attested_receipt_block,
    workspace_provenance_unknown_block,
)
from finishup.domain.workspace_provenance import workspace_provenance_unknown_wire
from finishup.ports.control import ControlClientKind, ControlMethod, RepositoryPrivacyContext
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.ports.workspace_agent import workspace_handle_for_claim
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import ReceiptRequest, ReceiptResultModel, ReceiptSuccessModel
from integration.application.test_respond_status_receipt import (  # pyright: ignore[reportPrivateUsage]
    _bootstrap_finding,  # pyright: ignore[reportPrivateUsage]
    _build_app,  # pyright: ignore[reportPrivateUsage]
    _receipt_wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_COMMITMENT = "hmac-sha256:" + "c" * 64
_CLAIM = RepositoryPrivacyContext(
    _COMMITMENT,
    "client_claim",
    workspace_handle=workspace_handle_for_claim(_COMMITMENT, "sha256:" + "a1" * 32),
)


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
async def test_a_failed_attestation_read_records_the_receipt_and_a_retry_recovers(
    backend: Literal["memory", "sqlite"],
) -> None:
    """Decision D4: a failed lookup never refuses; the receipt says what happened and a retry
    once the fault clears renders the binding the opening event records."""

    app, runtime, _ = _build_app(seed_offset=49, ledger_backend=backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5600)
    ledger, objects = runtime.resources[started.task_id]
    faulty = _AttestationReadFails(ledger)
    runtime.resources[started.task_id] = (cast(Any, faulty), objects)
    receipts_before = objects.refs_for_kind(ObjectKind.RECEIPT)
    wire = _receipt_wire(
        5610,
        task_id=started.task_id,
        session=started.session_id,
        writer=started.writer_id,
        frontier=checked.result_frontier,
    )
    request = ReceiptRequest.model_validate({**wire, "format": "text"})
    unknown_block = "\n\n" + workspace_provenance_unknown_block(markdown=False)

    recorded = await app.receipt(request)
    assert len(objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipts_before) + 1
    assert await ledger.lookup_operation(started.writer_id, request.request_id) is not None
    assert recorded.human_text is not None
    assert recorded.human_text.endswith(unknown_block)
    assert recorded.human_text.count("Workspace evidence") == 1

    # The fault clears: running the same receipt again reads the opening, and this task is
    # not claim-bound, so the replay carries no workspace-evidence section at all.
    faulty.failing = False
    replayed = await app.receipt(request)
    assert replayed.receipt_id == recorded.receipt_id
    assert replayed.human_text is not None
    assert replayed.human_text == recorded.human_text.removesuffix(unknown_block)
    assert "Workspace evidence" not in replayed.human_text

    # A fault on the replay is shown the same way, never a refusal of a recorded receipt.
    faulty.failing = True
    again = await app.receipt(request)
    assert again.receipt_id == recorded.receipt_id
    assert again.human_text == recorded.human_text
    assert len(objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipts_before) + 1

    # A new receipt after the fault clears is built with its binding read.
    faulty.failing = False
    fresh = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **_receipt_wire(
                    5611,
                    task_id=started.task_id,
                    session=started.session_id,
                    writer=started.writer_id,
                    frontier=recorded.result_frontier,
                ),
                "format": "markdown",
            }
        )
    )
    assert fresh.receipt_id != recorded.receipt_id
    assert fresh.human_text is not None
    assert "Workspace evidence" not in fresh.human_text


async def test_a_claim_bound_receipt_shows_unknown_then_its_attested_block_on_retry() -> None:
    """The retry path of a claim-bound task: unknown while the lookup fails, then the
    client-attested block naming the serving service once it reads."""

    app, runtime, _ = _build_app(seed_offset=50)
    started = await app.start(
        start_request(5700, title="Claim-bound receipt"), repository_privacy_context=_CLAIM
    )
    ledger, objects = runtime.resources[started.task_id]
    faulty = _AttestationReadFails(ledger)
    runtime.resources[started.task_id] = (cast(Any, faulty), objects)
    request = ReceiptRequest.model_validate(
        {
            **_receipt_wire(
                5710,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=started.frontier,
            ),
            "format": "text",
        }
    )

    unknown = await app.receipt(request)
    assert unknown.human_text is not None
    assert unknown.human_text.endswith("\n\n" + workspace_provenance_unknown_block(markdown=False))
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in unknown.human_text

    faulty.failing = False
    attested = await app.receipt(request)
    assert attested.receipt_id == unknown.receipt_id
    assert attested.human_text is not None
    assert attested.human_text.endswith(
        "\n\n"
        + client_attested_receipt_block(ownership_fence().service_instance_id, markdown=False)
    )
    assert WORKSPACE_PROVENANCE_UNKNOWN_LINE not in attested.human_text


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
    request = ReceiptRequest.model_validate({**wire, "format": receipt_format})
    result = await app.receipt(request)
    # Decision D4: every format, JSON included, carries the fixed member. This harness's JSON
    # document predates the children section the public model requires, so the client
    # projection is driven for text and markdown; the unit tests admit the member on JSON.
    assert result.as_json()["workspace_provenance"] == workspace_provenance_unknown_wire()
    for context in (
        ()
        if receipt_format == "json"
        else (
            ClientProjectionContext(
                ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True, owner_view=True
            ),
            ClientProjectionContext(
                ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
            ),
        )
    ):
        projected = await _project(app, request, result, context)
        assert projected.workspace_provenance is not None
        assert projected.workspace_provenance.model_dump() == workspace_provenance_unknown_wire()
    if receipt_format == "json":
        assert result.human_text is None
        return
    assert result.human_text is not None
    block = workspace_provenance_unknown_block(markdown=receipt_format == "markdown")
    assert result.human_text.endswith("\n\n" + block)
    assert result.human_text.count("Workspace evidence") == 1


@pytest.mark.parametrize("receipt_format", ["text", "markdown"])
async def test_a_receipt_whose_binding_was_read_carries_no_provenance_member(
    receipt_format: Literal["text", "markdown", "json"],
) -> None:
    app, _runtime, _ = _build_app(seed_offset=51)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5800)
    request = ReceiptRequest.model_validate(
        {
            **_receipt_wire(
                5810,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=checked.result_frontier,
            ),
            "format": receipt_format,
        }
    )
    result = await app.receipt(request)
    assert "workspace_provenance" not in result.as_json()
    projected = await _project(
        app,
        request,
        result,
        ClientProjectionContext(
            ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True, owner_view=True
        ),
    )
    assert projected.workspace_provenance is None


_CONTEXTS: dict[str, ClientProjectionContext] = {
    "cli_owner": ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True, owner_view=True
    ),
    "cli_agent": ClientProjectionContext(
        ControlClientKind.CLI, ProjectionRenderMode.HUMAN_READABLE, True
    ),
    "mcp": ClientProjectionContext(
        ControlClientKind.MCP_BRIDGE, ProjectionRenderMode.MACHINE_READABLE, False
    ),
}


def _render_long(monkeypatch: pytest.MonkeyPatch, length: int) -> None:
    """Every receipt renders ``length`` characters before its closing section.

    The first section's body is padded so the real renderer, bound included, runs on a receipt
    whose other sections already fill the 32,768-character ``human_text`` bound (or nearly).
    """

    from finishup.application import receipt as receipt_module

    real = receipt_module.render_receipt_human

    def render(document: Any, *, markdown: bool, trailer: str | None = None) -> str:  # noqa: ANN401
        first = document.sections[0]

        def with_body(size: int) -> Any:  # noqa: ANN401
            return replace(
                document, sections=(replace(first, body="x" * size), *document.sections[1:])
            )

        padded = with_body(1 + length - len(real(with_body(1), markdown=markdown)))
        assert len(real(padded, markdown=markdown)) == length
        return real(padded, markdown=markdown, trailer=trailer)

    monkeypatch.setattr(receipt_module, "render_receipt_human", render)


@pytest.mark.parametrize("length", [32_400, 32_768])
@pytest.mark.parametrize("receipt_format", ["text", "markdown"])
async def test_a_long_receipt_of_unknown_provenance_is_delivered_with_its_section(
    receipt_format: Literal["text", "markdown"],
    length: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decision D4 at the wire bound: the closing section's room is reserved, so a receipt whose
    text already fills the bound still validates for every client and ends with the section."""

    from finishup.application import receipt as receipt_module

    unknown = getattr(receipt_module, "_Provenance").UNKNOWN

    async def opening_cannot_say(runtime: object, *, request_id: str | None = None) -> object:
        del runtime, request_id
        return unknown

    monkeypatch.setattr(receipt_module, "_attested_by", opening_cannot_say)
    _render_long(monkeypatch, length)
    app, _runtime, _ = _build_app(seed_offset=52)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5900)
    request = ReceiptRequest.model_validate(
        {
            **_receipt_wire(
                5910,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=checked.result_frontier,
            ),
            "format": receipt_format,
        }
    )
    block = workspace_provenance_unknown_block(markdown=receipt_format == "markdown")

    result = await app.receipt(request)

    assert result.human_text is not None
    assert len(result.human_text) <= 32_768
    assert result.human_text.endswith("\n\n" + block)
    for context in _CONTEXTS.values():
        projected = await _project(app, request, result, context)
        assert isinstance(projected.human_text, str)
        assert projected.human_text.endswith("\n\n" + block)
        assert projected.workspace_provenance is not None


@pytest.mark.parametrize("receipt_format", ["text", "markdown"])
async def test_a_long_claim_bound_receipt_is_delivered_with_its_attested_section(
    receipt_format: Literal["text", "markdown"], monkeypatch: pytest.MonkeyPatch
) -> None:
    _render_long(monkeypatch, 32_768)
    app, _runtime, _ = _build_app(seed_offset=53)
    started = await app.start(
        start_request(5950, title="Long claim-bound receipt"), repository_privacy_context=_CLAIM
    )
    request = ReceiptRequest.model_validate(
        {
            **_receipt_wire(
                5960,
                task_id=started.task_id,
                session=started.session_id,
                writer=started.writer_id,
                frontier=started.frontier,
            ),
            "format": receipt_format,
        }
    )
    block = client_attested_receipt_block(
        ownership_fence().service_instance_id, markdown=receipt_format == "markdown"
    )

    result = await app.receipt(request)

    assert result.human_text is not None
    assert len(result.human_text) <= 32_768
    assert result.human_text.endswith("\n\n" + block)
    for context in _CONTEXTS.values():
        projected = await _project(app, request, result, context)
        assert isinstance(projected.human_text, str)
        assert projected.human_text.endswith("\n\n" + block)
        assert projected.workspace_provenance is None


async def _project(
    app: Any,  # noqa: ANN401
    request: ReceiptRequest,
    result: Any,  # noqa: ANN401
    context: ClientProjectionContext,
) -> ReceiptSuccessModel:
    """The public receipt a client receives: the service's own projection and validation."""

    facts = await app.projection_binding_facts(ControlMethod.RECEIPT, request, result)
    rpc_id = "rpc_00000000-0000-4000-8000-000000005901"
    service_instance_id = ownership_fence().service_instance_id
    binding = ControlProjectionBinding(
        rpc_id,
        ControlMethod.RECEIPT,
        service_instance_id,
        1,
        facts.original_request_id,
        facts.route_identity_digest,
        canonical_encode(
            {
                "rpc_id": rpc_id,
                "method": "receipt",
                "service_instance_id": service_instance_id,
                "service_generation": "1",
            }
        ),
    )
    projected = await app.project_result_for_client(context, binding, result)
    assert isinstance(projected, ReceiptResultModel)
    success = projected.root
    assert isinstance(success, ReceiptSuccessModel)
    return success
