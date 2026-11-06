"""Client wait cancellation cannot restart an admitted semantic operation."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest

from finishup.ports.control import ControlError, ControlMethod, ControlResult
from finishup.ports.ledger import check_admission_stage
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import CheckResult
from finishup.protocol.recovery import directive_for
from finishup.service.check_waits import (
    CAPACITY_RETRY_AFTER_MS,
    EXPLICIT_CONTROL_CANCEL,
    MAX_RETAINED_CHECKS,
    CheckWaits,
)
from finishup.service.control_protocol import validate_result

_CAPACITY_DETAILS = {
    "continuation": "check_service_busy_same_identity",
    "limit": 8,
    "retry_after_ms": 30_000,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_disconnect_preserves_work_and_replay_reports_pending() -> None:
    waits = CheckWaits()
    entered, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
    calls = 0

    async def work() -> object:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        finished.set()
        return "complete"

    waiter = asyncio.create_task(waits.run(("writer", "request"), "digest", work, None))
    try:
        await entered.wait()
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        with pytest.raises(PublicOperationError) as pending:
            await waits.run(("writer", "request"), "digest", work, None)
        assert pending.value.code is PublicErrorCode.OPERATION_PENDING
        with pytest.raises(PublicOperationError) as conflict:
            await waits.run(("writer", "request"), "different", work, None)
        assert conflict.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT
        assert calls == 1 and not finished.is_set()
        release.set()
        await finished.wait()
    finally:
        release.set()
        await waits.close()


@pytest.mark.anyio
async def test_wait_deadline_preserves_work_until_shutdown_joins_it() -> None:
    waits = CheckWaits()
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def work() -> object:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    try:
        with pytest.raises(ControlError) as timeout:
            await waits.run(("writer", "request"), "digest", work, 10)
        assert timeout.value.reason == "request_timeout"
        assert entered.is_set() and not cancelled.is_set()
    finally:
        await waits.close()
    assert cancelled.is_set()
    with pytest.raises(ControlError) as stopped:
        await waits.run(("writer", "next"), "digest", work, None)
    assert stopped.value.reason == "service_draining"


@pytest.mark.anyio
async def test_explicit_control_cancel_stops_attached_work() -> None:
    waits = CheckWaits()
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def work() -> object:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    waiter = asyncio.create_task(waits.run(("writer", "request"), "digest", work, None))
    await entered.wait()
    waiter.cancel(EXPLICIT_CONTROL_CANCEL)
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert cancelled.is_set()
    await waits.close()


@pytest.mark.anyio
async def test_detached_failure_is_observed_without_retaining_a_result() -> None:
    waits = CheckWaits()
    entered, release, completed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def work() -> object:
        entered.set()
        await release.wait()
        raise ValueError("synthetic_failure")

    waiter = asyncio.create_task(waits.run(("writer", "request"), "digest", work, None))
    await entered.wait()
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    # A callback after the manager's callback establishes that failure collection completed.
    task = waits._tasks[("writer", "request")][1]  # pyright: ignore[reportPrivateUsage]
    task.add_done_callback(lambda _task: completed.set())
    release.set()
    await completed.wait()
    assert not waits._tasks  # pyright: ignore[reportPrivateUsage]
    await waits.close()


@pytest.mark.anyio
async def test_retained_waiters_have_a_fixed_capacity() -> None:
    """Issue #1309: a check over capacity gets a typed, retryable workflow refusal.

    It used to be a control-level ``service_unavailable`` that no control-result error body
    admits, so the daemon could not frame its own answer. The refusal runs nothing; an exact
    replay of a retained check still reports it pending, and a freed slot admits the next one.
    """

    waits = CheckWaits()
    entered = asyncio.Queue[None]()
    release = asyncio.Event()
    calls = 0

    async def work() -> object:
        nonlocal calls
        calls += 1
        await entered.put(None)
        await release.wait()
        return "complete"

    blocked = asyncio.Event()

    async def blocked_work() -> object:
        nonlocal calls
        calls += 1
        await entered.put(None)
        await blocked.wait()
        return "complete"

    waiters = [
        asyncio.create_task(waits.run(("writer", str(index)), "digest", blocked_work, None))
        for index in range(MAX_RETAINED_CHECKS - 1)
    ]
    waiters.append(asyncio.create_task(waits.run(("writer", "freed"), "digest", work, None)))
    try:
        assert MAX_RETAINED_CHECKS == 8
        for _ in waiters:
            await entered.get()
        with pytest.raises(PublicOperationError) as busy:
            await waits.run(("writer", "overflow"), "digest", work, None)
        refusal = busy.value
        assert refusal.code is PublicErrorCode.BUNDLE_BUSY
        assert refusal.retryable is True
        assert dict(refusal.safe_details) == _CAPACITY_DETAILS
        assert refusal.correlation_id is not None
        assert "limit of 8 checks" in refusal.message
        assert calls == MAX_RETAINED_CHECKS
        # A retained check keeps its own answer; capacity never masks it.
        with pytest.raises(PublicOperationError) as pending:
            await waits.run(("writer", "0"), "digest", blocked_work, None)
        assert pending.value.code is PublicErrorCode.OPERATION_PENDING
        assert "reason_code" not in pending.value.safe_details
        with pytest.raises(PublicOperationError) as conflict:
            await waits.run(("writer", "0"), "different", blocked_work, None)
        assert conflict.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT
        # One retained check finishing frees exactly one slot for the refused request's replay.
        release.set()
        assert await waiters[-1] == "complete"
        release.clear()
        replay = asyncio.create_task(waits.run(("writer", "overflow"), "digest", work, None))
        await entered.get()
        assert calls == MAX_RETAINED_CHECKS + 1
        release.set()
        assert await replay == "complete"
    finally:
        release.set()
        blocked.set()
        await asyncio.gather(*waiters, return_exceptions=True)
        await waits.close()


@pytest.mark.anyio
async def test_capacity_refusal_never_claims_a_finished_check_is_unrecorded() -> None:
    """Review of #1309: a finished check is no longer retained, but its result is in the ledger.

    A check whose client stopped waiting finishes detached and leaves the service's waits. Its
    exact replay is the documented recovery (a completed operation replays from its ledger). At
    capacity that replay is refused before the operation, and so before any ledger read: the
    refusal must not reuse an admission stage whose directive says nothing is recorded or that
    the check was not admitted. Once a slot frees, the replay reaches the operation again,
    which in the service is the path that answers from the ledger.
    """

    waits = CheckWaits()
    entered = asyncio.Queue[str]()
    finish, blocked = asyncio.Event(), asyncio.Event()
    calls: list[str] = []

    def operation(label: str, gate: asyncio.Event) -> Callable[[], Awaitable[object]]:
        async def run() -> object:
            calls.append(label)
            await entered.put(label)
            await gate.wait()
            return label

        return run

    finished_key = ("writer", "finished")
    detached = asyncio.create_task(
        waits.run(finished_key, "digest", operation("finished", finish), None)
    )
    assert await entered.get() == "finished"
    detached.cancel()
    with pytest.raises(asyncio.CancelledError):
        await detached
    retained = waits._tasks[finished_key][1]  # pyright: ignore[reportPrivateUsage]
    finish.set()
    # The manager's done callback was registered first, so it has run once this wait returns.
    await asyncio.wait((retained,))
    assert finished_key not in waits._tasks  # pyright: ignore[reportPrivateUsage]

    holders = [
        asyncio.create_task(
            waits.run(("writer", str(index)), "digest", operation(str(index), blocked), None)
        )
        for index in range(MAX_RETAINED_CHECKS)
    ]
    try:
        for _ in holders:
            await entered.get()
        with pytest.raises(PublicOperationError) as busy:
            await waits.run(finished_key, "digest", operation("replay", finish), None)
        refusal = busy.value
        assert calls.count("replay") == 0
        assert refusal.code is PublicErrorCode.BUNDLE_BUSY
        assert refusal.retryable is True
        assert dict(refusal.safe_details) == _CAPACITY_DETAILS
        assert check_admission_stage(refusal) is None
        directive = directive_for("check_service_busy_same_identity")
        assert directive is not None
        for text in (refusal.message, directive.directive, directive.nudge or ""):
            lowered = text.lower()
            assert "nothing is recorded" not in lowered
            assert "not admitted" not in lowered
        assert "did not look up" in refusal.message
        assert "did not look up" in directive.directive
        blocked.set()
        await asyncio.gather(*holders)
        assert await waits.run(finished_key, "digest", operation("replay", finish), None) == (
            "replay"
        )
        assert calls.count("replay") == 1
    finally:
        finish.set()
        blocked.set()
        await asyncio.gather(*holders, return_exceptions=True)
        await waits.close()


async def _overflow_refusal() -> PublicOperationError:
    """Fill the service's check waits, then return the refusal a new check receives."""

    waits = CheckWaits()
    blocked = asyncio.Event()
    entered = asyncio.Queue[None]()

    async def work() -> object:
        await entered.put(None)
        await blocked.wait()
        return "complete"

    waiters = [
        asyncio.create_task(waits.run(("writer", str(index)), "digest", work, None))
        for index in range(MAX_RETAINED_CHECKS)
    ]
    try:
        for _ in waiters:
            await entered.get()
        with pytest.raises(PublicOperationError) as busy:
            await waits.run(("writer", new_id(IdKind.REQUEST)), "digest", work, None)
    finally:
        blocked.set()
        await asyncio.gather(*waiters, return_exceptions=True)
        await waits.close()
    return busy.value


@pytest.mark.anyio
async def test_capacity_refusal_frames_as_a_valid_control_result() -> None:
    """Issue #1309 reproduction: the daemon's framing of the refusal passes ``validate_result``.

    The daemon frames a workflow ``PublicOperationError`` as ``outcome=ok`` with an ``ok: false``
    check result. On ``main`` the refusal was a ``ControlError`` framed as ``outcome=error``,
    and ``validate_result`` rejected it as ``frame_invalid``.
    """

    refusal = await _overflow_refusal()
    body = CheckResult.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "ok": False,
            "error": refusal.as_public_dict(),
        }
    )
    result = ControlResult(
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=new_id(IdKind.SERVICE_INSTANCE),
        service_generation="1",
        method=ControlMethod.CHECK,
        outcome="ok",
        body=body,
    )
    validate_result(result)


@pytest.mark.anyio
async def test_capacity_refusal_correlation_names_the_capacity_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review of #1309: the correlation id resolves to a capacity record, not an input race.

    The refusal binds the id of its own diagnostic record, so the daemon reuses it instead of
    recording a generic ``check_public_error`` and an operator can tell the cause apart.
    """

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    refusal = await _overflow_refusal()
    records = diagnostics.lookup_diagnostic_records(refusal.correlation_id, root=tmp_path)
    assert [
        (record.get("component"), record.get("operation"), record.get("reason"))
        for record in records
    ] == [("service.check_waits", "check_service_busy", "bundle_busy")]
    assert all("reason_code" not in record for record in records)


@pytest.mark.anyio
async def test_capacity_refusal_reads_as_retry_later_on_cli_and_mcp() -> None:
    """Issue #1309: the CLI and the MCP text channel both say what happened and what to do.

    The CLI prints the fixed message (the service's limit, and that the request was not looked
    up) and the full directive; the MCP text channel, which never echoes the message, names the
    retryable code and the same directive. The directive's wait matches the refusal's own
    ``retry_after_ms``, because the MCP text channel does not print that number.
    """

    from finishup.cli.render import render_human_error
    from finishup.mcp.summaries import summary_for_public_error
    from finishup.protocol.models import PublicErrorModel

    refusal = await _overflow_refusal()
    wire = refusal.as_public_dict()
    directive = directive_for("check_service_busy_same_identity")
    assert directive is not None
    assert CAPACITY_RETRY_AFTER_MS == 30_000
    assert "retry_after_ms (30 s)" in directive.directive

    cli = render_human_error(PublicErrorModel.model_validate(wire)).splitlines()
    assert cli[0] == (
        "BUNDLE_BUSY: The FinishUP service already has its limit of 8 checks in progress, so it "
        "did not look up or start this check. Wait, then replay the exact request; the replay is "
        "answered from anything already recorded under this request_id. (retryable)"
    )
    assert "Continuation: check_service_busy_same_identity" in cli
    assert f"Next: {directive.directive}" in cli

    mcp = summary_for_public_error({"ok": False, "error": wire})
    assert mcp.startswith("Error BUNDLE_BUSY; retryable: yes; correlation: err_")
    assert "Continuation: check_service_busy_same_identity." in mcp
    assert directive.directive in mcp
    assert "check_admission" not in mcp


@pytest.mark.anyio
async def test_read_window_admits_only_while_open_and_close_drains_readers() -> None:
    """Issue #571 A2: the gate owner cannot release its gates under an admitted reader."""

    from finishup.service.check_waits import CheckReadWindow

    window = CheckReadWindow()
    assert not window.admits_readers
    with pytest.raises(RuntimeError):
        window.enter()
    window.open()
    assert window.admits_readers
    window.enter()
    closing = asyncio.create_task(window.close())
    done, _pending = await asyncio.wait({closing}, timeout=0)
    # Closing stops new admissions at once but waits for the active reader.
    assert not window.admits_readers
    assert not done
    with pytest.raises(RuntimeError):
        window.enter()
    window.leave()
    await asyncio.wait_for(closing, timeout=1.0)
    with pytest.raises(RuntimeError):
        window.leave()
