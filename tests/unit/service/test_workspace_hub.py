"""The workspace-agent hub: bounded, typed calls to a claim-bound connection's agent (ADR-051)."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

import pytest

from finishup.ports.approved_checks import ApprovedCheckApproval, approval_commitment
from finishup.ports.change_capture import TaskChangeBase
from finishup.ports.control import WorkspaceAgentDeclaration, WorkspaceCall, WorkspaceReply
from finishup.ports.workspace_agent import (
    WORKSPACE_OPERATION_NAMES,
    RunApprovedCheckArguments,
    WorkspaceAgentUnavailable,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    operation_spec,
    workspace_handle_for_claim,
)
from finishup.service.workspace_hub import (
    MAX_CALLS_PER_CHANNEL,
    WorkspaceAgentChannel,
    WorkspaceAgentHub,
    in_live_call,
    live_call_scope,
    workspace_call_deadline,
)

pytestmark = pytest.mark.anyio

_HANDLE = "client:0123456789abcdef"
_INSTANCE = "svc_00000000-0000-4000-8000-000000000051"
_BASE = TaskChangeBase("sha1", "a" * 40)
_ARGS = WorkspaceOnlyArguments(_HANDLE)


def _declaration(*operations: str) -> WorkspaceAgentDeclaration:
    names = operations or WORKSPACE_OPERATION_NAMES
    return WorkspaceAgentDeclaration(tuple(sorted(names, key=str.encode)), 6_291_456)


def _ok(call: WorkspaceCall, value: object) -> WorkspaceReply:
    spec = operation_spec(call.operation)
    assert spec is not None
    return WorkspaceReply(
        "workspace_reply", "1.0", call.call_id, "ok", spec.encode_result(value), None
    )


def _failure(call: WorkspaceCall, outcome: str, reason: str) -> WorkspaceReply:
    return WorkspaceReply("workspace_reply", "1.0", call.call_id, outcome, None, reason)  # pyright: ignore[reportArgumentType]


async def _register(
    hub: WorkspaceAgentHub,
    answer: Callable[[WorkspaceCall], WorkspaceReply | None],
    *,
    declaration: WorkspaceAgentDeclaration | None = None,
    sent: list[WorkspaceCall] | None = None,
    handle: str = _HANDLE,
    worktree: str | None = None,
) -> WorkspaceAgentChannel:
    holder: list[WorkspaceAgentChannel] = []

    async def writer(call: WorkspaceCall) -> None:
        if sent is not None:
            sent.append(call)
        reply = answer(call)
        if reply is not None:
            asyncio.get_running_loop().call_soon(hub.deliver, holder[0], reply)

    channel = await hub.register(
        handle=handle,
        declaration=declaration or _declaration(),
        service_instance_id=_INSTANCE,
        service_generation="7",
        writer=writer,
        worktree=worktree,
    )
    holder.append(channel)
    return channel


def _hub(wait: float = 0.2) -> WorkspaceAgentHub:
    return WorkspaceAgentHub(inline_wait_seconds=wait, background_wait_seconds=wait)


_DEADLINE_SECONDS = 10.0


async def _until(condition: Callable[[], bool], *, interval: float = 0.0) -> None:
    """Yield to the loop until ``condition`` holds; fail once the deadline passes without it."""

    loop = asyncio.get_running_loop()
    deadline = loop.time() + _DEADLINE_SECONDS
    while not condition():
        assert loop.time() < deadline, "deadline passed before the state was observed"
        await asyncio.sleep(interval)


async def test_a_call_is_framed_for_the_agents_connection_and_decodes_its_answer() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=sent)

    base = await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)

    assert base == _BASE
    (call,) = sent
    assert call.operation == "read_task_base"
    assert call.service_instance_id == _INSTANCE and call.service_generation == "7"
    assert call.arguments == {"workspace": _HANDLE}
    assert 1 <= call.deadline_ms <= 2_000


async def test_no_agent_within_the_wait_is_typed_no_agent() -> None:
    hub = _hub(0.05)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "no_agent" and caught.value.agent_reason is None


async def test_a_call_waits_for_an_agent_that_connects_within_the_bound() -> None:
    hub = _hub(2.0)
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)
    )
    await asyncio.sleep(0)
    await _register(hub, lambda call: _ok(call, _BASE))
    assert await pending == _BASE


async def test_live_calls_wait_less_than_background_work() -> None:
    hub = WorkspaceAgentHub(inline_wait_seconds=0.01, background_wait_seconds=5.0)
    assert not in_live_call()
    with live_call_scope():
        assert in_live_call()
        with pytest.raises(WorkspaceAgentUnavailable):
            await asyncio.wait_for(
                hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0),
                1.0,
            )
    background = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    )
    with live_call_scope():
        live = asyncio.create_task(
            hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
        )
    # Started just after the background call, the live call has already given up waiting.
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(live, 1.0)
    assert caught.value.reason == "no_agent"
    assert not background.done()  # still inside the longer background wait
    await _register(hub, lambda call: _ok(call, _BASE))
    assert await background == _BASE


@pytest.mark.parametrize(
    ("outcome", "agent_reason", "reason"),
    (
        ("refused", "workspace_not_claimed", "agent_refused"),
        ("unavailable", "not_git", "agent_unavailable"),
        ("failed", "internal_error", "agent_failed"),
    ),
)
async def test_an_agents_own_answer_keeps_its_closed_reason(
    outcome: str, agent_reason: str, reason: str
) -> None:
    hub = _hub()
    await _register(hub, lambda call: _failure(call, outcome, agent_reason))
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert (caught.value.reason, caught.value.agent_reason) == (reason, agent_reason)
    assert caught.value.refused is (reason == "agent_refused")


async def test_a_reply_that_is_not_the_operations_result_is_reply_invalid() -> None:
    hub = _hub()
    await _register(
        hub,
        lambda call: WorkspaceReply(
            "workspace_reply", "1.0", call.call_id, "ok", {"not": "a base"}, None
        ),
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "reply_invalid"


async def test_no_reply_by_the_deadline_is_deadline_exceeded_and_a_late_reply_is_dropped() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    channel = await _register(hub, lambda _call: None, sent=sent)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.05)
    assert caught.value.reason == "deadline_exceeded"
    assert channel.pending_count == 0
    hub.deliver(channel, _ok(sent[0], _BASE))  # nothing awaits it any more; ignored


async def test_a_dropped_connection_fails_its_pending_calls_at_once() -> None:
    hub = _hub()
    channel = await _register(hub, lambda _call: None)
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=30.0)
    )
    await _until(lambda: channel.pending_count > 0)
    await hub.unregister(channel)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 1.0)
    assert caught.value.reason == "agent_disconnected"
    assert not hub.has_agent(_HANDLE)


async def test_a_connection_that_cannot_take_the_frame_is_disconnected() -> None:
    hub = _hub()

    async def broken(_call: WorkspaceCall) -> None:
        raise ConnectionResetError("gone")

    await hub.register(
        handle=_HANDLE,
        declaration=_declaration(),
        service_instance_id=_INSTANCE,
        service_generation="7",
        writer=broken,
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "agent_disconnected"


async def test_an_agent_that_declared_other_operations_is_not_asked() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    await _register(
        hub, lambda call: _ok(call, _BASE), declaration=_declaration("capture"), sent=sent
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "operation_not_declared"
    assert sent == []


async def test_one_connection_serves_a_bounded_number_of_calls_at_once() -> None:
    hub = _hub()
    held: list[WorkspaceCall] = []
    channel = await _register(hub, lambda _call: None, sent=held)
    calls = [
        asyncio.create_task(
            hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
        )
        for _ in range(MAX_CALLS_PER_CHANNEL)
    ]
    await _until(lambda: len(held) == MAX_CALLS_PER_CHANNEL)
    # One call more waits for a slot within its own bound, is never sent, and says so.
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.1)
    assert caught.value.reason == "agent_busy"
    assert len(held) == MAX_CALLS_PER_CHANNEL
    for call in held:
        hub.deliver(channel, _ok(call, _BASE))
    assert await asyncio.gather(*calls) == [_BASE] * MAX_CALLS_PER_CHANNEL


_COMMITMENT = "hmac-sha256:" + "0a" * 32
_WORKTREE_MAIN = "sha256:" + "1" * 64
_WORKTREE_LINKED = "sha256:" + "2" * 64


async def test_linked_worktrees_have_their_own_handles_and_their_own_agents() -> None:
    """ADR-051: one repository commitment, one handle per worktree; never another tree's agent."""

    hub = _hub()
    main = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_MAIN)
    linked = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_LINKED)
    assert main != linked
    main_calls: list[WorkspaceCall] = []
    linked_calls: list[WorkspaceCall] = []
    await _register(
        hub, lambda call: _ok(call, _BASE), sent=main_calls, handle=main, worktree=_WORKTREE_MAIN
    )
    # The linked worktree's agent connects later: it must never answer the main tree's task.
    await _register(
        hub,
        lambda call: _ok(call, _BASE),
        sent=linked_calls,
        handle=linked,
        worktree=_WORKTREE_LINKED,
    )
    for handle in (main, main, linked):
        arguments = WorkspaceOnlyArguments(handle)
        await hub.call(handle, WorkspaceOperation.READ_TASK_BASE, arguments, timeout_seconds=1.0)
    assert [call.arguments["workspace"] for call in main_calls] == [main, main]
    assert [call.arguments["workspace"] for call in linked_calls] == [linked]


async def test_an_agent_of_another_worktree_is_never_admitted_under_a_handle() -> None:
    hub = _hub()
    first: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=first, worktree=_WORKTREE_MAIN)
    with pytest.raises(ValueError, match="workspace_agent_worktree_conflict"):
        await _register(hub, lambda call: _ok(call, _BASE), worktree=_WORKTREE_LINKED)
    # Another connection from the same worktree is admitted beside it.
    await _register(hub, lambda call: _ok(call, _BASE), worktree=_WORKTREE_MAIN)
    with pytest.raises(ValueError, match="workspace_worktree_invalid"):
        await _register(hub, lambda call: _ok(call, _BASE), worktree="/srv/dev/repo")


async def test_a_live_call_prefers_its_own_connections_agent() -> None:
    hub = _hub()
    own: list[WorkspaceCall] = []
    newer: list[WorkspaceCall] = []
    channel = await _register(hub, lambda call: _ok(call, _BASE), sent=own)
    await _register(hub, lambda call: _ok(call, _BASE), sent=newer)
    with live_call_scope(channel):
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)

        def blocking() -> object:
            return hub.call_blocking(
                _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0
            )

        # A worker thread serving the same call keeps the preference.
        assert await asyncio.to_thread(blocking) == _BASE
    assert (len(own), len(newer)) == (2, 0)
    # Background work has no serving connection; every channel serves the one worktree.
    await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert (len(own), len(newer)) == (2, 1)
    # A preference for a channel that is gone, or for another handle, is ignored.
    other = workspace_handle_for_claim(_COMMITMENT, _WORKTREE_LINKED)
    elsewhere: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=elsewhere, handle=other)
    await hub.unregister(channel)
    with live_call_scope(channel):
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
        await hub.call(
            other,
            WorkspaceOperation.READ_TASK_BASE,
            WorkspaceOnlyArguments(other),
            timeout_seconds=1.0,
        )
    assert (len(own), len(newer), len(elsewhere)) == (2, 2, 1)


async def test_a_read_whose_connection_dropped_is_asked_once_of_another_live_one() -> None:
    """Two connections of one client serve the claim; the newest goes away mid-call."""

    hub = _hub()
    older: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=older)
    newest = await _register(hub, lambda _call: None)
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
    )
    await _until(lambda: newest.pending_count > 0)
    await hub.unregister(newest)
    assert await asyncio.wait_for(pending, 1.0) == _BASE
    assert [call.operation for call in older] == ["read_task_base"]


async def test_an_approved_check_whose_connection_dropped_is_never_run_twice() -> None:
    hub = _hub()
    older: list[WorkspaceCall] = []
    await _register(hub, lambda _call: None, sent=older)
    newest = await _register(hub, lambda _call: None)
    arguments = RunApprovedCheckArguments(
        "rws_" + "0" * 32,
        ApprovedCheckApproval(
            approval_id="unit",
            argv=("/usr/bin/true",),
            allow_network=False,
            timeout_seconds=10.0,
            approval_commitment=approval_commitment(
                "unit", ("/usr/bin/true",), allow_network=False
            ),
        ),
        "sha256:" + "4" * 64,
        None,
    )
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.RUN_APPROVED_CHECK, arguments, timeout_seconds=5.0)
    )
    await _until(lambda: newest.pending_count > 0)
    await hub.unregister(newest)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await asyncio.wait_for(pending, 1.0)
    assert caught.value.reason == "agent_disconnected"
    assert older == []


async def test_a_blocking_call_from_a_worker_thread_reaches_the_loop() -> None:
    hub = _hub()
    await _register(hub, lambda call: _ok(call, _BASE))

    def blocking() -> object:
        return hub.call_blocking(
            _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0
        )

    assert await asyncio.to_thread(blocking) == _BASE


async def test_a_blocking_call_on_the_loops_own_thread_is_refused_not_deadlocked() -> None:
    hub = _hub()
    await _register(hub, lambda call: _ok(call, _BASE))
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        hub.call_blocking(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "hub_unavailable"


def test_a_hub_no_loop_serves_is_unavailable() -> None:
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        _hub().call_blocking(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "hub_unavailable"


async def test_arguments_the_catalog_refuses_are_typed_and_never_sent() -> None:
    hub = _hub()
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=sent)
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, object(), timeout_seconds=1.0)
    assert caught.value.reason == "arguments_invalid"
    assert sent == []


def test_unavailability_reasons_are_closed_and_name_nothing() -> None:
    with pytest.raises(ValueError, match="workspace_agent_unavailable_reason_invalid"):
        WorkspaceAgentUnavailable("/srv/dev/repo")
    with pytest.raises(ValueError, match="workspace_agent_reason_invalid"):
        WorkspaceAgentUnavailable("agent_refused", "not a token")
    with pytest.raises(ValueError, match="workspace_agent_reason_invalid"):
        WorkspaceAgentUnavailable("no_agent", "not_git")
    assert str(WorkspaceAgentUnavailable("agent_refused", "root_not_admitted")) == "agent_refused"


def test_representations_name_no_handle() -> None:
    assert repr(_hub()) == "WorkspaceAgentHub(<redacted>)"


# --- the control call a workspace call serves bounds and cancels it (ADR-051) ---------------


async def test_a_cancelled_handler_cancels_its_blocking_workspace_call_at_once() -> None:
    hub = _hub(1.0)
    channel = await _register(hub, lambda _call: None)
    returned = threading.Event()
    reasons: list[str] = []

    def blocking() -> object:
        try:
            return hub.call_blocking(
                _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=60.0
            )
        except WorkspaceAgentUnavailable as exc:
            reasons.append(exc.reason)
            raise
        finally:
            returned.set()

    async def handler() -> object:
        with live_call_scope(), workspace_call_deadline():
            return await asyncio.to_thread(blocking)

    task = asyncio.create_task(handler())
    await _until(lambda: channel.pending_count > 0, interval=0.005)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The worker thread and the agent slot are free at once, not after the call's 60 s.
    assert await asyncio.to_thread(returned.wait, 2.0)
    assert reasons == ["call_cancelled"]
    await _until(lambda: channel.pending_count == 0, interval=0.005)


async def test_a_workspace_call_never_waits_past_its_handlers_deadline() -> None:
    hub = _hub(1.0)
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda _call: None, sent=sent)
    loop = asyncio.get_running_loop()

    def blocking() -> object:
        return hub.call_blocking(
            _HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=60.0
        )

    started = loop.time()
    with live_call_scope(), workspace_call_deadline(loop.time() + 0.3):
        with pytest.raises(WorkspaceAgentUnavailable) as caught:
            await asyncio.to_thread(blocking)
    assert caught.value.reason == "deadline_exceeded"
    # Told only the handler's remaining time, and waited about that long (plus the reply grace).
    (call,) = sent
    assert 1 <= call.deadline_ms <= 300
    assert loop.time() - started < 5.0
    # A handler with no time left sends nothing at all.
    with live_call_scope(), workspace_call_deadline(loop.time() - 1.0):
        with pytest.raises(WorkspaceAgentUnavailable) as caught:
            await asyncio.to_thread(blocking)
        with pytest.raises(WorkspaceAgentUnavailable):
            await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=1.0)
    assert caught.value.reason == "deadline_exceeded"
    assert len(sent) == 1


async def test_work_a_handler_started_is_not_bounded_by_it_once_it_returned() -> None:
    """A task the handler spawned copies its context; it is not the handler's call any more."""

    hub = _hub(1.0)
    sent: list[WorkspaceCall] = []
    await _register(hub, lambda call: _ok(call, _BASE), sent=sent)
    loop = asyncio.get_running_loop()
    release = asyncio.Event()

    async def later() -> object:
        await release.wait()
        return await asyncio.to_thread(
            hub.call_blocking,
            _HANDLE,
            WorkspaceOperation.READ_TASK_BASE,
            _ARGS,
            timeout_seconds=30.0,
        )

    handler_deadline = loop.time() + 0.05
    with workspace_call_deadline(handler_deadline):
        spawned = asyncio.create_task(later())
    # The handler's deadline has passed; its scope ended normally.
    await _until(lambda: loop.time() > handler_deadline, interval=0.01)
    release.set()
    assert await spawned == _BASE
    (call,) = sent
    assert call.deadline_ms > 1_000


async def test_a_queued_call_is_told_only_the_time_it_has_left() -> None:
    hub = _hub()
    held: list[WorkspaceCall] = []
    channel = await _register(hub, lambda _call: None, sent=held)
    blockers = [
        asyncio.create_task(
            hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
        )
        for _ in range(MAX_CALLS_PER_CHANNEL)
    ]
    await _until(lambda: len(held) == MAX_CALLS_PER_CHANNEL)
    loop = asyncio.get_running_loop()
    queued = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=2.0)
    )
    await asyncio.sleep(0)  # one step: the queued call fixed its 2 s budget and waits for a slot
    budget_fixed_by = loop.time()
    # Let the slot wait cost a measurable part of that budget before one slot frees.
    await _until(lambda: loop.time() >= budget_fixed_by + 0.5, interval=0.01)
    freed_at = loop.time()
    hub.deliver(channel, _ok(held[0], _BASE))
    await _until(lambda: len(held) == MAX_CALLS_PER_CHANNEL + 1)
    late = held[-1]
    # Not the full 2 s: told at most what was left once the slot freed.
    assert 1 <= late.deadline_ms <= int((budget_fixed_by + 2.0 - freed_at) * 1000) + 1
    # The agent answers as soon as it is asked, within the deadline it was told.
    hub.deliver(channel, _ok(late, _BASE))
    assert await queued == _BASE
    for blocker in blockers:
        blocker.cancel()
    await asyncio.gather(*blockers, return_exceptions=True)


async def test_a_frame_is_written_whole_when_its_caller_stops_waiting() -> None:
    hub = _hub()
    release = asyncio.Event()
    finished: list[str] = []

    entered: list[str] = []

    async def slow_writer(_call: WorkspaceCall) -> None:
        entered.append("writing")
        try:
            await release.wait()  # a peer that drains slowly, or a long result ahead on the line
            finished.append("written")
        except asyncio.CancelledError:
            finished.append("cut off")
            raise

    channel = await hub.register(
        handle=_HANDLE,
        declaration=_declaration(),
        service_instance_id=_INSTANCE,
        service_generation="7",
        writer=slow_writer,
    )
    with pytest.raises(WorkspaceAgentUnavailable) as caught:
        await hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=0.1)
    assert caught.value.reason == "deadline_exceeded"
    assert channel.pending_count == 0
    # Cancelling the waiting caller does not cut the write either.
    pending = asyncio.create_task(
        hub.call(_HANDLE, WorkspaceOperation.READ_TASK_BASE, _ARGS, timeout_seconds=5.0)
    )
    await _until(lambda: len(entered) == 2)  # its frame is being written
    pending.cancel()
    await asyncio.gather(pending, return_exceptions=True)
    assert finished == []
    release.set()
    await _until(lambda: len(finished) == 2)
    assert finished == ["written", "written"]
