"""A terminal availability result is inherited by later request identities, not re-probed.

Issue #469: in the 2026-08-29 Cursor Multitask dogfood the parent's `start` failed before any
session existed, and each delegated worker then called `start` again under a fresh request id,
minting more diagnostics and spending more startup budgets against the same dead binding. The
bridge now latches the first availability result for its host binding: one parent plus three
delegates produce exactly one connection attempt and one diagnostic, the delegates receive the
parent's correlation with ``availability_inherited: true``, and only the sanctioned continuations
(the original request id, a changed service holder, or a quiet successful handshake) clear it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import BaseModel

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    PublicRequestModel,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
)
from finishup.service.lifecycle import SingletonHolder

_PARENT = "req_00000000-0000-4000-8000-000000000001"
_DELEGATES = (
    "req_00000000-0000-4000-8000-000000000002",
    "req_00000000-0000-4000-8000-000000000003",
    "req_00000000-0000-4000-8000-000000000004",
)


def _start(request_id: str) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create",
        "task_title": "Delegated work",
        "requested_view": "compact",
    }


def _status(request_id: str) -> dict[str, JsonValue]:
    body = _start(request_id)
    for key in ("mode", "task_title", "requested_view"):
        body.pop(key)
    body.update(
        {
            "session_id": "ses_00000000-0000-4000-8000-000000000001",
            "writer_id": "wri_00000000-0000-4000-8000-000000000001",
            "view": "compact",
            "limit": "10",
        }
    )
    return body


def _failure[ResultT: BaseModel](result_type: type[ResultT], request_id: str) -> ResultT:
    return result_type.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": request_id,
            "ok": False,
            "error": {
                "code": "SESSION_CONFLICT",
                "message": "The session conflicts with the request.",
                "retryable": False,
                "correlation_id": "err_00000000-0000-4000-8000-000000000099",
            },
        }
    )


class _FakeClient:
    def __init__(
        self,
        *,
        connect_error: BaseException | None = None,
        call_error: BaseException | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.closed = False
        self.connect_error = connect_error
        self.call_error = call_error

    async def connect(self) -> None:
        if self.connect_error is not None:
            raise self.connect_error
        return None

    async def _call[ResultT: BaseModel](
        self, name: str, request: PublicRequestModel, result_type: type[ResultT]
    ) -> ResultT:
        if self.call_error is not None:
            raise self.call_error
        self.calls.append(name)
        return _failure(result_type, request.request_id)

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> StartResult:
        return await self._call("start", request, StartResult)

    async def status(
        self,
        request: StatusRequest,
        *,
        deadline_ms: int | None = None,
        route_profile: str | None = None,
    ) -> StatusResult:
        return await self._call("status", request, StatusResult)

    async def close(self) -> None:
        self.closed = True


class _Harness:
    """Counts every way the bridge could reach the service and every diagnostic it mints."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        import finishup.observability.diagnostics as diagnostics

        monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
        self.on_demand: list[str] = []
        self.quiet: int = 0
        self.recorded: list[str] = []
        self.holder: SingletonHolder | None = None
        self.on_demand_failure: BaseException | None = None
        self.on_demand_client: _FakeClient | None = None
        self.quiet_client: _FakeClient | None = None
        self.entered_on_demand = asyncio.Event()
        self.release_on_demand = asyncio.Event()
        self.stall_on_demand = False
        original = bridge.record_public_error_without_raising

        async def on_demand(
            _kind: object, *, workspace_locator: object = None, timeout_seconds: float = 30.0
        ) -> object:
            del workspace_locator, timeout_seconds
            self.on_demand.append("connect")
            self.entered_on_demand.set()
            if self.stall_on_demand:
                await self.release_on_demand.wait()
            if self.on_demand_failure is not None:
                raise self.on_demand_failure
            assert self.on_demand_client is not None
            return self.on_demand_client

        async def quiet(_kind: object, *, workspace_locator: object = None) -> object:
            del workspace_locator
            self.quiet += 1
            if self.quiet_client is None:
                raise ControlError("service_unavailable", retryable=True)
            return self.quiet_client

        def record(**kwargs: object) -> str:
            self.recorded.append(str(kwargs.get("reason")))
            return original(**cast(dict[str, object], kwargs))  # type: ignore[arg-type]

        monkeypatch.setattr(
            bridge,
            "connect_service_on_demand",
            cast(Callable[[object], Awaitable[object]], on_demand),
        )
        monkeypatch.setattr(
            bridge, "connect_service", cast(Callable[[object], Awaitable[object]], quiet)
        )
        monkeypatch.setattr(bridge, "service_holder_identity", lambda: self.holder)
        monkeypatch.setattr(bridge, "record_public_error_without_raising", record)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert getattr(result, "isError") is True
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
async def test_parent_terminal_start_is_inherited_by_three_delegates_without_any_service_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_incompatible", retryable=True)
    runtime = bridge.build_bridge_runtime(
        host_profile="cursor", workspace_locator=WorkspaceLocator(str(tmp_path))
    )

    parent = _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert parent["code"] == "SERVICE_UNAVAILABLE"
    assert parent["retryable"] is True
    details = cast(dict[str, object], parent["safe_details"])
    assert details["reason_code"] == "service_incompatible"
    assert details["availability"] == "terminal_unavailable"
    assert details["host_profile"] == "cursor"
    assert details["route_profile"] == "policy"
    assert "availability_inherited" not in details
    correlation = parent["correlation_id"]
    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["service_incompatible"]

    # Three delegated workers, each with a fresh request identity, each a different tool.
    for index, request_id in enumerate(_DELEGATES):
        arguments = _status(request_id) if index == 1 else _start(request_id)
        dispatch = bridge.dispatch_status if index == 1 else bridge.dispatch_start
        inherited = _error(await dispatch(arguments, runtime))
        assert inherited["code"] == "SERVICE_UNAVAILABLE"
        assert inherited["correlation_id"] == correlation
        assert inherited["retryable"] is True
        inherited_details = cast(dict[str, object], inherited["safe_details"])
        assert inherited_details["availability"] == "terminal_unavailable"
        assert inherited_details["availability_inherited"] is True
        assert inherited_details["availability_request_id"] == _PARENT
        assert inherited_details["reason_code"] == "service_incompatible"
        message = cast(str, inherited["message"])
        assert "finishup service restart" in message
        assert "no new diagnostic was recorded" in message
        assert len(message) <= 4096

    # Zero further connection attempts, spawns, or supersedes; zero new diagnostics. The only
    # service contact for a retryable class is one quiet handshake per inherited call, which
    # here fails against the same incompatible holder.
    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["service_incompatible"]
    assert harness.quiet == len(_DELEGATES)


@pytest.mark.anyio
async def test_concurrent_first_arrivals_share_one_on_demand_attempt_and_one_diagnostic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #476: N parallel first calls share one probe, one diagnostic, and N−1 inheritances."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_unavailable", retryable=True)
    harness.stall_on_demand = True
    runtime = bridge.build_bridge_runtime()
    request_ids = (_PARENT, *_DELEGATES)

    tasks = [
        asyncio.create_task(bridge.dispatch_start(_start(request_id), runtime))
        for request_id in request_ids
    ]
    await harness.entered_on_demand.wait()
    assert harness.on_demand == ["connect"]
    harness.release_on_demand.set()
    results = [_error(result) for result in await asyncio.gather(*tasks)]

    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["service_unavailable"]
    assert harness.quiet == 0
    correlations = {result["correlation_id"] for result in results}
    assert len(correlations) == 1
    first = [
        result
        for result in results
        if "availability_inherited" not in cast(dict[str, object], result["safe_details"])
    ]
    inherited = [
        result
        for result in results
        if cast(dict[str, object], result["safe_details"]).get("availability_inherited") is True
    ]
    assert len(first) == 1
    assert len(inherited) == len(request_ids) - 1
    winner_details = cast(dict[str, object], inherited[0]["safe_details"])
    winner_request_id = winner_details["availability_request_id"]
    assert winner_request_id in request_ids
    for result in inherited:
        details = cast(dict[str, object], result["safe_details"])
        assert result["correlation_id"] == first[0]["correlation_id"]
        assert result["retryable"] is True
        assert details["availability"] == "terminal_unavailable"
        assert details["availability_inherited"] is True
        assert details["availability_request_id"] == winner_request_id
        assert "no new diagnostic was recorded" in cast(str, result["message"])

    harness.stall_on_demand = False
    harness.on_demand_failure = None
    harness.on_demand_client = _FakeClient()
    assert type(winner_request_id) is str
    replay = _error(await bridge.dispatch_start(_start(winner_request_id), runtime))
    assert replay["code"] == "SESSION_CONFLICT"
    assert harness.on_demand == ["connect", "connect"]


@pytest.mark.anyio
async def test_concurrent_same_request_id_inherits_before_later_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Concurrent duplicates share the first result; only a later replay probes again."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_unavailable", retryable=True)
    harness.stall_on_demand = True
    runtime = bridge.build_bridge_runtime()

    tasks = [asyncio.create_task(bridge.dispatch_start(_start(_PARENT), runtime)) for _ in range(4)]
    await harness.entered_on_demand.wait()
    assert harness.on_demand == ["connect"]
    harness.release_on_demand.set()
    results = [_error(result) for result in await asyncio.gather(*tasks)]

    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["service_unavailable"]
    assert harness.quiet == 0
    assert len({result["correlation_id"] for result in results}) == 1
    inherited = [
        result
        for result in results
        if cast(dict[str, object], result["safe_details"]).get("availability_inherited") is True
    ]
    assert len(inherited) == len(tasks) - 1

    harness.stall_on_demand = False
    harness.on_demand_failure = None
    harness.on_demand_client = _FakeClient()
    replay = _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert replay["code"] == "SESSION_CONFLICT"
    assert harness.on_demand == ["connect", "connect"]


@pytest.mark.anyio
async def test_cancelled_first_attempt_releases_waiters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cancelling the probe owner must not strand the process-local availability gate."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.stall_on_demand = True
    runtime = bridge.build_bridge_runtime()

    owner = asyncio.create_task(bridge.dispatch_start(_start(_PARENT), runtime))
    await harness.entered_on_demand.wait()
    owner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await owner

    assert runtime._slot.attempting is False  # pyright: ignore[reportPrivateUsage]
    assert runtime._slot.attempt_finished is None  # pyright: ignore[reportPrivateUsage]
    harness.stall_on_demand = False
    harness.on_demand_client = _FakeClient()
    fresh = _error(await bridge.dispatch_start(_start(_DELEGATES[0]), runtime))
    assert fresh["code"] == "SESSION_CONFLICT"
    assert harness.on_demand == ["connect", "connect"]


@pytest.mark.anyio
async def test_live_client_handshake_failure_shares_one_on_demand_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A live slot client that then fails handshake must not bypass the probe gate."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_unavailable", retryable=True)
    harness.stall_on_demand = True
    runtime = bridge.build_bridge_runtime()
    runtime._slot.client = cast(  # pyright: ignore[reportPrivateUsage]
        Any, _FakeClient(connect_error=ControlError("service_unavailable", retryable=True))
    )
    request_ids = (_PARENT, *_DELEGATES)

    tasks = [
        asyncio.create_task(bridge.dispatch_start(_start(request_id), runtime))
        for request_id in request_ids
    ]
    await harness.entered_on_demand.wait()
    assert harness.on_demand == ["connect"]
    harness.release_on_demand.set()
    results = [_error(result) for result in await asyncio.gather(*tasks)]

    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["service_unavailable"]
    inherited = [
        result
        for result in results
        if cast(dict[str, object], result["safe_details"]).get("availability_inherited") is True
    ]
    assert len(inherited) == len(request_ids) - 1


@pytest.mark.anyio
async def test_live_client_invoke_failure_reconnect_shares_one_on_demand_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Reconnect after a live-client RPC availability error is one probe, not N."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_unavailable", retryable=True)
    harness.stall_on_demand = True
    runtime = bridge.build_bridge_runtime()
    runtime._slot.client = cast(  # pyright: ignore[reportPrivateUsage]
        Any, _FakeClient(call_error=ControlError("service_unavailable", retryable=True))
    )
    request_ids = (_PARENT, *_DELEGATES)

    tasks = [
        asyncio.create_task(bridge.dispatch_start(_start(request_id), runtime))
        for request_id in request_ids
    ]
    await harness.entered_on_demand.wait()
    assert harness.on_demand == ["connect"]
    harness.release_on_demand.set()
    results = [_error(result) for result in await asyncio.gather(*tasks)]

    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["service_unavailable"]
    inherited = [
        result
        for result in results
        if cast(dict[str, object], result["safe_details"]).get("availability_inherited") is True
    ]
    assert len(inherited) == len(request_ids) - 1


@pytest.mark.anyio
async def test_invalid_publish_waits_for_in_flight_first_attempt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Envelope-first recovery must not start a second on-demand probe during the first attempt."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_incompatible", retryable=True)
    harness.stall_on_demand = True
    runtime = bridge.build_bridge_runtime()

    start_task = asyncio.create_task(bridge.dispatch_start(_start(_PARENT), runtime))
    await harness.entered_on_demand.wait()
    invalid = _status(_DELEGATES[0])
    invalid.pop("view")
    invalid.pop("limit")
    invalid["expected_frontier"] = {"sequence": "0", "head_digest": "genesis"}
    invalid["event_drafts"] = "not-a-list"
    publish_task = asyncio.create_task(bridge.dispatch_publish_work(invalid, runtime))
    harness.release_on_demand.set()

    parent = _error(await start_task)
    result = _error(await publish_task)
    assert parent["code"] == "SERVICE_UNAVAILABLE"
    assert result["code"] == "INVALID_REQUEST"
    details = cast(dict[str, object], result["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert harness.on_demand == ["connect"]
    assert harness.recorded.count("service_incompatible") == 1


@pytest.mark.anyio
@pytest.mark.parametrize("live_client_fails_during_call", [False, True])
async def test_invalid_publish_recovery_releases_its_failed_attempt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    live_client_fails_during_call: bool,
) -> None:
    """A non-latching recovery oracle must release both initial and reconnect failures."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_incompatible", retryable=True)
    runtime = bridge.build_bridge_runtime()
    if live_client_fails_during_call:
        runtime._slot.client = cast(  # pyright: ignore[reportPrivateUsage]
            Any, _FakeClient(call_error=ControlError("service_unavailable", retryable=True))
        )

    invalid = _status(_DELEGATES[0])
    invalid.pop("view")
    invalid.pop("limit")
    invalid["expected_frontier"] = {"sequence": "0", "head_digest": "genesis"}
    invalid["event_drafts"] = "not-a-list"
    result = _error(await bridge.dispatch_publish_work(invalid, runtime))

    assert result["code"] == "INVALID_REQUEST"
    details = cast(dict[str, object], result["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert runtime._slot.attempting is False  # pyright: ignore[reportPrivateUsage]
    assert runtime._slot.attempt_finished is None  # pyright: ignore[reportPrivateUsage]
    assert harness.on_demand == ["connect"]
    assert harness.recorded == ["invalid_request"]

    harness.on_demand_failure = None
    harness.on_demand_client = _FakeClient()
    fresh = _error(await bridge.dispatch_start(_start(_DELEGATES[1]), runtime))
    assert fresh["code"] == "SESSION_CONFLICT"
    assert harness.on_demand == ["connect", "connect"]


@pytest.mark.anyio
async def test_non_retryable_availability_is_inherited_without_even_a_quiet_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("endpoint_unsafe", retryable=False)
    runtime = bridge.build_bridge_runtime()

    parent = _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert parent["retryable"] is False
    for request_id in _DELEGATES:
        inherited = _error(await bridge.dispatch_start(_start(request_id), runtime))
        assert inherited["correlation_id"] == parent["correlation_id"]
        assert inherited["retryable"] is False
        assert cast(dict[str, object], inherited["safe_details"])["availability_inherited"] is True
    assert harness.on_demand == ["connect"]
    assert harness.quiet == 0
    assert len(harness.recorded) == 1


@pytest.mark.anyio
async def test_original_request_id_replays_through_and_success_clears_the_latch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_unavailable", retryable=True)
    runtime = bridge.build_bridge_runtime()

    parent = _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert parent["code"] == "SERVICE_UNAVAILABLE"
    blocked = _error(await bridge.dispatch_start(_start(_DELEGATES[0]), runtime))
    assert cast(dict[str, object], blocked["safe_details"])["availability_inherited"] is True
    assert harness.on_demand == ["connect"]

    # The operator ran the named repair; the coordinator replays the original request id.
    harness.on_demand_failure = None
    harness.on_demand_client = _FakeClient()
    replay = _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert replay["code"] == "SESSION_CONFLICT"
    assert harness.on_demand == ["connect", "connect"]
    assert harness.on_demand_client.calls == ["start"]

    # The latch is gone: a new delegate identity reaches the service normally.
    fresh = _error(await bridge.dispatch_start(_start(_DELEGATES[1]), runtime))
    assert fresh["code"] == "SESSION_CONFLICT"
    assert harness.on_demand_client.calls == ["start", "start"]


@pytest.mark.anyio
async def test_a_changed_service_holder_clears_the_latch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = _Harness(monkeypatch, tmp_path)
    harness.holder = SingletonHolder(4242, "old", "sha256:" + "a" * 64, "0.0.9")
    harness.on_demand_failure = ControlError("service_incompatible", retryable=True)
    runtime = bridge.build_bridge_runtime()

    _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    inherited = _error(await bridge.dispatch_start(_start(_DELEGATES[0]), runtime))
    assert cast(dict[str, object], inherited["safe_details"])["availability_inherited"] is True

    # `finishup service restart` replaced the holder: the next new identity probes afresh.
    harness.holder = SingletonHolder(4343, "new", "sha256:" + "b" * 64, "0.1.0")
    harness.on_demand_failure = None
    harness.on_demand_client = _FakeClient()
    fresh = _error(await bridge.dispatch_start(_start(_DELEGATES[1]), runtime))
    assert fresh["code"] == "SESSION_CONFLICT"
    assert harness.on_demand == ["connect", "connect"]


@pytest.mark.anyio
async def test_a_quiet_successful_handshake_clears_a_retryable_latch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_unavailable", retryable=True)
    runtime = bridge.build_bridge_runtime()

    _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    # The service came back by itself (the operator started it); a delegate must not be told
    # the binding is dead. The quiet handshake never spawns or supersedes anything.
    harness.quiet_client = _FakeClient()
    fresh = _error(await bridge.dispatch_start(_start(_DELEGATES[0]), runtime))
    assert fresh["code"] == "SESSION_CONFLICT"
    assert harness.quiet == 1
    assert harness.on_demand == ["connect"]
    assert harness.quiet_client.calls == ["start"]
    assert len(harness.recorded) == 1


@pytest.mark.anyio
async def test_per_request_failures_never_latch_the_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("vault_locked", retryable=False)
    runtime = bridge.build_bridge_runtime()

    locked = _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert locked["code"] == "VAULT_LOCKED"
    assert "availability" not in cast(dict[str, object], locked.get("safe_details") or {})
    again = _error(await bridge.dispatch_start(_start(_DELEGATES[0]), runtime))
    assert again["code"] == "VAULT_LOCKED"
    assert again["correlation_id"] != locked["correlation_id"]
    # Each locked dispatch performs its on-demand connect plus one bounded initialization-probe
    # reconnect (issue #512); neither attempt latches the binding.
    assert harness.on_demand == ["connect", "connect", "connect", "connect"]


@pytest.mark.anyio
async def test_publish_recovery_never_reaches_the_service_under_a_latched_outage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Envelope-first publish recovery is an oracle read against the service; it must inherit."""

    harness = _Harness(monkeypatch, tmp_path)
    harness.on_demand_failure = ControlError("service_incompatible", retryable=True)
    runtime = bridge.build_bridge_runtime()
    _error(await bridge.dispatch_start(_start(_PARENT), runtime))
    assert harness.on_demand == ["connect"]

    # A delegate publishes an invalid body under a fresh request id with a complete envelope, so
    # recovery would normally query the service for that request id.
    invalid = _status(_DELEGATES[0])
    invalid.pop("view")
    invalid.pop("limit")
    invalid["expected_frontier"] = {"sequence": "0", "head_digest": "genesis"}
    invalid["event_drafts"] = "not-a-list"
    result = _error(await bridge.dispatch_publish_work(invalid, runtime))

    assert result["code"] == "INVALID_REQUEST"
    details = cast(dict[str, object], result["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert "could not be checked" in cast(str, result["message"])
    assert harness.on_demand == ["connect"]
    assert harness.quiet == 1
    assert (
        "service_incompatible" in harness.recorded
        and harness.recorded.count("service_incompatible") == 1
    )
