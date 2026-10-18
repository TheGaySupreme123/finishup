"""#1118 unit 1 review R1/R4: snapshot boundaries live inside the admitting operation.

A start or publication reserves its boundary in the task ledger before reading, keyed by its
operation, so a replay, a recovered attempt or a crash retry never rereads a later file as the
original; and a statement first supplied on attach is admitted like a declaration.
"""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal, cast

import pytest

import finishup.application.publish_work as publish_module
import finishup.application.start as start_module
from builders.start_application import protocol_id, start_request
from finishup.adapters.task_input_read import snapshot_outside_inputs
from finishup.application.input_snapshot import InputSnapshotScope, load_input_snapshots
from finishup.application.service import Application
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.runtime import RouteAccess, RouteCommand
from finishup.protocol.models import PublishWorkRequest
from integration.application.test_respond_status_receipt import (
    _build_app,  # pyright: ignore[reportPrivateUsage]
    _frontier,  # pyright: ignore[reportPrivateUsage]
    _request_base,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_ORIGINAL = b"OWNER_SPEC_THRESHOLD_GT_ZERO\n"
_LATER = b"AGENT_REPLACED_SPEC_THRESHOLD_GE_ZERO\n"
_CONTEXT = RepositoryPrivacyContext("hmac-sha256:" + "a" * 64, "directory")
type Backend = Literal["memory", "sqlite"]


@pytest.fixture
def spec(tmp_path: Path) -> Path:
    root = (tmp_path / "shared").resolve()
    root.mkdir()
    path = root / "spec.md"
    path.write_bytes(_ORIGINAL)
    return path


class _Reader:
    """The trusted reader, counting calls; ``empty_first`` makes the first call reach nothing."""

    def __init__(self, *, empty_first: bool = False) -> None:
        self.calls = 0
        self.empty_first = empty_first

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        if self.empty_first and self.calls == 1:
            return ()
        return snapshot_outside_inputs(*args, **kwargs)


def _app(backend: Backend, spec: Path, reader: _Reader) -> tuple[Application, Any]:
    app, routed, _ = _build_app(ledger_backend=backend)

    async def scope(_context: RepositoryPrivacyContext, _task_id: str) -> InputSnapshotScope:
        return InputSnapshotScope((os.fspath(spec.parent),), (), reader)

    return replace(app, input_snapshot_scope=scope), routed


async def _kept(routed: Any, session_id: str, writer_id: str) -> list[tuple[str, list[bytes]]]:
    runtime = await routed.route(
        RouteCommand(session_id, writer_id, RouteAccess.WRITE, frozenset({RuntimeCapability.WRITE}))
    )
    try:
        return [
            (kept.boundary, [item.text for item in kept.files])
            for kept in await load_input_snapshots(runtime, None)
        ]
    finally:
        await routed.release(runtime)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_replayed_start_never_backdates_a_later_file(spec: Path, backend: Backend) -> None:
    """R1: the first start reached nothing; its replay keeps that gap, never the later bytes."""

    reader = _Reader(empty_first=True)
    app, routed = _app(backend, spec, reader)
    request = start_request(9701).model_copy(update={"task_statement": f"Use {spec}"})
    first = await app.start(request, repository_privacy_context=_CONTEXT)
    spec.write_bytes(_LATER)
    replay = await app.start(request, repository_privacy_context=_CONTEXT)

    assert replay == first and reader.calls == 1
    assert await _kept(routed, first.session_id, first.writer_id) == []


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("crash", ["_lifecycle_append", "_publish_result"])
async def test_a_start_recovered_after_a_crash_rereads_nothing(
    spec: Path, backend: Backend, crash: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R1: a crash before or after the lifecycle event; the retry keeps the first copy."""

    reader = _Reader()
    app, routed = _app(backend, spec, reader)
    original = getattr(start_module, crash)
    crashed = False

    async def crash_once(*args: Any, **kwargs: Any) -> Any:
        nonlocal crashed
        if not crashed:
            crashed = True
            if crash == "_publish_result":
                await original(*args, **kwargs)
            raise RuntimeError("simulated_crash")
        return await original(*args, **kwargs)

    monkeypatch.setattr(start_module, crash, crash_once)
    request = start_request(9711).model_copy(update={"task_statement": f"Use {spec}"})
    with pytest.raises(RuntimeError, match="simulated_crash"):
        await app.start(request, repository_privacy_context=_CONTEXT)
    spec.write_bytes(_LATER)
    cast(Any, app.clock).advance(61)  # The crashed attempt's lease lapses.
    started = await app.start(request, repository_privacy_context=_CONTEXT)

    assert reader.calls == 1
    assert await _kept(routed, started.session_id, started.writer_id) == [
        ("task_start", [_ORIGINAL])
    ]


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_statement_first_supplied_on_attach_is_admitted(
    spec: Path, backend: Backend
) -> None:
    """R4: the attach that first supplies the statement keeps an admission-time copy."""

    reader = _Reader()
    app, routed = _app(backend, spec, reader)
    started = await app.start(start_request(9750), repository_privacy_context=_CONTEXT)
    attach = start_request(9751, mode="attach", session_id=started.session_id)
    attached = await app.start(
        attach.model_copy(update={"task_statement": f"Use {spec}"}),
        repository_privacy_context=_CONTEXT,
    )

    assert attached.outcome == "attached"
    assert await _kept(routed, attached.session_id, attached.writer_id) == [
        ("admission_time", [_ORIGINAL])
    ]


def _declaration(started: Any, spec: Path, seed: int) -> PublishWorkRequest:
    return PublishWorkRequest.model_validate(
        {
            **_request_base(protocol_id("req_", seed)),
            "session_id": started.session_id,
            "writer_id": started.writer_id,
            "expected_frontier": _frontier(started.frontier),
            "event_drafts": (
                {
                    "event_id": protocol_id("evt_", seed),
                    "schema": {"name": "obligation_published", "version": "1.1.0"},
                    "occurred_at": "2026-10-19T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {
                        "obligation_id": protocol_id("obl_", seed),
                        "description": "Follow the specification.",
                        "evidence_expectation": "A test run.",
                        "requested_items": (
                            {"item_kind": "file", "value": os.fspath(spec), "role": "input"},
                        ),
                        "status": "open",
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
        }
    )


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_declaration_retried_after_a_crash_or_replayed_rereads_nothing(
    spec: Path, backend: Backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R1: the declaration's boundary is its request; a retry and a replay keep the first copy."""

    reader = _Reader()
    app, routed = _app(backend, spec, reader)
    started = await app.start(start_request(9760), repository_privacy_context=_CONTEXT)
    original = publish_module.run_prepared_append
    crashed = False

    async def crash_once(*args: Any, **kwargs: Any) -> Any:
        nonlocal crashed
        if not crashed:
            crashed = True
            raise RuntimeError("simulated_crash")
        return await original(*args, **kwargs)

    monkeypatch.setattr(publish_module, "run_prepared_append", crash_once)
    request = _declaration(started, spec, 9761)
    with pytest.raises(RuntimeError, match="simulated_crash"):
        await app.publish_work(request, repository_privacy_context=_CONTEXT)
    spec.write_bytes(_LATER)
    await app.publish_work(request, repository_privacy_context=_CONTEXT)
    await app.publish_work(request, repository_privacy_context=_CONTEXT)

    assert reader.calls == 1
    assert await _kept(routed, started.session_id, started.writer_id) == [
        ("admission_time", [_ORIGINAL])
    ]
