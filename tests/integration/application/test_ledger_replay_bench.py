"""Opt-in latency benchmark for issue #886: late-session respond/receipt/status at large ledgers.

Skipped by default. Run with ``FINISHUP_BENCH_886=1`` (optionally ``FINISHUP_BENCH_886_SIZES=1500,3000``)
and ``-s`` to see the ``BENCH`` lines. Each call is timed alongside a 5 ms asyncio ticker whose
largest gap is the worst event-loop stall the call caused. The assertions are generous ceilings
that catch a regression back to per-call genesis replay, not a precise performance contract.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable
from typing import Literal

import pytest

from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.domain.values import Frontier, event_id, evidence_id, timestamp_from_datetime
from finishup.protocol.canonical import canonical_encode
from integration.application import test_respond_status_receipt as h

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(
        os.environ.get("FINISHUP_BENCH_886") != "1",
        reason="opt-in latency benchmark; set FINISHUP_BENCH_886=1",
    ),
]

_SIZES = tuple(
    int(value) for value in os.environ.get("FINISHUP_BENCH_886_SIZES", "1500,3000").split(",")
)
_BATCH = 100
_CALL_CEILING_SECONDS = 30.0
_STALL_CEILING_SECONDS = 5.0


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _drain_many(
    app: Application,
    runtime: h._WorkflowRuntime,  # pyright: ignore[reportPrivateUsage]
    started: StartInternalResult,
    *,
    seed: int,
    expected: int,
    count: int,
) -> Frontier:
    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    channel = h.PublicationChannel.HOOK_OBSERVED
    entries: list[h.AppendEntry] = []
    for offset in range(count):
        payload = h.EvidenceRecordedPayload(
            evidence_id(h.protocol_id("evd_", seed + offset)),
            h.EvidenceKind.ARTIFACT,
            h.EvidenceImmutability.MUTABLE_REFERENCE,
            timestamp_from_datetime(now),
            reference=f"hook-observation-note-{seed + offset}",
        )
        encoded = canonical_encode(h.encode_payload(payload))
        metadata = h.ObjectMetadata(
            h.ObjectKind.EVENT_PAYLOAD, h.media_type_for("evidence_recorded"), started.task_id, now
        )
        staged = await objects.stage(
            h.ObjectSource(data=encoded, declared_size=len(encoded)), metadata
        )
        ref = await objects.finalize(staged)
        entries.append(
            h.AppendEntry(
                h.EventDraft(
                    event_id(h.protocol_id("evt_", seed + offset)),
                    h.EventSchema("evidence_recorded", h.EVIDENCE_SCHEMA_VERSION),
                    timestamp_from_datetime(now),
                    (),
                    payload,
                    (),
                    (),
                ),
                h.observation_author(),
                ref,
                ref.commitment,
                metadata.media_type,
                ref.plaintext_size,
                channel,
                h.coverage_for_channel(channel),
                "projected",
            )
        )
    result = await ledger.append_batch(
        h.AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            h.protocol_id("req_", seed + 900_000),
            h.OperationKind.PUBLISH_WORK,
            h._DIGEST,  # pyright: ignore[reportPrivateUsage]
            expected,
            tuple(entries),
            None,
        )
    )
    return result.result_frontier


async def _timed[T](label: str, call: Awaitable[T], timings: dict[str, tuple[float, float]]) -> T:
    worst = 0.0
    stop = False

    async def ticker() -> None:
        nonlocal worst
        last = time.perf_counter()
        while not stop:
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            worst = max(worst, now - last)
            last = now

    probe = asyncio.create_task(ticker())
    started = time.perf_counter()
    result = await call
    elapsed = time.perf_counter() - started
    stop = True
    await probe
    timings[label] = (elapsed, worst)
    print(f"BENCH {label}: {elapsed:.3f}s (max loop stall {worst:.3f}s)")
    return result


@pytest.mark.timeout(1200)
@pytest.mark.parametrize("observations", _SIZES)
@pytest.mark.parametrize("backend", ["sqlite"])
async def test_late_session_calls_stay_fast_at_large_ledgers(
    backend: Literal["memory", "sqlite"], observations: int
) -> None:
    app, runtime, _ = h._build_app(  # pyright: ignore[reportPrivateUsage]
        seed_offset=77, ledger_backend=backend
    )
    started, checked, _ = await h._bootstrap_finding(  # pyright: ignore[reportPrivateUsage]
        app, seed=7700
    )
    finding = checked.findings[0]
    head = checked.result_frontier
    build_started = time.perf_counter()
    for offset in range(0, observations, _BATCH):
        head = await _drain_many(
            app,
            runtime,
            started,
            seed=100_000 + offset,
            expected=head.sequence,
            count=min(_BATCH, observations - offset),
        )
    print(
        f"BENCH build {observations} observations to seq {head.sequence}: "
        f"{time.perf_counter() - build_started:.1f}s"
    )
    timings: dict[str, tuple[float, float]] = {}
    frontier = h._frontier  # pyright: ignore[reportPrivateUsage]
    base = h._request_base  # pyright: ignore[reportPrivateUsage]

    responded = await _timed(
        "respond stale finding frontier",
        app.respond(
            h.RespondRequest.model_validate(
                {
                    **base(h.protocol_id("req_", 7710)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": frontier(head),
                    "finding_id": finding.finding_id,
                    "finding_frontier": frontier(checked.result_frontier),
                    "disposition": "acknowledged",
                }
            )
        ),
        timings,
    )
    status_wire = {
        **base(h.protocol_id("req_", 7711)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "view": "candidate_findings",
        "limit": "10",
    }
    await _timed(
        "status candidate_findings",
        app.status(h.StatusRequest.model_validate(status_wire)),
        timings,
    )
    await _timed(
        "status evidence",
        app.status(
            h.StatusRequest.model_validate(
                {**status_wire, "request_id": h.protocol_id("req_", 7712), "view": "evidence"}
            )
        ),
        timings,
    )
    decision_wire = {
        **base(h.protocol_id("req_", 7713)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier(responded.result_frontier),
        "event_drafts": (
            {
                "event_id": h.protocol_id("evt_", 7714),
                "schema": {"name": "decision_recorded", "version": "1.0.0"},
                "occurred_at": "2026-07-19T12:00:02.000Z",
                "causal_parents": (),
                "payload": {
                    "statement": "Keep the benchmark scenario unchanged.",
                    "rationale": "It measures late-session latency only.",
                    "authority": "harness:bench",
                },
                "artifact_refs": (),
                "evidence_refs": (),
            },
        ),
    }
    await _timed(
        "publish_work dry_run",
        app.publish_work(h.PublishWorkRequest.model_validate({**decision_wire, "dry_run": True})),
        timings,
    )
    published = await _timed(
        "publish_work",
        app.publish_work(h.PublishWorkRequest.model_validate(decision_wire)),
        timings,
    )
    checked_again = await _timed(
        "check deterministic_only",
        app.check(
            h.CheckRequest.model_validate(
                {
                    **base(h.protocol_id("req_", 7715)),
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": frontier(published.result_frontier),
                    "mode": "deterministic_only",
                    "max_findings": "3",
                }
            )
        ),
        timings,
    )
    assert type(checked_again) is h.CheckCommitResult
    pinned = checked_again.result_frontier
    live = await _drain_many(app, runtime, started, seed=500_000, expected=pinned.sequence, count=1)
    receipt_wire = {
        **base(h.protocol_id("req_", 7720)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier(pinned),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    receipt = await _timed(
        "receipt one drain behind head",
        app.receipt(h.ReceiptRequest.model_validate(receipt_wire)),
        timings,
    )
    assert receipt.subject_frontier == pinned
    assert receipt.result_frontier.sequence == live.sequence + 1
    await _timed(
        "receipt at exact head",
        app.receipt(
            h.ReceiptRequest.model_validate(
                {
                    **receipt_wire,
                    "request_id": h.protocol_id("req_", 7730),
                    "expected_frontier": frontier(receipt.result_frontier),
                }
            )
        ),
        timings,
    )
    for label, (elapsed, stall) in timings.items():
        assert elapsed < _CALL_CEILING_SECONDS, label
        assert stall < _STALL_CEILING_SECONDS, label
