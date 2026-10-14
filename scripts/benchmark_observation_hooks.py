"""Concurrent public-safe native-adapter probe; no service, vault or host login.

This measures adapter execution, not a vendor-host deadline or RPC acceptance.
All children use an explicit fresh local store. Never pass a live state root.
``--drain`` also runs the real service sweeper in this process against the same
store, delivering to an acknowledging stub instead of a service.
"""

from __future__ import annotations

import argparse
import io
import json
import multiprocessing
import tempfile
import time
from pathlib import Path
from typing import Any


def _invoke(root: str, host: str, lane: int) -> dict[str, Any]:
    from finishup.cli.observe_hooks import (
        handle_claude_observe,
        handle_cursor_observe,
        handle_observe,
    )
    from finishup.domain.observation_profiles import (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )

    state = Path(root) / "state"
    workspace = str(Path(root) / "workspace")
    payload = {
        "session_id": f"probe-{lane}",
        "tool_name": "Bash",
        "tool_use_id": f"call-{lane}",
        "tool_input": {"command": "true"},
        "event_ordinal": 1,
    }
    arguments: dict[str, Any] = {
        "event_name": "PreToolUse",
        "stdout": io.BytesIO(),
        "workspace": workspace,
        "_state": state,
        "skip_service": True,
    }
    if host == "claude":
        handler = handle_claude_observe
        arguments["observation_profile"] = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    elif host == "cursor":
        handler = handle_cursor_observe
        arguments["event_name"] = "preToolUse"
        arguments["observation_profile"] = CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
        payload["conversation_id"] = payload.pop("session_id")
    else:
        handler = handle_observe
        payload["tool_name"] = "shell"
        payload["correlation_id"] = payload["tool_use_id"]
    arguments["stdin_bytes"] = json.dumps(payload).encode()
    started = time.monotonic_ns()
    code = handler(**arguments)
    ended = time.monotonic_ns()
    return {
        "lane": lane,
        "start_ns": started,
        "end_ns": ended,
        "ms": (ended - started) / 1e6,
        "exit_code": code,
    }


def _worker(root: str, host: str, lane: int, barrier: Any, results: Any) -> None:
    # Import before the barrier; the reported boundary excludes interpreter
    # startup and explicitly measures concurrent adapter/store execution.
    import finishup.cli.observe_hooks  # noqa: F401

    barrier.wait(timeout=30)
    results.put(_invoke(root, host, lane))


def _seed(root: Path, retained: bool, pending_rows: int = 60) -> tuple[Any, str]:
    from finishup.adapters.integrations.observation_local import (
        LocalObservationStore,
        ObservationOutboxRow,
    )
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope

    store = LocalObservationStore(_state=root / "state")
    workspace = store.workspace_commitment(str(root / "workspace"))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "seed")
    if retained and pending_rows > 60:
        # A larger accepted queue needs a capacity that admits it (#689 probe shapes).
        from finishup.domain.observation_budget import LARGEST_CAPACITY
        from finishup.domain.observation_settings import (
            ObservationDetailProfile,
            ObservationSelection,
        )

        store.set_workspace_selection(
            workspace, ObservationSelection(ObservationDetailProfile.DETAILED, LARGEST_CAPACITY)
        )
    if retained:
        with store.batched(workspace):
            state = store._load(workspace)  # pyright: ignore[reportPrivateUsage]
            assert state.envelopes is not None and state.quarantine is not None
            assert state.pending_outbox is not None
            now = store._wall_timestamp()  # pyright: ignore[reportPrivateUsage]
            # 250 retained envelopes, ``pending_rows`` accepted rows (60 is the
            # 2026-09-10 shape, about 366 KiB) and 199 quarantined rows.
            for ordinal in range(449 + pending_rows):
                envelope = map_hook_payload_to_envelope(
                    "PostToolUse",
                    {
                        "session_id": "seed",
                        "tool_name": "shell",
                        "exit_status": 1,
                        "correlation_id": f"seed-{ordinal}",
                    },
                    session_commitment=session,
                    event_ordinal=ordinal + 1,
                    key_material=store.key_material(),
                )
                if ordinal < 250:
                    state.envelopes.append(envelope)
                elif ordinal < 250 + pending_rows:
                    state.pending_outbox.append(ObservationOutboxRow("seed", envelope))
                else:
                    state.quarantine.append(("seed", envelope, "service_unavailable", now))
            store._save(workspace, state)  # pyright: ignore[reportPrivateUsage]
    return store, workspace


# After the hooks finish, the sweeper keeps draining for at most this long; whatever is still
# pending then is reported rather than waited for.
_DRAIN_GRACE_SECONDS = 60.0


def _drain_concurrently(store: Any, stop: Any, delivered: set[str], stats: dict[str, Any]) -> None:
    """Drive the real service sweeper against the same store while the hooks run (#689).

    The coordinator is an acknowledging stub: no service, vault, ledger or network. It records
    which host lanes reached delivery so a delivered input still counts as retained.
    """

    import asyncio

    from finishup.application.observation_drain import ObservationOutboxSweeper
    from finishup.domain.observation import ObservationIngestDisposition, ObservationIngestResult

    class _Acknowledging:
        async def ingest_request(self, request: Any) -> ObservationIngestResult:
            delivered.add(request.codex_session_id)
            return ObservationIngestResult(
                ObservationIngestDisposition.DUPLICATE, "duplicate", None
            )

    async def loop() -> None:
        sweeper = ObservationOutboxSweeper(store, _Acknowledging(), budget_seconds=20.0)
        stopped_at: float | None = None
        try:
            while True:
                try:
                    summary = await asyncio.wait_for(sweeper.sweep(), timeout=30.0)
                except Exception as error:  # the daemon records these and continues
                    failures = stats["sweep_failures"]
                    failures[type(error).__name__] = failures.get(type(error).__name__, 0) + 1
                    attempted = 0
                else:
                    stats["passes"] += 1
                    stats["acknowledged"] += summary.acknowledged
                    for reason, count in summary.reasons:
                        stats["reasons"][reason] = stats["reasons"].get(reason, 0) + count
                    attempted = summary.attempted
                if stop.is_set():
                    now = time.monotonic()
                    stopped_at = now if stopped_at is None else stopped_at
                    if attempted == 0 or now - stopped_at >= _DRAIN_GRACE_SECONDS:
                        stats["drain_after_hooks_s"] = round(now - stopped_at, 1)
                        return
                if attempted == 0:
                    await asyncio.sleep(0.05)
        finally:
            sweeper.close()

    asyncio.run(loop())


def run(
    host: str,
    fanout: int,
    retained: bool,
    pending_rows: int = 60,
    drain: bool = False,
) -> dict[str, Any]:
    # Resolve macOS's temporary path before creating an owner-only directory.
    with tempfile.TemporaryDirectory(
        prefix="yz-hooks-", dir=Path(tempfile.gettempdir()).resolve()
    ) as name:
        root = Path(name)
        root.chmod(0o700)
        (root / "workspace").mkdir()
        store, workspace = _seed(root, retained, pending_rows)
        before = store.selection_accounting(workspace)
        before_pending = store.pending_outbox_count(workspace)
        before_quarantine = store.quarantined_count(workspace)
        before_bytes = store._workspace_path(workspace).stat().st_size
        import threading

        from finishup.adapters.integrations import observation_local

        lock_events: list[Any] = []
        if hasattr(observation_local, "set_observation_store_lock_reporter"):
            # The parent plays the service: name its role and count its lock events.
            observation_local.set_observation_store_lock_role("service")
            observation_local.set_observation_store_lock_reporter(lock_events.append)
        delivered: set[str] = set()
        drain_stats: dict[str, Any] = {
            "passes": 0,
            "acknowledged": 0,
            "reasons": {},
            "sweep_failures": {},
        }
        stop = threading.Event()
        drainer = (
            threading.Thread(target=_drain_concurrently, args=(store, stop, delivered, drain_stats))
            if drain
            else None
        )
        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(fanout + 1)
        results = context.Queue()
        workers = [
            context.Process(target=_worker, args=(name, host, lane, barrier, results))
            for lane in range(fanout)
        ]
        try:
            for worker in workers:
                worker.start()
            barrier.wait(timeout=30)
            if drainer is not None:
                drainer.start()
            samples = [results.get(timeout=30) for _ in workers]
            for worker in workers:
                worker.join(timeout=10)
                if worker.exitcode != 0:
                    raise RuntimeError("probe_worker_failed")
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.terminate()
                    worker.join(timeout=10)
            results.close()
            stop.set()
            if drainer is not None and drainer.is_alive():
                # One more pass may run to its 30-second deadline after the grace ends.
                drainer.join(timeout=_DRAIN_GRACE_SECONDS + 60.0)
        from finishup.cli.hook_diagnostics import hook_diagnostic_summary
        from finishup.protocol.canonical import canonical_encode

        after = store.selection_accounting(workspace)
        lanes = {row.codex_session_id for row in store.list_pending_outbox_rows(workspace)}
        prefix = {"codex": "", "claude": "claude:", "cursor": "cursor:"}[host]
        for sample in samples:
            lane = f"{prefix}probe-{sample['lane']}"
            sample["retained"] = lane in lanes or lane in delivered
        observed = after["observed_count"] - before["observed_count"]
        values = sorted(sample["ms"] for sample in samples)

        def percentile(p: int) -> float:
            return values[(len(values) * p + 99) // 100 - 1]

        return {
            "host": host,
            "fanout": fanout,
            "retained": retained,
            "diagnostics": json.loads(
                canonical_encode(hook_diagnostic_summary(_state=root / "state"))
            ),
            "coverage": "synthetic_concurrent_native_adapters_no_rpc_no_vendor_host",
            "initial_state_bytes": before_bytes,
            "pending_rows_seeded": pending_rows if retained else 0,
            "unaccounted_input_count": fanout - observed,
            "retained_invocation_count": sum(sample["retained"] for sample in samples),
            "retained_ms": [sample["ms"] for sample in samples if sample["retained"]],
            "not_retained_ms": [sample["ms"] for sample in samples if not sample["retained"]],
            "initial_pending": before_pending,
            "final_pending": store.pending_outbox_count(workspace),
            "initial_quarantined": before_quarantine,
            "final_quarantined": store.quarantined_count(workspace),
            "accounting_before": dict(before),
            "accounting_after": dict(after),
            "p50_ms": percentile(50),
            "p95_ms": percentile(95),
            "p99_ms": percentile(99),
            "max_ms": values[-1],
            "samples": sorted(samples, key=lambda sample: sample["lane"]),
            "drain": drain_stats if drain else None,
            "service_lock_events": {
                "timeouts": sum(1 for event in lock_events if event.kind == "timeout"),
                "long_holds": sum(1 for event in lock_events if event.kind == "long_hold"),
                "timeout_holder_roles": sorted(
                    {event.timeout.holder_role for event in lock_events if event.timeout}
                ),
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fanout", type=int, default=8, choices=range(1, 17))
    parser.add_argument("--host", choices=["codex", "claude", "cursor", "all"], default="all")
    parser.add_argument("--retained", action="store_true")
    parser.add_argument(
        "--pending-rows",
        type=int,
        default=60,
        choices=range(60, 8_193),
        metavar="60..8192",
        help="accepted rows in the retained fixture (larger than 60 selects Largest capacity)",
    )
    parser.add_argument(
        "--drain",
        action="store_true",
        help="run the service sweeper against the same store, with an acknowledging stub",
    )
    args = parser.parse_args()
    hosts = ["codex", "claude", "cursor"] if args.host == "all" else [args.host]
    for host in hosts:
        print(
            json.dumps(
                run(host, args.fanout, args.retained, args.pending_rows, args.drain),
                sort_keys=True,
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
