"""Bounded snapshots of task-named outside inputs (#1118 unit 1, ADR-031 amendment).

A file the task names beneath a root the owner admitted is read once, whole, when the task starts
(``task_start``) or when the task first names it as an input (``admission_time``). A later check
sends that copy instead of the file's current bytes, so an agent that rewrites the specification
cannot pass its edit off as the original (AIP-1). Copies are redacted before they are kept, are
stored as encrypted ``change_capture`` objects, and count against task-wide bounds that no check
replenishes. Nothing is read when the policy admits no root or the review recipe carries no task
inputs, so a local-only task never reads a file to prepare a review it will not run.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, cast

from finishup.adapters.task_input_read import OutsideSnapshotRead
from finishup.application.check_change import (
    _read,  # pyright: ignore[reportPrivateUsage]
    _redacted_text,  # pyright: ignore[reportPrivateUsage]
    _store,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import PrivacyPolicy
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.ports.change_capture import (
    MAX_SNAPSHOT_ADMISSION_SECONDS,
    MAX_SNAPSHOT_CANDIDATES,
    MAX_SNAPSHOT_FILE_BYTES,
    MAX_SNAPSHOT_FILES,
    MAX_SNAPSHOT_SECONDS,
    MAX_SNAPSHOT_TOTAL_BYTES,
    TASK_INPUT_SNAPSHOT_MEDIA_TYPE,
    SnapshotBoundary,
    SnapshotFile,
    SnapshotOmissionReason,
    TaskInputSnapshotSet,
    decode_task_input_snapshot,
    encode_task_input_snapshot,
)
from finishup.ports.clock import ClockPort
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.ports.runtime import TaskRuntime

__all__ = [
    "InputSnapshotScope",
    "SnapshotReader",
    "load_input_snapshots",
    "record_input_snapshot",
    "snapshot_roots",
]

_COMPONENT: Final = "input_snapshot"

# The service's trusted outside reader, whole-file variant (``snapshot_outside_inputs``).
type SnapshotReader = Callable[..., tuple[OutsideSnapshotRead, ...]]


@dataclass(frozen=True, slots=True)
class InputSnapshotScope:
    """What a snapshot may read now: the admitted roots, directories never read from, and the
    service's trusted reader."""

    roots: tuple[str, ...]
    excluded: tuple[str, ...]
    reader: SnapshotReader


def snapshot_roots(policy: PrivacyPolicy, carries_task_inputs: bool) -> tuple[str, ...]:
    """The roots a snapshot may read beneath under ``policy``; empty when it may read nothing.

    Only when AI-powered review can run at all (the external channel or the local model is on)
    and its recipe carries task inputs: a local-only or no-file policy never reads ahead.
    """

    review_on = policy.local_model_enabled or any(
        item.enabled and item.channel.value == "llm_inference" for item in policy.channel_policies
    )
    return policy.admitted_input_roots if review_on and carries_task_inputs else ()


async def load_input_snapshots(
    runtime: TaskRuntime, request_id: str | None
) -> tuple[TaskInputSnapshotSet, ...]:
    """The task's kept snapshot sets, oldest first; empty when none or unreadable."""

    loader = getattr(runtime.ledger, "load_task_input_snapshots", None)
    if not callable(loader):
        return ()
    try:
        refs = await cast(Callable[[], Awaitable[tuple[ObjectRef, ...]]], loader)()
        sets: list[TaskInputSnapshotSet] = []
        for ref in refs:
            if (
                ref.metadata.kind is not ObjectKind.CHANGE_CAPTURE
                or ref.metadata.media_type != TASK_INPUT_SNAPSHOT_MEDIA_TYPE
                or ref.metadata.task_id != runtime.task_id
            ):
                raise ValueError("task_input_snapshot_invalid")
            sets.append(decode_task_input_snapshot(await _read(runtime, ref)))
        return tuple(sets)
    except Exception as exc:
        # An unreadable snapshot is no snapshot: the check labels current bytes as unverified.
        record_unexpected_exception_without_raising(
            exc, component=_COMPONENT, operation="input_snapshot_unreadable", request_id=request_id
        )
        return ()


async def record_input_snapshot(
    *,
    runtime: TaskRuntime,
    values: tuple[str, ...],
    scope: InputSnapshotScope,
    boundary: SnapshotBoundary,
    clock: ClockPort,
    request_id: str | None,
) -> bool:
    """Keep one snapshot set for the outside ``values`` not yet kept; ``True`` when recorded.

    Task-wide bounds (4 files, 256 KiB each, 1 MiB, 16 candidates, 10 s) are counted from the
    sets already kept, so a retry or a later declaration never resets them. A candidate the read
    could not keep whole is recorded with its reason, never as a partial original. A failure
    records nothing and leaves the task without a baseline for those inputs, which its checks
    then disclose; it never fails the start or publication that called it.
    """

    recorder = getattr(runtime.ledger, "record_task_input_snapshot", None)
    if not callable(recorder) or not scope.roots:
        return False
    try:
        prior = await load_input_snapshots(runtime, request_id)
        seen = {item.path for kept in prior for item in kept.files} | {
            path for kept in prior for path, _reason in kept.omitted
        }
        files_left = MAX_SNAPSHOT_FILES - sum(len(kept.files) for kept in prior)
        bytes_left = MAX_SNAPSHOT_TOTAL_BYTES - sum(
            item.size for kept in prior for item in kept.files
        )
        candidates_left = MAX_SNAPSHOT_CANDIDATES - sum(kept.candidates for kept in prior)
        seconds_left = MAX_SNAPSHOT_SECONDS - sum(kept.elapsed_ms for kept in prior) / 1000
        outside = tuple(
            dict.fromkeys(
                os.path.normpath(value) + ("/" if value.endswith("/") else "")
                for value in values
                if value.startswith("/") and os.path.normpath(value) not in seen
            )
        )[: max(0, candidates_left)]
        if not outside or files_left < 1 or seconds_left <= 0:
            return False
        started = time.monotonic()
        reads = await asyncio.to_thread(
            lambda: scope.reader(
                scope.roots,
                outside,
                # Bounded by candidates and time; the file budget is applied below, so a
                # file too large or not text never takes a kept file's place.
                limit=MAX_SNAPSHOT_CANDIDATES,
                max_bytes=MAX_SNAPSHOT_FILE_BYTES,
                seconds=min(MAX_SNAPSHOT_ADMISSION_SECONDS, seconds_left),
                excluded=scope.excluded,
            )
        )
        files: list[SnapshotFile] = []
        omitted: list[tuple[str, SnapshotOmissionReason]] = []
        for read in reads:
            if read.path in seen:
                continue
            seen.add(read.path)
            if read.text is None:
                omitted.append((read.path, read.reason or "unreadable"))
            elif len(files) >= files_left or read.size > bytes_left:
                omitted.append((read.path, "budget"))
            else:
                try:
                    kept_text, redacted = _redacted_text(read.text)
                except Exception:
                    omitted.append((read.path, "redaction_incomplete"))
                    continue
                files.append(SnapshotFile(read.path, read.root, kept_text, read.size, redacted))
                bytes_left -= read.size
        if not files and not omitted:
            return False
        elapsed_ms = min(3_600_000, int((time.monotonic() - started) * 1000))
        snapshot = TaskInputSnapshotSet(
            boundary,
            len(outside),
            elapsed_ms,
            tuple(files),
            tuple(omitted[:MAX_SNAPSHOT_CANDIDATES]),
        )
        ref = await _store(
            runtime, encode_task_input_snapshot(snapshot), TASK_INPUT_SNAPSHOT_MEDIA_TYPE, clock
        )
        return await cast(Callable[[ObjectRef], Awaitable[bool]], recorder)(ref)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc, component=_COMPONENT, operation="input_snapshot_failed", request_id=request_id
        )
        return False
