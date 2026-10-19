"""Bounded snapshots of task-named outside inputs (#1118 unit 1, ADR-031 amendment).

A file the task names beneath a root the owner admitted is read once, whole, inside the operation
that admits it: the creating start, before its lifecycle event (``task_start``), or a later
statement or ``role: input`` declaration (``admission_time``). A later check sends that copy
instead of the file's current bytes, so an agent that rewrites the specification cannot pass its
edit off as the original (AIP-1).

Each boundary is reserved in the task ledger, keyed by its operation id, before anything is read.
The reservation takes the task-wide capacity left (4 files, 256 KiB each, 1 MiB, 16 candidates,
10 s with at most 5 s per boundary) in one ledger transaction, and its completion records what was
actually spent, even when nothing was kept, including the UTF-8 bytes of the paths it names
(32 KiB per task). A start whose scope is denied or unavailable still reserves its boundary, as a
gap, without reading. A retry of the same operation finds the reservation and rereads nothing:
its copy or its gap stands. Copies are redacted before they are kept and are stored as encrypted
``change_capture`` objects. Nothing is read unless the effective policy could send a file to
AI-powered review (``snapshot_roots``).
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, cast

from finishup.adapters.task_input_read import OutsideSnapshotRead
from finishup.application.check_change import (
    _read,  # pyright: ignore[reportPrivateUsage]
    _redacted_text,  # pyright: ignore[reportPrivateUsage]
    _store,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    ConversationReview,
    DataCategory,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
)
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.ports.change_capture import (
    MAX_SNAPSHOT_CANDIDATES,
    MAX_SNAPSHOT_FILE_BYTES,
    TASK_INPUT_SNAPSHOT_MEDIA_TYPE,
    SnapshotBoundary,
    SnapshotFile,
    SnapshotOmissionReason,
    SnapshotUsage,
    TaskChangeBaseStorePort,
    TaskInputSnapshotSet,
    decode_task_input_snapshot,
    encode_task_input_snapshot,
    snapshot_manifest_bytes,
)
from finishup.ports.clock import ClockPort
from finishup.ports.objects import ObjectRef
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

    Only when a file could reach AI-powered review at all: the recipe carries task inputs, the
    owner's conversation setting is not ``local_only``, and the external channel or the separately
    enabled local model admits repository excerpts of ordinary content. Any other policy reads
    nothing ahead for a review it cannot run.
    """

    excerpt, ordinary = DataCategory.REPOSITORY_EXCERPT, DataClass.ORDINARY_USER_CONTENT
    external = any(
        item.enabled
        and item.channel is EgressChannel.LLM_INFERENCE
        and excerpt in item.allowed_categories
        and ordinary in item.allowed_data_classes
        for item in policy.channel_policies
    )
    local = (
        policy.local_model_enabled
        and excerpt in policy.local_model_categories
        and ordinary in policy.local_model_data_classes
    )
    review = policy.effective_conversation_review is not ConversationReview.LOCAL_ONLY
    return (
        policy.admitted_input_roots
        if carries_task_inputs and review and (external or local)
        else ()
    )


async def _load_sets(runtime: TaskRuntime) -> tuple[TaskInputSnapshotSet, ...]:
    """The task's kept sets, oldest first; raises when any cannot be read."""

    refs = await cast(TaskChangeBaseStorePort, runtime.ledger).load_task_input_snapshots()
    return tuple([decode_task_input_snapshot(await _read(runtime, ref)) for ref in refs])


async def load_input_snapshots(
    runtime: TaskRuntime, request_id: str | None
) -> tuple[TaskInputSnapshotSet, ...]:
    """The task's kept sets for a check; empty when none or unreadable (the check then labels
    outside inputs as current bytes and discloses the missing baseline)."""

    if not callable(getattr(runtime.ledger, "load_task_input_snapshots", None)):
        return ()
    try:
        return await _load_sets(runtime)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc, component=_COMPONENT, operation="input_snapshot_unreadable", request_id=request_id
        )
        return ()


async def record_input_snapshot(
    *,
    runtime: TaskRuntime,
    key: str,
    values: tuple[str, ...],
    scope: InputSnapshotScope | None,
    boundary: SnapshotBoundary,
    clock: ClockPort,
    request_id: str | None,
) -> bool:
    """Keep one snapshot set at boundary ``key`` for the outside ``values``; ``True`` when kept.

    Reserves ``key`` first, even when ``scope`` is ``None`` or admits no root: that boundary reads
    nothing and stands as a gap. An already reserved key reads nothing. A candidate that could not
    be kept whole, including one past the capacity left, is recorded with its reason, never as a
    partial original; past the task's manifest bytes it is counted but not named. A failure,
    including an unreadable earlier set, keeps nothing and leaves the boundary spent; it never
    fails the start or publication that called it.
    """

    ledger = cast(TaskChangeBaseStorePort, runtime.ledger)
    outside = tuple(
        dict.fromkeys(
            os.path.normpath(value) + ("/" if value.endswith("/") else "")
            for value in values
            if value.startswith("/")
        )
    )
    if not outside or not callable(getattr(ledger, "reserve_task_input_snapshot", None)):
        return False
    try:
        grant = await ledger.reserve_task_input_snapshot(key)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc, component=_COMPONENT, operation="input_snapshot_failed", request_id=request_id
        )
        return False
    if grant is None:
        return False
    files: list[SnapshotFile] = []
    omitted: list[tuple[str, SnapshotOmissionReason]] = []
    attempted = 0
    left = grant.manifest  # Task-wide path bytes this boundary may still name.
    started: float | None = None
    ref: ObjectRef | None = None

    def omit(path: str, reason: SnapshotOmissionReason) -> None:
        nonlocal left
        if snapshot_manifest_bytes(path) <= left:
            left -= snapshot_manifest_bytes(path)
            omitted.append((path, reason))

    try:
        if scope is not None and scope.roots:
            prior = await _load_sets(runtime)
            seen = {i.path for kept in prior for i in kept.files} | {
                path for kept in prior for path, _reason in kept.omitted
            }
            wanted = tuple(v for v in outside if v.rstrip("/") not in seen)
            wanted = wanted[:MAX_SNAPSHOT_CANDIDATES]
            if wanted and grant.files and grant.candidates and grant.ms:
                attempted = grant.candidates  # Until the reader returns, every candidate is spent.
                started = time.monotonic()
                reads = await asyncio.to_thread(
                    lambda: scope.reader(
                        scope.roots,
                        wanted,
                        limit=grant.candidates,
                        max_bytes=MAX_SNAPSHOT_FILE_BYTES,
                        seconds=grant.ms / 1000,
                        excluded=scope.excluded,
                    )
                )
                attempted = min(len(reads), grant.candidates)
                bytes_left = grant.bytes
                for read in reads[:attempted]:
                    if read.path in seen:
                        continue
                    seen.add(read.path)
                    cost = snapshot_manifest_bytes(read.path, read.root)
                    if read.text is None:
                        omit(read.path, read.reason or "unreadable")
                    elif len(files) >= grant.files or read.size > bytes_left or cost > left:
                        omit(read.path, "budget")
                    else:
                        try:
                            kept_text, redacted = _redacted_text(read.text)
                        except Exception:
                            omit(read.path, "redaction_incomplete")
                            continue
                        files.append(
                            SnapshotFile(read.path, read.root, kept_text, read.size, redacted)
                        )
                        bytes_left -= read.size
                        left -= cost
            else:
                for value in wanted:
                    omit(value.rstrip("/"), "budget")
        if files or omitted:
            snapshot = TaskInputSnapshotSet(boundary, tuple(files), tuple(omitted))
            ref = await _store(
                runtime, encode_task_input_snapshot(snapshot), TASK_INPUT_SNAPSHOT_MEDIA_TYPE, clock
            )
    except Exception as exc:
        files, ref, left = [], None, grant.manifest
        record_unexpected_exception_without_raising(
            exc, component=_COMPONENT, operation="input_snapshot_failed", request_id=request_id
        )
    finally:
        elapsed = 0 if started is None else int((time.monotonic() - started) * 1000)
        spent = SnapshotUsage(
            len(files),
            sum(i.size for i in files),
            attempted,
            min(3_600_000, elapsed),
            grant.manifest - left,
        )
        try:
            await ledger.complete_task_input_snapshot(key, spent, ref)
        except Exception as exc:
            ref = None
            record_unexpected_exception_without_raising(
                exc, component=_COMPONENT, operation="input_snapshot_failed", request_id=request_id
            )
    return ref is not None
