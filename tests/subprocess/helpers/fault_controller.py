"""Deterministic descriptor-driven crash-boundary controller."""

from __future__ import annotations

import errno
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final, Literal, cast

from helpers.child import (
    ChildHandle,
    ChildSpec,
    signal_child,
    spawn_installed,
    terminate_owned_group,
)

__all__ = [
    "FAULT_DESCRIPTOR_FD",
    "ArmedChild",
    "CommitClass",
    "FaultMode",
    "FaultObservation",
    "FaultPlan",
    "FaultPoint",
    "arm_fault",
    "assert_fault_hooks_unavailable_in_release",
    "wait_and_trigger",
]

FAULT_DESCRIPTOR_FD: Final = 198
_MARKER_CAP: Final = 4_096
_DESCRIPTOR_LOCK: Final = threading.Lock()


class FaultPoint(StrEnum):
    BEFORE_OBJECT_CREATION = "before_object_creation"
    AFTER_PARTIAL_CIPHERTEXT = "after_partial_ciphertext"
    AFTER_FILE_FSYNC_BEFORE_RENAME = "after_file_fsync_before_rename"
    AFTER_RENAME_BEFORE_DIRECTORY_FSYNC = "after_rename_before_directory_fsync"
    AFTER_DURABLE_OBJECT_BEFORE_BEGIN = "after_durable_object_before_begin"
    AFTER_SEQUENCE_ALLOCATION = "after_sequence_allocation"
    AFTER_EVENT_INSERT = "after_event_insert"
    AFTER_PROJECTION_UPDATE = "after_projection_update"
    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT_BEFORE_RESPONSE = "after_commit_before_response"
    DURING_MCP_STDOUT_RESPONSE = "during_mcp_stdout_response"
    DURING_CHECKPOINT = "during_checkpoint"
    DURING_BACKUP_FINALIZATION = "during_backup_finalization"
    DURING_CATALOG_ROUTE_SWITCH = "during_catalog_route_switch"
    AFTER_PROVIDER_RESPONSE = "after_provider_response"
    BEFORE_SEMANTIC_FRESHNESS_VALIDATION = "before_semantic_freshness_validation"


class FaultMode(StrEnum):
    SIGKILL = "sigkill"
    ABRUPT_EXIT = "abrupt_exit"
    INJECTED_IO_ERROR = "injected_io_error"
    BROKEN_PIPE = "broken_pipe"


type CommitClass = Literal["pre_commit", "post_commit", "maintenance", "semantic"]

_POINT_CLASS: Final[dict[FaultPoint, CommitClass]] = {
    **{
        point: "pre_commit"
        for point in (
            FaultPoint.BEFORE_OBJECT_CREATION,
            FaultPoint.AFTER_PARTIAL_CIPHERTEXT,
            FaultPoint.AFTER_FILE_FSYNC_BEFORE_RENAME,
            FaultPoint.AFTER_RENAME_BEFORE_DIRECTORY_FSYNC,
            FaultPoint.AFTER_DURABLE_OBJECT_BEFORE_BEGIN,
            FaultPoint.AFTER_SEQUENCE_ALLOCATION,
            FaultPoint.AFTER_EVENT_INSERT,
            FaultPoint.AFTER_PROJECTION_UPDATE,
            FaultPoint.BEFORE_COMMIT,
        )
    },
    FaultPoint.AFTER_COMMIT_BEFORE_RESPONSE: "post_commit",
    FaultPoint.DURING_MCP_STDOUT_RESPONSE: "post_commit",
    FaultPoint.DURING_CHECKPOINT: "maintenance",
    FaultPoint.DURING_BACKUP_FINALIZATION: "maintenance",
    FaultPoint.DURING_CATALOG_ROUTE_SWITCH: "maintenance",
    FaultPoint.AFTER_PROVIDER_RESPONSE: "semantic",
    FaultPoint.BEFORE_SEMANTIC_FRESHNESS_VALIDATION: "semantic",
}


@dataclass(frozen=True, slots=True)
class FaultPlan:
    point: FaultPoint
    mode: FaultMode
    operation_identity: str
    request_identity: str
    deadline_seconds: float
    expected_class: CommitClass

    def __post_init__(self) -> None:
        if type(self.point) is not FaultPoint or type(self.mode) is not FaultMode:
            raise TypeError("fault_plan_enum_invalid")
        for identity in (self.operation_identity, self.request_identity):
            if type(identity) is not str or not identity or len(identity) > 256:
                raise ValueError("fault_plan_identity_invalid")
        if type(self.deadline_seconds) is not float or not 0.1 <= self.deadline_seconds <= 600.0:
            raise ValueError("fault_plan_deadline_invalid")
        if self.expected_class not in {"pre_commit", "post_commit", "maintenance", "semantic"}:
            raise ValueError("fault_plan_class_invalid")
        if self.expected_class != _POINT_CLASS[self.point]:
            raise ValueError("fault_plan_class_invalid")


@dataclass(frozen=True, slots=True)
class FaultObservation:
    armed_monotonic: float
    reached_monotonic: float
    terminated_monotonic: float
    marker_ordinal: int
    exit_code: int | None
    signal: int | None
    reason_code: str


@dataclass(slots=True)
class ArmedChild:
    handle: ChildHandle
    plan: FaultPlan
    nonce: str
    _controller: socket.socket = field(repr=False)
    _transcript_path: Path = field(repr=False)
    _buffer: bytearray = field(default_factory=bytearray, repr=False)


def _install_descriptor(source_fd: int) -> int | None:
    try:
        saved = os.dup(FAULT_DESCRIPTOR_FD)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise
        saved = None
    os.dup2(source_fd, FAULT_DESCRIPTOR_FD, inheritable=True)
    return saved


def _restore_descriptor(saved: int | None) -> None:
    if saved is None:
        os.close(FAULT_DESCRIPTOR_FD)
        return
    try:
        os.dup2(saved, FAULT_DESCRIPTOR_FD, inheritable=False)
    finally:
        os.close(saved)


def _send_marker(stream: socket.socket, marker: dict[str, object]) -> None:
    encoded = json.dumps(marker, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"
    if len(encoded) > _MARKER_CAP:
        raise RuntimeError("fault_marker_too_large")
    stream.sendall(encoded)


def arm_fault(
    child_spec: ChildSpec,
    plan: FaultPlan,
    artifact_env: Mapping[str, str] | None = None,
) -> ArmedChild:
    """Spawn a child with the fixed private marker descriptor and send one arm record."""

    if type(child_spec) is not ChildSpec or type(plan) is not FaultPlan:
        raise TypeError("fault_arm_invalid")
    controller, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    controller.set_inheritable(False)
    child.set_inheritable(False)
    try:
        with _DESCRIPTOR_LOCK:
            saved = _install_descriptor(child.fileno())
            try:
                handle = spawn_installed(
                    child_spec,
                    {} if artifact_env is None else artifact_env,
                    _inherited_fds=(FAULT_DESCRIPTOR_FD,),
                )
            finally:
                _restore_descriptor(saved)
    except BaseException:
        controller.close()
        child.close()
        raise
    child.close()
    armed = ArmedChild(
        handle=handle,
        plan=plan,
        nonce=handle.temp_root.name,
        _controller=controller,
        _transcript_path=handle.temp_root / "fault-controller.jsonl",
    )
    _send_marker(
        controller,
        {
            "kind": "arm",
            "mode": plan.mode.value,
            "nonce": armed.nonce,
            "point": plan.point.value,
        },
    )
    return armed


def _next_marker(armed: ArmedChild, deadline: float) -> dict[str, object]:
    selector = selectors.DefaultSelector()
    selector.register(armed._controller, selectors.EVENT_READ)  # pyright: ignore[reportPrivateUsage]
    try:
        while time.monotonic() < deadline:
            newline = armed._buffer.find(b"\n")  # pyright: ignore[reportPrivateUsage]
            if newline >= 0:
                encoded = bytes(armed._buffer[:newline])  # pyright: ignore[reportPrivateUsage]
                del armed._buffer[: newline + 1]  # pyright: ignore[reportPrivateUsage]
                try:
                    decoded = json.loads(encoded)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError("fault_marker_invalid") from exc
                if type(decoded) is not dict:
                    raise RuntimeError("fault_marker_invalid")
                source = cast(dict[object, object], decoded)
                if any(type(key) is not str for key in source):
                    raise RuntimeError("fault_marker_invalid")
                return {cast(str, key): value for key, value in source.items()}
            events = selector.select(max(0.0, deadline - time.monotonic()))
            if not events:
                break
            chunk = armed._controller.recv(_MARKER_CAP)  # pyright: ignore[reportPrivateUsage]
            if not chunk:
                raise RuntimeError("fault_child_exited_before_marker")
            armed._buffer.extend(chunk)  # pyright: ignore[reportPrivateUsage]
            if len(armed._buffer) > _MARKER_CAP:  # pyright: ignore[reportPrivateUsage]
                raise RuntimeError("fault_marker_too_large")
    finally:
        selector.close()
    raise RuntimeError("fault_marker_deadline")


def _validate_marker(
    marker: dict[str, object],
    armed: ArmedChild,
    *,
    kind: Literal["armed", "reached"],
    ordinal: int,
) -> None:
    if marker != {
        "kind": kind,
        "nonce": armed.nonce,
        "ordinal": ordinal,
        "point": armed.plan.point.value,
    }:
        raise RuntimeError("fault_marker_invalid")


def _wait_for_exit(armed: ArmedChild, deadline: float) -> None:
    while armed.handle.process.poll() is None:
        if time.monotonic() >= deadline:
            raise RuntimeError("fault_termination_deadline")
        time.sleep(0.005)


def _write_transcript(armed: ArmedChild, observation: FaultObservation) -> None:
    record = {
        "exit_code": observation.exit_code,
        "marker_ordinal": observation.marker_ordinal,
        "reason_code": observation.reason_code,
        "signal": observation.signal,
    }
    encoded = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"
    descriptor = os.open(
        armed._transcript_path,  # pyright: ignore[reportPrivateUsage]
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def wait_and_trigger(armed: ArmedChild) -> FaultObservation:
    """Wait for exact semantic acknowledgement, trigger once, and persist structural evidence."""

    if type(armed) is not ArmedChild:
        raise TypeError("fault_armed_child_invalid")
    deadline = time.monotonic() + armed.plan.deadline_seconds
    try:
        armed_marker = _next_marker(armed, deadline)
        _validate_marker(armed_marker, armed, kind="armed", ordinal=1)
        armed_at = time.monotonic()
        reached_marker = _next_marker(armed, deadline)
        _validate_marker(reached_marker, armed, kind="reached", ordinal=2)
        reached_at = time.monotonic()
        if armed.plan.mode is FaultMode.SIGKILL:
            signal_child(armed.handle, signal.SIGKILL)
        else:
            _send_marker(
                armed._controller,  # pyright: ignore[reportPrivateUsage]
                {
                    "kind": "trigger",
                    "mode": armed.plan.mode.value,
                    "nonce": armed.nonce,
                    "point": armed.plan.point.value,
                },
            )
        _wait_for_exit(armed, deadline)
        terminated_at = time.monotonic()
        return_code = armed.handle.process.returncode
        observation = FaultObservation(
            armed_monotonic=armed_at,
            reached_monotonic=reached_at,
            terminated_monotonic=terminated_at,
            marker_ordinal=2,
            exit_code=return_code if return_code is not None and return_code >= 0 else None,
            signal=-return_code if return_code is not None and return_code < 0 else None,
            reason_code=f"fault_triggered:{armed.plan.mode.value}",
        )
        _write_transcript(armed, observation)
        return observation
    except BaseException:
        terminate_owned_group(armed.handle)
        raise
    finally:
        armed._controller.close()  # pyright: ignore[reportPrivateUsage]


def assert_fault_hooks_unavailable_in_release(installed_env: Mapping[str, str]) -> None:
    """Prove forged public environment cannot expose a daemon fault-hook surface."""

    environment = dict(installed_env)
    environment.update(
        {
            "FINISHUP_FAULT_POINT": FaultPoint.BEFORE_COMMIT.value,
            "FINISHUP_FAULT_MODE": FaultMode.SIGKILL.value,
            "FINISHUP_TEST_BUILD": "1",
        }
    )
    environment.pop("PYTHONPATH", None)
    probe = (
        "import finishup.service.daemon as d; "
        "names={'FaultPoint','FaultPlan','arm_fault','fault_hook'}; "
        "assert not names.intersection(d.__dict__); "
        "print('fault_hooks_unavailable')"
    )
    completed = subprocess.run(
        (sys.executable, "-I", "-c", probe),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        timeout=10.0,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout != b"fault_hooks_unavailable\n":
        raise AssertionError("release_fault_hook_surface_present")
    if completed.stderr:
        raise AssertionError("release_fault_hook_probe_diagnostic")
