"""A test-only workspace agent: answers ``workspace_call`` frames from a real local repository.

It is not the product's client-side agent (``finishup.client.workspace_agent``). It decodes each
call with the catalog codecs, runs the real local adapters against its own root (the repository
the "client machine" holds), and encodes the answer, so a test can prove what the server learned
came from this root and nothing else. Observation operations are not declared.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.task_input_read import (
    list_beneath,
    read_declared_test,
    read_outside_inputs,
    read_text_beneath,
    snapshot_outside_inputs,
)
from finishup.ports.change_capture import ChangeCaptureUnavailable
from finishup.ports.control import WorkspaceAgentDeclaration, WorkspaceCall, WorkspaceReply
from finishup.ports.workspace_agent import (
    CaptureArguments,
    CaptureMetadataArguments,
    ClassifyUndeclaredReferencesArguments,
    CountChangeLinesArguments,
    ListBeneathArguments,
    LstatCandidatesArguments,
    LstatFacts,
    ProbeRequestedPathsArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    SnapshotOutsideInputsArguments,
    WorkspaceCodecError,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    operation_spec,
    outcome_for_reason,
    resolve_client_location,
)

__all__ = ["FakeWorkspaceAgent", "GIT_AND_READ_OPERATIONS", "fake_declaration"]

GIT_AND_READ_OPERATIONS: tuple[str, ...] = tuple(
    sorted(
        (
            op.value
            for op in WorkspaceOperation
            if op
            not in {
                WorkspaceOperation.OPEN_WORKSPACE,
                WorkspaceOperation.LOAD_CHECK_POLICY,
                WorkspaceOperation.SUBJECT_STATE_CAPTURE,
                WorkspaceOperation.LIST_CHANGED_PATHS,
                WorkspaceOperation.INSPECT,
                WorkspaceOperation.RUN_APPROVED_CHECK,
            }
        ),
        key=str.encode,
    )
)


def fake_declaration() -> WorkspaceAgentDeclaration:
    return WorkspaceAgentDeclaration(GIT_AND_READ_OPERATIONS, 6_291_456)


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class FakeWorkspaceAgent:
    """Answers for one claimed ``root``; ``handle`` is set from the connection's hello-result."""

    root: Path
    handle: str | None = None
    operations: list[str] = field(default_factory=list[str])
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self._capture = GitChangeCaptureAdapter()

    def _workspace(self, handle: str) -> str:
        if handle != self.handle:
            raise _Refused("workspace_not_claimed")
        return str(self.root)

    def _location(self, value: str) -> str:
        assert self.handle is not None
        resolved = resolve_client_location(value, self.handle, str(self.root))
        if resolved is None:
            raise _Refused("workspace_not_claimed")
        return resolved

    def _locations(self, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(self._location(value) for value in values)

    def answer(self, call: WorkspaceCall) -> WorkspaceReply:
        with self._lock:
            self.operations.append(call.operation)
        spec = operation_spec(call.operation)
        assert spec is not None
        try:
            arguments = spec.decode_arguments(call.arguments)
            result = spec.encode_result(self._run(spec.operation, arguments))
        except WorkspaceCodecError as exc:
            reason = (
                "arguments_invalid" if exc.reason.startswith("arguments") else "result_too_large"
            )
            return self._failure(call, reason)
        except _Refused as exc:
            return self._failure(call, exc.reason)
        except ChangeCaptureUnavailable as exc:
            return self._failure(call, exc.reason)
        return WorkspaceReply("workspace_reply", "1.0", call.call_id, "ok", result, None)

    @staticmethod
    def _failure(call: WorkspaceCall, reason: str) -> WorkspaceReply:
        return WorkspaceReply(
            "workspace_reply", "1.0", call.call_id, outcome_for_reason(reason), None, reason
        )

    def _run(self, operation: WorkspaceOperation, arguments: Any) -> Any:  # noqa: ANN401, C901
        capture = self._capture
        if operation is WorkspaceOperation.READ_TASK_BASE:
            assert type(arguments) is WorkspaceOnlyArguments
            return capture.read_task_base(self._workspace(arguments.workspace))
        if operation is WorkspaceOperation.CAPTURE:
            assert type(arguments) is CaptureArguments
            options: dict[str, Any] = {}
            if arguments.priority_paths:
                options["priority_paths"] = arguments.priority_paths
            if arguments.input_paths:
                options["input_paths"] = arguments.input_paths
            if arguments.space_cut_paths:
                options["space_cut_paths"] = arguments.space_cut_paths
            return capture.capture(self._workspace(arguments.workspace), arguments.base, **options)
        if operation is WorkspaceOperation.CAPTURE_METADATA:
            assert type(arguments) is CaptureMetadataArguments
            return capture.capture_metadata(self._workspace(arguments.workspace), arguments.base)
        if operation is WorkspaceOperation.PROBE_REQUESTED_PATHS:
            assert type(arguments) is ProbeRequestedPathsArguments
            return capture.probe_requested_paths(
                self._workspace(arguments.workspace), arguments.values
            )
        if operation is WorkspaceOperation.COUNT_CHANGE_LINES:
            assert type(arguments) is CountChangeLinesArguments
            return capture.count_change_lines(
                self._workspace(arguments.workspace), arguments.base_commit, arguments.base_paths
            )
        if operation is WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES:
            assert type(arguments) is ClassifyUndeclaredReferencesArguments
            return capture.classify_undeclared_references(
                self._workspace(arguments.workspace),
                arguments.deliverables,
                arguments.candidates,
                arguments.declared,
            )
        if operation is WorkspaceOperation.READ_OUTSIDE_INPUTS:
            assert type(arguments) is ReadOutsideInputsArguments
            return read_outside_inputs(
                arguments.roots,
                arguments.values,
                limit=arguments.limit,
                excluded=self._locations(arguments.excluded),
                space_cut=arguments.space_cut,
            )
        if operation is WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS:
            assert type(arguments) is SnapshotOutsideInputsArguments
            return snapshot_outside_inputs(
                arguments.roots,
                arguments.values,
                limit=arguments.limit,
                max_bytes=arguments.max_bytes,
                seconds=arguments.budget_ms / 1000,
                excluded=self._locations(arguments.excluded),
            )
        if operation is WorkspaceOperation.READ_DECLARED_TEST:
            assert type(arguments) is ReadDeclaredTestArguments
            return read_declared_test(
                self._location(arguments.location), excluded=self._locations(arguments.excluded)
            )
        if operation is WorkspaceOperation.READ_TEXT_BENEATH:
            assert type(arguments) is ReadTextBeneathArguments
            return read_text_beneath(
                self._location(arguments.root),
                arguments.relative,
                excluded=self._locations(arguments.excluded),
                expired=lambda: False,
            )
        if operation is WorkspaceOperation.LIST_BENEATH:
            assert type(arguments) is ListBeneathArguments
            return list_beneath(
                self._location(arguments.root),
                arguments.relative,
                excluded=self._locations(arguments.excluded),
                expired=lambda: False,
                inspect=arguments.inspect,
            )
        if operation is WorkspaceOperation.LSTAT_CANDIDATES:
            assert type(arguments) is LstatCandidatesArguments
            found: list[LstatFacts | None] = []
            for path in arguments.paths:
                try:
                    found.append(LstatFacts.from_stat_result(os.lstat(path)))
                except OSError:
                    found.append(None)
            return tuple(found)
        raise _Refused("operation_not_declared")
