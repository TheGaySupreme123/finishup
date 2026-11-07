"""A test-only workspace agent: answers ``workspace_call`` frames from a real local repository.

Its Git operations are not the product's client-side agent (``finishup.client.workspace_agent``):
it decodes each call with the catalog codecs, runs the real local adapters against its own root
(the repository the "client machine" holds), and encodes the answer, so a test can prove what the
server learned came from this root and nothing else. Its reads go through the product's own
``WorkspaceAgentHandler`` for that root, so they keep the agent's confinement: outside the
claimed workspace only beneath the folders the test admits (``admitted_folders``, the client's
``finishup server folders`` record), declared tests included. Observation operations are not
declared.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.client.server_folders import OutsideReadMode, OutsideReads
from finishup.client.workspace_agent import WorkspaceAgentHandler
from finishup.ports.change_capture import ChangeCaptureUnavailable
from finishup.ports.control import (
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.workspace_agent import (
    CaptureArguments,
    CaptureMetadataArguments,
    ClassifyUndeclaredReferencesArguments,
    CountChangeLinesArguments,
    ProbeRequestedPathsArguments,
    WorkspaceCodecError,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    operation_spec,
    outcome_for_reason,
)

__all__ = ["FakeWorkspaceAgent", "GIT_AND_READ_OPERATIONS", "fake_declaration"]

# Answered by the product's own handler, with the agent's confinement.
_READS: frozenset[WorkspaceOperation] = frozenset(
    {
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
        WorkspaceOperation.READ_DECLARED_TEST,
        WorkspaceOperation.READ_TEXT_BENEATH,
        WorkspaceOperation.LIST_BENEATH,
        WorkspaceOperation.LSTAT_CANDIDATES,
    }
)

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
    """Answers for one claimed ``root``; ``handle`` is set from the connection's hello-result.

    ``admitted_folders`` stands for the folders this client's owner listed for the server
    (``finishup server folders add``), and ``mode`` for its outside-read mode (``listed`` unless
    a test says otherwise); both are read on every call, as the record is.
    """

    root: Path
    handle: str | None = None
    operations: list[str] = field(default_factory=list[str])
    admitted_folders: list[str] = field(default_factory=list[str])
    mode: OutsideReadMode = "listed"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self._capture = GitChangeCaptureAdapter()
        self._reads = WorkspaceAgentHandler(
            WorkspaceLocator(str(self.root)),
            protected=(),
            outside_reads=lambda: OutsideReads(self.mode, tuple(self.admitted_folders)),
        )

    def _workspace(self, handle: str) -> str:
        if handle != self.handle:
            raise _Refused("workspace_not_claimed")
        return str(self.root)

    def answer(self, call: WorkspaceCall) -> WorkspaceReply:
        with self._lock:
            self.operations.append(call.operation)
        spec = operation_spec(call.operation)
        assert spec is not None
        if spec.operation in _READS:
            return self._reads.answer(call, workspace_handle=self.handle)
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
        raise _Refused("operation_not_declared")
