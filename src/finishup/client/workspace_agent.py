"""The client-side workspace agent: answers a remote server's workspace calls (ADR-051).

A FinishUP server on another machine never reads the agent's workspace itself. When it needs
workspace evidence (a check-time change, a task input, a reviewer's file read, an approved check)
it sends a bounded ``workspace_call`` over the client's own control connection, and this handler
answers it by running the very local adapters a local service runs, with every fence they keep:
Git hardening and ownership checks, ignore rules, credential-named and hidden-path refusals,
byte and time bounds, and the network-denying check sandbox.

Two confinements hold on top of the adapters':

* **The claimed workspace only.** A handler is built for the one workspace its connection
  claimed. The server names that workspace by the connection's ``client:`` handle; the handler
  maps the handle to its own root and refuses any other handle (``workspace_not_claimed``).
* **Outside reads stay outside.** Reads beyond the workspace are confined to the admitted roots
  the server names (each must pass the owner-policy rule ``admitted_input_root_valid``) and never
  enter the claimed workspace through an outside root, or this client's own FinishUP directories
  at all, whatever the server lists as excluded.

An approved check runs only when the repository's own ``.finishup/checks.toml`` (read here, by
the existing policy loader) approves exactly the argv the server asked for; anything else is
refused (``check_not_approved``). HOME decisions are this machine's: every adapter consults this
process's home directory, never the server's.

Results travel in the catalog's codecs (``finishup.ports.workspace_agent``). Every non-``ok``
reply carries one closed reason; logs carry closed tokens only, never a path, argument or output.
``answer`` is synchronous and blocking: callers run it in a worker thread.
"""

from __future__ import annotations

import os
import posixpath
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from finishup.adapters.approved_checks import ApprovedCheckCommand, ApprovedCheckRunner
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.git_subject_state import (
    GitSubjectStateAdapter,
    list_changed_relative_paths,
    open_local_workspace,
)
from finishup.adapters.task_input_read import (
    ReadDeadline,
    list_beneath,
    read_declared_test,
    read_outside_inputs,
    read_text_beneath,
    snapshot_outside_inputs,
)
from finishup.adapters.workspace_inspect import LocalWorkspaceInspectAdapter
from finishup.application.observation_check_policy import (
    CHECK_POLICY_PATH,
    ObservationCheckPolicyAbsent,
    ObservationCheckPolicyAmbiguous,
    load_observation_check_policy,
)
from finishup.config import paths as config_paths
from finishup.domain.privacy import admitted_input_root_valid
from finishup.observability.logging import (
    record_public_error_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.ports.change_capture import ChangeCaptureUnavailable
from finishup.ports.check_sandbox import CheckSandboxPort
from finishup.ports.control import (
    WorkspaceAgentDeclaration,
    WorkspaceCall,
    WorkspaceLocator,
    WorkspaceReply,
)
from finishup.ports.subject_state import LocalWorkspaceHandle, SubjectStateCaptureCommand
from finishup.ports.workspace_agent import (
    MAX_WORKSPACE_FRAME_BYTES,
    WORKSPACE_OPERATION_NAMES,
    WORKSPACE_REPLY_REASONS,
    WORKSPACE_UNAVAILABLE_REASONS,
    ApprovedCheckRun,
    CaptureArguments,
    CaptureMetadataArguments,
    CheckPolicyRead,
    ClassifyUndeclaredReferencesArguments,
    CountChangeLinesArguments,
    InspectArguments,
    ListBeneathArguments,
    ListChangedPathsArguments,
    LstatCandidatesArguments,
    LstatFacts,
    OpenWorkspaceArguments,
    ProbeRequestedPathsArguments,
    ReadDeclaredTestArguments,
    ReadOutsideInputsArguments,
    ReadTextBeneathArguments,
    RunApprovedCheckArguments,
    SnapshotOutsideInputsArguments,
    SubjectStateCaptureArguments,
    WorkspaceCodecError,
    WorkspaceOnlyArguments,
    WorkspaceOperation,
    new_remote_workspace_handle,
    operation_spec,
    outcome_for_reason,
    resolve_client_location,
    workspace_handle_valid,
)
from finishup.ports.workspace_inspect import WorkspaceInspectCommand
from finishup.protocol.canonical import JsonValue

__all__ = [
    "WorkspaceAgentHandler",
    "client_protected_directories",
    "workspace_reply",
]

_COMPONENT: Final = "client.workspace_agent"
# Opened workspaces (``open_workspace``) this handler keeps; the oldest is forgotten first, and a
# call naming a forgotten one is answered ``handle_unknown`` so the server opens it again.
_MAX_OPEN_WORKSPACES: Final = 8


class _Outcome(Exception):
    """Internal: the call ends with this closed non-``ok`` reply reason."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in WORKSPACE_REPLY_REASONS:
            raise ValueError("workspace_reply_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def workspace_reply(call_id: str, reason: str | None, result: JsonValue = None) -> WorkspaceReply:
    """The reply to ``call_id``: ``ok`` with ``result`` when ``reason`` is None, else the outcome
    the closed ``reason`` belongs to, with no result."""

    if reason is None:
        return WorkspaceReply("workspace_reply", "1.0", call_id, "ok", result, None)
    return WorkspaceReply(
        "workspace_reply", "1.0", call_id, outcome_for_reason(reason), None, reason
    )


def client_protected_directories() -> tuple[str, ...]:
    """This client's own FinishUP directories, which no workspace call may ever read.

    The isolation root when one is in force, and every directory this process resolves for its
    bundle, configuration, cache, state, logs and endpoints. A directory that cannot be resolved
    is left out: it cannot be named, so there is nothing under that name to protect.
    """

    found: list[str] = []
    resolvers: tuple[Callable[[], Path | None], ...] = (
        config_paths.isolated_root,
        config_paths.bundle_root,
        lambda: config_paths.config_file_path().parent,
        config_paths.cache_dir,
        config_paths.state_dir,
        config_paths.log_dir,
        config_paths.runtime_dir,
    )
    for resolve in resolvers:
        try:
            directory = resolve()
        except Exception:  # noqa: BLE001 - an unresolvable directory has no name to protect
            continue
        if directory is not None and directory.is_absolute():
            found.append(os.path.normpath(os.fspath(directory)))
    return tuple(dict.fromkeys(found))


def _folded_within(path: str, directories: Iterable[str]) -> bool:
    """Whether ``path`` is one of ``directories`` or beneath one, compared case-folded.

    The outside read's own lexical rule: on a case-insensitive volume a differently cased
    spelling names the same directory, so the comparison errs toward refusing.
    """

    folded = posixpath.normpath(path).casefold()
    for directory in directories:
        root = posixpath.normpath(directory).casefold().rstrip("/")
        if folded == root or folded.startswith(root + "/"):
            return True
    return False


@dataclass(frozen=True, slots=True)
class _Call:
    """What one call may use: the session's workspace handle and the call's own deadline."""

    handle: str | None
    deadline: float

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())


class WorkspaceAgentHandler:
    """Answer one claimed workspace's ``workspace_call`` frames with the real local adapters."""

    __slots__ = (
        "_capture",
        "_declaration",
        "_inspect",
        "_opened",
        "_opened_guard",
        "_operations",
        "_protected",
        "_root",
        "_sandbox",
        "_subject_state",
        "_table",
    )

    def __init__(
        self,
        workspace: WorkspaceLocator,
        *,
        protected: Sequence[str] | None = None,
        operations: Iterable[str] | None = None,
        max_reply_bytes: int = MAX_WORKSPACE_FRAME_BYTES,
        check_sandbox: CheckSandboxPort | None = None,
    ) -> None:
        """``workspace`` is the locator the connection's claim was computed from.

        ``protected`` defaults to ``client_protected_directories()``; ``operations`` to the whole
        catalog. ``check_sandbox`` replaces the platform's network-denying sandbox only where a
        caller supplies an equally enforcing one.
        """

        if type(workspace) is not WorkspaceLocator:
            raise TypeError("workspace_locator_invalid")
        if posixpath.normpath(workspace.path) != workspace.path:
            raise ValueError("workspace_locator_path_invalid")
        directories = client_protected_directories() if protected is None else tuple(protected)
        if any(type(item) is not str or not item.startswith("/") for item in directories):
            raise ValueError("workspace_agent_protected_invalid")
        offered = tuple(
            sorted(
                set(WORKSPACE_OPERATION_NAMES if operations is None else operations),
                key=str.encode,
            )
        )
        self._declaration = WorkspaceAgentDeclaration(offered, max_reply_bytes)
        self._operations = frozenset(offered)
        self._root = workspace.path
        self._protected = directories
        # Exactly the service composition's adapters (``ready_composition``): the change capture
        # admits a project at HOME because this handler only ever answers for the workspace its
        # own connection claimed, as the service's locator is the one its connection proved.
        self._capture = GitChangeCaptureAdapter(admitted_home_project=True)
        self._subject_state = GitSubjectStateAdapter()
        self._inspect = LocalWorkspaceInspectAdapter()
        self._sandbox = check_sandbox
        self._opened: OrderedDict[str, LocalWorkspaceHandle] = OrderedDict()
        self._opened_guard = threading.Lock()
        self._table: dict[WorkspaceOperation, Callable[[Any, _Call], object]] = {
            WorkspaceOperation.READ_TASK_BASE: self._read_task_base,
            WorkspaceOperation.CAPTURE: self._capture_change,
            WorkspaceOperation.CAPTURE_METADATA: self._capture_metadata,
            WorkspaceOperation.PROBE_REQUESTED_PATHS: self._probe_requested_paths,
            WorkspaceOperation.COUNT_CHANGE_LINES: self._count_change_lines,
            WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES: self._classify_references,
            WorkspaceOperation.READ_OUTSIDE_INPUTS: self._read_outside_inputs,
            WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS: self._snapshot_outside_inputs,
            WorkspaceOperation.READ_DECLARED_TEST: self._read_declared_test,
            WorkspaceOperation.READ_TEXT_BENEATH: self._read_text_beneath,
            WorkspaceOperation.LIST_BENEATH: self._list_beneath,
            WorkspaceOperation.LSTAT_CANDIDATES: self._lstat_candidates,
            WorkspaceOperation.OPEN_WORKSPACE: self._open_workspace,
            WorkspaceOperation.LOAD_CHECK_POLICY: self._load_check_policy,
            WorkspaceOperation.SUBJECT_STATE_CAPTURE: self._subject_state_capture,
            WorkspaceOperation.LIST_CHANGED_PATHS: self._list_changed_paths,
            WorkspaceOperation.INSPECT: self._inspect_paths,
            WorkspaceOperation.RUN_APPROVED_CHECK: self._run_approved_check,
        }

    @property
    def declaration(self) -> WorkspaceAgentDeclaration:
        """What the hello offers: the operations this handler answers and its reply bound."""

        return self._declaration

    def answer(self, call: WorkspaceCall, *, workspace_handle: str | None) -> WorkspaceReply:
        """Run one call and return its reply; never raises for anything the call carried.

        ``workspace_handle`` is the ``client:`` handle the server answered this connection's
        hello with (None when it derived none): the only workspace name this call may use.
        """

        if type(call) is not WorkspaceCall:
            raise TypeError("workspace_call_invalid")
        reason: str
        try:
            return workspace_reply(call.call_id, None, self._run(call, workspace_handle))
        except _Outcome as outcome:
            reason = outcome.reason
        except ChangeCaptureUnavailable as unavailable:
            # Change capture's own closed reasons travel unchanged, so the server raises the very
            # failure a local read would have raised.
            reason = unavailable.reason
        except Exception as exc:  # noqa: BLE001 - every unexpected fault is one closed reply
            record_unexpected_exception_without_raising(
                exc, component=_COMPONENT, operation="workspace_call_failed"
            )
            reason = "internal_error"
        if outcome_for_reason(reason) != "unavailable":
            # A refusal or a fault is worth a record; an ordinary unavailability is not.
            record_public_error_without_raising(
                component=_COMPONENT, operation="workspace_call_" + call.operation, reason=reason
            )
        return workspace_reply(call.call_id, reason)

    # --- dispatch ---------------------------------------------------------------------------

    def _run(self, call: WorkspaceCall, handle: str | None) -> JsonValue:
        spec = operation_spec(call.operation)
        if spec is None:
            raise _Outcome("operation_unknown")
        if call.operation not in self._operations:
            raise _Outcome("operation_not_declared")
        try:
            arguments = spec.decode_arguments(call.arguments)
        except WorkspaceCodecError:
            raise _Outcome("arguments_invalid") from None
        context = _Call(
            handle if workspace_handle_valid(handle) else None,
            time.monotonic() + call.deadline_ms / 1_000,
        )
        value = self._table[spec.operation](arguments, context)
        try:
            return spec.encode_result(value)
        except WorkspaceCodecError as exc:
            if exc.reason == "result_too_large":
                raise _Outcome("result_too_large") from None
            raise

    # --- confinement ------------------------------------------------------------------------

    def _workspace(self, named: str, call: _Call) -> str:
        """The claimed root, when ``named`` is this connection's own workspace handle."""

        if call.handle is None or named != call.handle:
            raise _Outcome("workspace_not_claimed")
        return self._root

    def _location(self, value: str, call: _Call) -> str:
        """An absolute path as named, or a ``client:`` location resolved beneath the claimed root."""

        if value.startswith("/"):
            return value
        if call.handle is None:
            raise _Outcome("workspace_not_claimed")
        resolved = resolve_client_location(value, call.handle, self._root)
        if resolved is None:
            raise _Outcome("workspace_not_claimed")
        return resolved

    def _excluded(self, named: Sequence[str], call: _Call, *, outside: bool) -> tuple[str, ...]:
        """The server's exclusions resolved here, plus this client's own: never FinishUP's own
        directories, and for an outside read never the claimed workspace either."""

        resolved = tuple(self._location(value, call) for value in named)
        own = (self._root, *self._protected) if outside else self._protected
        return tuple(dict.fromkeys((*filter(_examinable, resolved), *own)))

    @staticmethod
    def _admitted(roots: Sequence[str]) -> None:
        if any(not admitted_input_root_valid(root) for root in roots):
            raise _Outcome("root_not_admitted")

    def _read_root(
        self, root: str, excluded: Sequence[str], call: _Call
    ) -> tuple[str, tuple[str, ...]]:
        """A reviewer read's root and exclusions: the claimed workspace, named by its handle, or
        an admitted outside root, beneath which neither the workspace nor FinishUP's own
        directories are ever entered."""

        if not root.startswith("/"):
            return self._location(root, call), self._excluded(excluded, call, outside=False)
        self._admitted((root,))
        if _folded_within(root, self._protected):
            raise _Outcome("root_not_admitted")
        return root, self._excluded(excluded, call, outside=True)

    def _opened_workspace(self, handle: str) -> LocalWorkspaceHandle:
        with self._opened_guard:
            opened = self._opened.get(handle)
            if opened is None:
                raise _Outcome("handle_unknown")
            self._opened.move_to_end(handle)
            return opened

    # --- git --------------------------------------------------------------------------------

    def _read_task_base(self, arguments: WorkspaceOnlyArguments, call: _Call) -> object:
        return self._capture.read_task_base(self._workspace(arguments.workspace, call))

    def _capture_change(self, arguments: CaptureArguments, call: _Call) -> object:
        return self._capture.capture(
            self._workspace(arguments.workspace, call),
            arguments.base,
            priority_paths=arguments.priority_paths,
            input_paths=arguments.input_paths,
            space_cut_paths=arguments.space_cut_paths,
        )

    def _capture_metadata(self, arguments: CaptureMetadataArguments, call: _Call) -> object:
        return self._capture.capture_metadata(
            self._workspace(arguments.workspace, call), arguments.base
        )

    def _probe_requested_paths(
        self, arguments: ProbeRequestedPathsArguments, call: _Call
    ) -> object:
        return self._capture.probe_requested_paths(
            self._workspace(arguments.workspace, call), arguments.values
        )

    def _count_change_lines(self, arguments: CountChangeLinesArguments, call: _Call) -> object:
        return self._capture.count_change_lines(
            self._workspace(arguments.workspace, call),
            arguments.base_commit,
            arguments.base_paths,
        )

    def _classify_references(
        self, arguments: ClassifyUndeclaredReferencesArguments, call: _Call
    ) -> object:
        return self._capture.classify_undeclared_references(
            self._workspace(arguments.workspace, call),
            arguments.deliverables,
            arguments.candidates,
            arguments.declared,
        )

    # --- reads ------------------------------------------------------------------------------

    def _read_outside_inputs(self, arguments: ReadOutsideInputsArguments, call: _Call) -> object:
        self._admitted(arguments.roots)
        return read_outside_inputs(
            arguments.roots,
            arguments.values,
            limit=arguments.limit,
            excluded=self._excluded(arguments.excluded, call, outside=True),
            space_cut=arguments.space_cut,
        )

    def _snapshot_outside_inputs(
        self, arguments: SnapshotOutsideInputsArguments, call: _Call
    ) -> object:
        self._admitted(arguments.roots)
        return snapshot_outside_inputs(
            arguments.roots,
            arguments.values,
            limit=arguments.limit,
            max_bytes=arguments.max_bytes,
            # The read's own budget, never past the call's deadline.
            seconds=min(arguments.budget_ms / 1_000, call.remaining()),
            excluded=self._excluded(arguments.excluded, call, outside=True),
        )

    def _read_declared_test(self, arguments: ReadDeclaredTestArguments, call: _Call) -> object:
        location = self._location(arguments.location, call)
        if posixpath.normpath(location) != location:
            raise _Outcome("arguments_invalid")
        return read_declared_test(
            location,
            excluded=self._excluded(arguments.excluded, call, outside=False),
            expired=call.expired,
        )

    def _read_text_beneath(self, arguments: ReadTextBeneathArguments, call: _Call) -> object:
        root, excluded = self._read_root(arguments.root, arguments.excluded, call)
        try:
            return read_text_beneath(
                root, arguments.relative, excluded=excluded, expired=call.expired
            )
        except ReadDeadline:
            raise _Outcome("read_deadline") from None

    def _list_beneath(self, arguments: ListBeneathArguments, call: _Call) -> object:
        root, excluded = self._read_root(arguments.root, arguments.excluded, call)
        try:
            return list_beneath(
                root,
                arguments.relative,
                excluded=excluded,
                expired=call.expired,
                inspect=arguments.inspect,
            )
        except ReadDeadline:
            raise _Outcome("read_deadline") from None

    def _lstat_candidates(self, arguments: LstatCandidatesArguments, call: _Call) -> object:
        """Metadata only. A candidate inside the claimed workspace or FinishUP's own directories,
        or not in normal form, is reported as not found: it is never an outside input."""

        facts: list[LstatFacts | None] = []
        fenced = (self._root, *self._protected)
        for path in arguments.paths:
            if call.expired():
                raise _Outcome("read_deadline")
            if posixpath.normpath(path) != path or _folded_within(path, fenced):
                facts.append(None)
                continue
            try:
                facts.append(LstatFacts.from_stat_result(os.lstat(path)))
            except (OSError, ValueError):
                facts.append(None)
        return tuple(facts)

    # --- observation ------------------------------------------------------------------------

    def _open_workspace(self, arguments: OpenWorkspaceArguments, call: _Call) -> object:
        root = self._workspace(arguments.workspace, call)
        try:
            opened = open_local_workspace(
                Path(root), admitted_home_project=arguments.admitted_home_project
            )
        except ValueError as exc:
            raise _Outcome(_unavailable(str(exc))) from None
        handle = new_remote_workspace_handle()
        with self._opened_guard:
            self._opened[handle] = opened
            while len(self._opened) > _MAX_OPEN_WORKSPACES:
                self._opened.popitem(last=False)
        return handle

    def _load_check_policy(self, arguments: WorkspaceOnlyArguments, call: _Call) -> object:
        root = self._workspace(arguments.workspace, call)
        try:
            policy, raw = load_observation_check_policy(Path(root))
        except ObservationCheckPolicyAbsent:
            raise _Outcome("policy_absent") from None
        except ObservationCheckPolicyAmbiguous:
            raise _Outcome("policy_ambiguous") from None
        except (OSError, ValueError):
            raise _Outcome("policy_invalid") from None
        return CheckPolicyRead(
            "current" if policy.source_path == CHECK_POLICY_PATH else "legacy", raw
        )

    def _subject_state_capture(
        self, arguments: SubjectStateCaptureArguments, _call: _Call
    ) -> object:
        return self._subject_state.capture(
            SubjectStateCaptureCommand(
                self._opened_workspace(arguments.handle), arguments.expected_format
            )
        )

    def _list_changed_paths(self, arguments: ListChangedPathsArguments, _call: _Call) -> object:
        try:
            return list_changed_relative_paths(
                self._opened_workspace(arguments.handle), max_files=arguments.max_files
            )
        except ValueError as exc:
            raise _Outcome(_unavailable(str(exc))) from None

    def _inspect_paths(self, arguments: InspectArguments, _call: _Call) -> object:
        return self._inspect.inspect(
            WorkspaceInspectCommand(
                workspace=self._opened_workspace(arguments.handle),
                relative_paths=arguments.relative_paths,
            )
        )

    def _run_approved_check(self, arguments: RunApprovedCheckArguments, _call: _Call) -> object:
        """Run one argv only when this repository's own policy approves exactly it."""

        workspace = self._opened_workspace(arguments.handle)
        try:
            policy, _raw = load_observation_check_policy(Path(self._root))
        except ObservationCheckPolicyAmbiguous:
            raise _Outcome("policy_ambiguous") from None
        except (OSError, ValueError):
            # No policy, or one that does not parse, approves nothing.
            raise _Outcome("check_not_approved") from None
        approval = arguments.approval
        if approval not in policy.checks:
            raise _Outcome("check_not_approved")
        captured: list[tuple[bytes, bool]] = []
        runner = ApprovedCheckRunner(
            {approval.approval_commitment: approval},
            sandbox=self._sandbox,
            output_sink=lambda output, redacted: captured.append((output, redacted)),
        )
        result = runner.run(
            ApprovedCheckCommand(
                workspace=workspace,
                approval=approval,
                subject_state_digest=arguments.subject_state_digest,
                expected_subject_state_digest=arguments.expected_subject_state_digest,
            )
        )
        if result.output_digest is None or not captured:
            return ApprovedCheckRun(result)
        output, redacted = captured[-1]
        return ApprovedCheckRun(result, output, redacted)


def _examinable(path: str) -> bool:
    """Whether this process can tell what a server-named exclusion is; one it cannot is dropped.

    The local readers read nothing at all when an exclusion exists but cannot be examined. A
    server on another machine lists its own directories among the exclusions; where such a path
    is on this machine but closed to this account (another user's home, say), a directory on the
    way is not searchable here, so nothing beneath it is readable here either. Dropping it narrows
    nothing and keeps the read; any other failure keeps the exclusion, failing closed.
    """

    try:
        os.stat(path)
    except PermissionError:
        return False
    except (OSError, ValueError):
        return True
    return True


def _unavailable(reason: str) -> str:
    """A local adapter's closed failure token as a reply reason, or ``workspace_unavailable``."""

    return reason if reason in WORKSPACE_UNAVAILABLE_REASONS else "workspace_unavailable"
