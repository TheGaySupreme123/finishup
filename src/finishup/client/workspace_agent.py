"""The client-side workspace agent: answers a remote server's workspace calls (ADR-051).

A FinishUP server on another machine never reads the agent's workspace itself. When it needs
workspace evidence (a check-time change, a task input, a reviewer's file read, an approved check)
it sends a bounded ``workspace_call`` over the client's own control connection, and this handler
answers it by running the very local adapters a local service runs, with every fence they keep:
Git hardening and ownership checks, ignore rules, credential-named and hidden-path refusals,
byte and time bounds, and the network-denying check sandbox.

These confinements hold on top of the adapters':

* **The claimed workspace only.** A handler is built for the one workspace its connection
  claimed. The server names that workspace by the connection's ``client:`` handle; the handler
  maps the handle to its own root and refuses any other handle (``workspace_not_claimed``).
* **Outside reads as this client's owner chose for that server.** A read root the server names
  must have the shape an owner may admit (``admitted_input_root_valid``). Beyond that, the
  outside-read mode of the server target the connection was made for decides
  (``client.server_folders``; ``finishup server folders mode``), a record this client keeps,
  reads on every call and never sends to the server. In ``local`` mode every read is answered as
  a local FinishUP service answers it: the server's own policy chose the roots, and only the
  adapters' fences and the exclusions below apply; a declared test is read as a local service
  reads the test its own agent declared. In ``listed`` mode what the read reaches must lie inside
  the claimed worktree or at or beneath a folder this computer's owner listed for that target
  (``finishup server folders add``). An existing file or folder beyond that is never read: a
  reviewer read or listing, or a declared test, is refused (``root_not_admitted``); a task-input
  read leaves just those inputs unread and reports their indices (``unlisted``), so the server
  says so in a fixed receipt line and keeps the rest of its read. A path that does not exist
  reads as nothing, as it does locally. A record that cannot be read, and an agent bound to
  none, are ``listed`` with no folder. In both modes outside reads never enter the claimed
  workspace through an outside root, or this client's own FinishUP directories at all, whatever
  the server lists as excluded.
* **Ignore rules on the agent.** A reviewer's file read inside the claimed workspace returns bytes
  only where Git answers that the file is not ignored, as the server's own broker asks first and
  requires, locally too: a server that skips that question never receives an ignored file's
  bytes, nor those of a file Git cannot answer for (a linked worktree, a submodule, no
  repository). In ``listed`` mode a declared test inside the workspace is held to the same rule;
  in ``local`` mode it is not, as a local service reads a declared test whether or not Git
  ignores it. A listing returns names only and is not asked about.

An approved check runs only when the repository's own ``.finishup/checks.toml`` (read here, by
the existing policy loader) approves exactly the argv the server asked for; anything else is
refused (``check_not_approved``). HOME decisions are this machine's: every adapter consults this
process's home directory, never the server's.

Results travel in the catalog's codecs (``finishup.ports.workspace_agent``). Every non-``ok``
reply carries one closed reason; logs carry closed tokens only, never a path, argument or output.
``answer`` is synchronous and blocking: callers run it in a worker thread.
"""

from __future__ import annotations

import hashlib
import hmac
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
from finishup.adapters.home_project_reads import home_private_path
from finishup.adapters.task_input_read import (
    ReadDeadline,
    declared_test_top,
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
from finishup.client.server_folders import OutsideReads, folder_covers, folder_holds_home
from finishup.config import paths as config_paths
from finishup.domain.privacy import admitted_input_root_valid, system_directory_path
from finishup.domain.repository_excerpt import credential_named_bytes
from finishup.observability.logging import (
    record_bounded_event_without_raising,
    record_public_error_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.ports.change_capture import ChangeCaptureUnavailable, RequestedPathProbe
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
    OutsideInputsRead,
    OutsideSnapshotsRead,
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
from finishup.ports.workspace_inspect import (
    WorkspaceInspectCommand,
    WorkspaceInspectLimitation,
    WorkspaceInspectResult,
    WorkspaceInspectStatus,
)
from finishup.protocol.canonical import JsonValue

__all__ = [
    "WorkspaceAgentHandler",
    "client_protected_directories",
    "workspace_reply",
]

_COMPONENT: Final = "client.workspace_agent"
# Opened workspaces (``open_workspace``) this handler keeps; the oldest is forgotten first, and a
# call naming a forgotten one is answered ``handle_unknown`` so the server opens it again
# (``workspace_routing`` reopens once). A keyed handler holds at most its two keyed handles.
_MAX_OPEN_WORKSPACES: Final = 8
# Domain of a keyed opened-workspace handle (``opened_handle_key``): the MAC over the open's
# admitted-HOME flag and this agent's own root, so any agent of this client for the same workspace
# recomputes it, and nothing else can.
_OPENED_HANDLE_DOMAIN: Final = b"yoetz/opened-workspace/v1\x00"
_OPENED_HANDLE_KEY_BYTES: Final = 32
# What an approved-check run keeps of its call's deadline: killing and reaping a check that
# reached its time, redacting and encoding its output, and the reply frame. A run never goes past
# the call's deadline less this, so its result, a timeout included, reaches the server in time.
_APPROVED_CHECK_REPLY_RESERVE_SECONDS: Final = 15.0
# The least run time an approval may ask for (``ApprovedCheckApproval``).
_MIN_APPROVED_CHECK_SECONDS: Final = 0.1


class _Outcome(Exception):
    """Internal: the call ends with this closed non-``ok`` reply reason."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in WORKSPACE_REPLY_REASONS:
            raise ValueError("workspace_reply_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class _NothingThere(Exception):
    """Internal: a listed-mode reviewer read reaches a path that does not exist; it reads as
    nothing, as a local read does, rather than as a refusal."""


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
    bundle, configuration, cache, state, logs and endpoints. Then the everyday installation's own
    platform directories under both application names, which hold the vault, the ledgers and
    every target root: a selected or isolated root resolves the first group elsewhere, and must
    not make those readable. A directory that cannot be resolved is left out: it cannot be named,
    so there is nothing under that name to protect.
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
    try:
        ambient = config_paths.ambient_installation_dirs()
    except Exception:  # noqa: BLE001 - an unresolvable directory has no name to protect
        ambient = ()
    found.extend(
        os.path.normpath(os.fspath(directory)) for directory in ambient if directory.is_absolute()
    )
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
        "_check_policy_trust",
        "_declaration",
        "_inspect",
        "_opened",
        "_opened_guard",
        "_opened_key",
        "_operations",
        "_outside_reads",
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
        opened_handle_key: bytes | None = None,
        check_policy_trust: Callable[[str], bool] | None = None,
        outside_reads: Callable[[], OutsideReads] | None = None,
    ) -> None:
        """``workspace`` is the locator the connection's claim was computed from; never the
        filesystem root, which no claim names (``workspace_locator_path_invalid``).

        ``protected`` defaults to ``client_protected_directories()``; ``operations`` to the whole
        catalog. ``check_sandbox`` replaces the platform's network-denying sandbox only where a
        caller supplies an equally enforcing one.

        ``opened_handle_key`` (32 bytes, a client secret the server never sees) makes the handle
        ``open_workspace`` answers a keyed digest of this root instead of a random one, so that
        when several of this client's connections serve the same worktree (a CLI command, the MCP
        bridge, a background agent, a reconnect), a later call naming the handle may be answered
        by any of them: an agent that did not open it recomputes it for its own root and opens it
        again, and the bounded table can never forget a handle still in use. Without a key, a
        handle is known only to the agent that opened it.

        ``check_policy_trust`` answers whether this client's owner trusted a check policy's raw
        digest; by default this process's own observation store answers
        (``client.observation_outbox.check_policy_trusted``).

        ``outside_reads`` answers, on each call, what this client's owner lets the server read
        outside the workspace: the reader of the record of the target the connection's claim was
        made for (``client.server_folders.outside_reads_reader`` given that target's root or its
        claim salt). Without one the handler is in ``listed`` mode with no folder: it never
        guesses the target from this process's selection, which may name another server, nor
        takes the mode of the target in use. An answer that fails is ``listed`` with no folder
        too.
        """

        if type(workspace) is not WorkspaceLocator:
            raise TypeError("workspace_locator_invalid")
        if posixpath.normpath(workspace.path) != workspace.path or workspace.path == "/":
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
        if opened_handle_key is not None and (
            type(opened_handle_key) is not bytes
            or len(opened_handle_key) != _OPENED_HANDLE_KEY_BYTES
        ):
            raise ValueError("opened_handle_key_invalid")
        self._opened_key = opened_handle_key
        # Whether this client's owner trusted a check policy's raw digest (ADR-051 decision 12);
        # None reads this process's own observation store, where 'observe checks trust' records it.
        self._check_policy_trust = check_policy_trust
        # What the owner lets this server read outside the workspace (ADR-051 decision 5): the
        # mode and folders 'server folders' records for the target its caller bound here; 'listed'
        # with no folder when the caller bound no record.
        self._outside_reads = _listed_nothing if outside_reads is None else outside_reads
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

    def _outside(self) -> OutsideReads:
        """What this client's owner lets the server read outside the workspace, read now.

        ``local`` as answered; ``listed`` with only the folders an owner could list. Anything
        else, and an answer that fails, is ``listed`` with no folder (fail closed).
        """

        try:
            found = self._outside_reads()
        except Exception:  # noqa: BLE001 - an unreadable record admits nothing (fail closed)
            return _LISTED_NOTHING
        if type(found) is not OutsideReads:
            return _LISTED_NOTHING
        if found.mode == "local":
            return found
        if found.mode != "listed":
            return _LISTED_NOTHING
        folders = tuple(
            folder
            for folder in found.folders
            if type(folder) is str
            and admitted_input_root_valid(folder)
            and not folder_holds_home(folder)
        )
        return OutsideReads("listed", folders, found.source)

    def _inside_claimed(self, path: str) -> bool:
        return path == self._root or path.startswith(self._root.rstrip("/") + "/")

    def _input_scope(
        self, roots: Sequence[str], values: Sequence[str]
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[int, ...]]:
        """The roots a task-input read walks, the values it reads, and the indices it left unread.

        Each named root must have the shape an owner may admit, or the whole call is
        ``root_not_admitted``. In ``local`` mode every named root is walked for every value, as a
        local service walks the roots its own policy admitted. In ``listed`` mode a value the task
        names at or beneath a named root (a path the read could open, as ``read_outside_inputs``
        locates it) is read only when it lies inside the claimed worktree, which the read never
        enters, or at or beneath a folder the owner listed; any other is left unread, and its
        index is reported (``unlisted``) when it names something that exists
        (``_exists_visibly``), so the server can say so and keep the rest of what it asked for.
        A value that names nothing is not reported: a local read would find nothing there
        either. A named root beneath which the task names nothing is never opened and is left
        out; one that holds a listed folder is walked only to the values beneath that folder, so
        the record narrows the server's roots and never widens them.
        """

        if any(not admitted_input_root_valid(root) for root in roots):
            raise _Outcome("root_not_admitted")
        outside = self._outside()
        if outside.mode == "local":
            return tuple(roots), tuple(values), ()
        folders = outside.folders
        kept: list[str] = []
        unlisted: list[int] = []
        for index, value in enumerate(values):
            if not value.startswith("/") or "\x00" in value:
                kept.append(value)  # never located beneath a root, so never read
                continue
            path = posixpath.normpath(value)
            if (
                not any(folder_covers(path, (root,)) for root in roots)
                or self._inside_claimed(path)
                or folder_covers(path, folders)
            ):
                kept.append(value)
            elif self._exists_visibly(path):
                unlisted.append(index)
        walked = tuple(
            root
            for root in roots
            if self._inside_claimed(root)
            or folder_covers(root, folders)
            or any(folder_covers(folder, (root,)) for folder in folders)
        )
        return walked, tuple(kept), tuple(unlisted)

    def _exists_visibly(self, path: str) -> bool:
        """Whether normalized absolute ``path`` exists and is one a local read could look at.

        Listed mode refuses or skips only what exists (ADR-051 decision 5): a path the task
        mentions that does not exist reads as nothing, as it does locally. The answer is given
        only for a path the local outside-input candidate rule would look at (no hidden
        component, not credential-named, in no system directory) outside FinishUP's own
        directories, so the server learns no more of this machine than ``lstat_candidates``
        already tells it.
        """

        if _folded_within(path, self._protected) or not _outside_candidate(path):
            return False
        try:
            os.lstat(path)
        except (OSError, ValueError):
            return False
        return True

    def _not_ignored(self, relative: str) -> bool:
        """Whether Git answers that the claimed-workspace-relative path ``relative`` is not ignored.

        The rule the server's reviewer broker asks the agent first (``probe_requested_paths``,
        with paths relative to the claimed root) and refuses on any answer but Git's own "not
        ignored" (``ignored is not False``), applied here too, so a workspace file's bytes reach
        only a server that could have read them honestly. Where Git cannot answer for the path
        (no repository, a linked worktree whose ``.git`` file the change capture refuses, a path
        inside a submodule, a home-private path, Git unavailable) the answer is no, exactly as the
        broker, local or remote, refuses such a read itself.
        """

        try:
            found = self._capture.probe_requested_paths(self._root, (relative,))
        except (ChangeCaptureUnavailable, OSError, ValueError):
            return False
        return (
            len(found) == 1
            and type(found[0]) is RequestedPathProbe
            and found[0].location == "inside"
            and found[0].ignored is False
        )

    def _claimed_relative(self, spellings: Sequence[str]) -> str | None:
        """The path strictly beneath the claimed root that one of ``spellings`` names, relative
        to it; ``None`` when none lies beneath it. Exact: the claimed root is the resolved
        locator every client surface sends, and a differently cased spelling is not beneath it."""

        prefix = self._root.rstrip("/") + "/"
        for spelling in spellings:
            if spelling.startswith(prefix) and len(spelling) > len(prefix):
                return spelling[len(prefix) :]
        return None

    def _read_root(
        self, root: str, relative: str, excluded: Sequence[str], call: _Call
    ) -> tuple[str, tuple[str, ...]]:
        """A reviewer read's root and exclusions: the claimed workspace, named by its handle, or
        an outside root beneath which neither the workspace nor FinishUP's own directories are
        ever entered.

        An outside root must have the shape an owner may admit. In ``local`` mode that is all, as
        for a local service: a root in FinishUP's own directories is not refused but excluded,
        so the read answers nothing there, as a local service's read, which excludes them, does.
        In ``listed`` mode a root in FinishUP's own directories is ``root_not_admitted``, and the
        root must also lie inside the claimed worktree or at or beneath a listed folder, or the
        path the read reaches (``root`` joined with ``relative``, normalized as the read
        normalizes it) must lie at or beneath a listed folder: a folder narrower than the
        server's root admits what lies beneath it, and a listing of the root above it stays
        ``root_not_admitted``. A path it reaches that does not exist is not refused but read as
        nothing (``_NothingThere``), as a local read finds nothing there.
        """

        if not root.startswith("/"):
            return self._location(root, call), self._excluded(excluded, call, outside=False)
        if not admitted_input_root_valid(root):
            raise _Outcome("root_not_admitted")
        outside = self._outside()
        if outside.mode != "local":
            if _folded_within(root, self._protected):
                raise _Outcome("root_not_admitted")
            folders = outside.folders
            reached = posixpath.normpath(posixpath.join(root, relative)) if relative else root
            if not (
                self._inside_claimed(root)
                or folder_covers(root, folders)
                or folder_covers(reached, folders)
            ):
                if self._exists_visibly(reached):
                    raise _Outcome("root_not_admitted")
                raise _NothingThere  # names nothing: read as nothing, as it is locally
        return root, self._excluded(excluded, call, outside=True)

    def _opened_workspace(self, handle: str) -> LocalWorkspaceHandle:
        with self._opened_guard:
            opened = self._opened.get(handle)
            if opened is not None:
                self._opened.move_to_end(handle)
                return opened
        # Opened by another agent of this client for the same workspace (another connection):
        # a keyed handle is recomputed for this root and the workspace opened here again.
        for admitted_home_project in (False, True):
            expected = self._keyed_opened_handle(admitted_home_project)
            if expected is not None and hmac.compare_digest(expected, handle):
                return self._remember_opened(
                    handle, self._open_local(admitted_home_project=admitted_home_project)
                )
        raise _Outcome("handle_unknown")

    def _keyed_opened_handle(self, admitted_home_project: bool) -> str | None:
        key = self._opened_key
        if key is None:
            return None
        message = (
            _OPENED_HANDLE_DOMAIN
            + (b"1" if admitted_home_project else b"0")
            + b"\x00"
            + os.fsencode(self._root)
        )
        return "rws_" + hmac.new(key, message, hashlib.sha256).hexdigest()[:32]

    def _open_local(self, *, admitted_home_project: bool) -> LocalWorkspaceHandle:
        try:
            return open_local_workspace(
                Path(self._root), admitted_home_project=admitted_home_project
            )
        except ValueError as exc:
            raise _Outcome(_unavailable(str(exc))) from None

    def _remember_opened(self, handle: str, opened: LocalWorkspaceHandle) -> LocalWorkspaceHandle:
        with self._opened_guard:
            self._opened[handle] = opened
            self._opened.move_to_end(handle)
            while len(self._opened) > _MAX_OPEN_WORKSPACES:
                self._opened.popitem(last=False)
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
        """Task inputs beneath the named roots that are admitted here (``_input_scope``), and the
        indices of the values left unread because the owner did not list them."""

        roots, values, unlisted = self._input_scope(arguments.roots, arguments.values)
        inputs = read_outside_inputs(
            roots,
            values,
            limit=arguments.limit,
            excluded=self._excluded(arguments.excluded, call, outside=True),
            space_cut=arguments.space_cut,
        )
        return OutsideInputsRead(inputs, unlisted)

    def _snapshot_outside_inputs(
        self, arguments: SnapshotOutsideInputsArguments, call: _Call
    ) -> object:
        roots, values, unlisted = self._input_scope(arguments.roots, arguments.values)
        reads = snapshot_outside_inputs(
            roots,
            values,
            limit=arguments.limit,
            max_bytes=arguments.max_bytes,
            # The read's own budget, never past the call's deadline.
            seconds=min(arguments.budget_ms / 1_000, call.remaining()),
            excluded=self._excluded(arguments.excluded, call, outside=True),
        )
        return OutsideSnapshotsRead(reads, unlisted)

    def _read_declared_test(self, arguments: ReadDeclaredTestArguments, call: _Call) -> object:
        """One declared test file, read as a local service reads it in ``local`` mode, or within
        what the owner listed in ``listed`` mode.

        A local service reads the test file its own agent declared, inside the workspace or
        outside it, whether or not Git ignores it (#1220). Here the server names the location and
        this agent cannot tell whether its agent declared it, so the server target's outside-read
        mode decides (ADR-051 decision 5). In ``local`` mode the location is read exactly as a
        local service reads it: the local read with all its fences, FinishUP's own directories
        excluded, and no other rule. In ``listed`` mode, strictly beneath the claimed root (named
        by its handle or its absolute path) Git must answer that the file is not ignored, and
        elsewhere it must lie at or beneath a folder this client's owner listed for the server;
        an existing file that meets neither is ``root_not_admitted``, never read on the server's
        word, so the server can say what was not offered (``_exists_visibly``), and one that does
        not exist reads as nothing, as it does locally. In ``listed`` mode both comparisons are
        made on the spelling the local read walks too: a first component that is a link root
        owns (``/tmp`` on macOS) counts as its target. They are exact otherwise: a differently
        cased spelling is refused, never let in. One let in outside the workspace is an outside
        read, so it never enters the claimed workspace under another spelling (another case on a
        case-insensitive volume, a bind mount), by case-folded path or by device and inode, where
        Git's ignore rule would not be asked.
        """

        location = self._location(arguments.location, call)
        if posixpath.normpath(location) != location:
            raise _Outcome("arguments_invalid")
        if call.handle is None:
            raise _Outcome("workspace_not_claimed")
        outside = self._outside()
        if outside.mode == "local":
            return read_declared_test(
                location,
                excluded=self._excluded(arguments.excluded, call, outside=False),
                expired=call.expired,
            )
        walked = declared_test_top(location)
        spellings = (location,) if walked is None else (location, f"{walked[0]}/{walked[1]}")
        relative = self._claimed_relative(spellings)
        if relative is not None:
            admitted = self._not_ignored(relative)
        else:
            admitted = any(folder_covers(spelling, outside.folders) for spelling in spellings)
        if not admitted:
            if any(self._exists_visibly(spelling) for spelling in spellings):
                raise _Outcome("root_not_admitted")
            return None  # names nothing: read as a test that could not be read, as locally
        return read_declared_test(
            location,
            # Let in outside the workspace through a folder, it is an outside read: the claimed
            # workspace is excluded by identity and case-folded spelling, so no alias of it
            # reaches an ignored file.
            excluded=self._excluded(arguments.excluded, call, outside=relative is None),
            expired=call.expired,
        )

    def _read_text_beneath(self, arguments: ReadTextBeneathArguments, call: _Call) -> object:
        try:
            root, excluded = self._read_root(
                arguments.root, arguments.relative, arguments.excluded, call
            )
        except _NothingThere:
            return None
        if not arguments.root.startswith("/"):
            # A workspace file reads only where Git answers that it is not ignored, as the
            # broker's own rule has it: an ignored file, and one Git cannot answer for, read as
            # nothing.
            relative = self._claimed_relative(
                (posixpath.normpath(posixpath.join(root, arguments.relative)),)
            )
            if relative is None or not self._not_ignored(relative):
                return None
        try:
            return read_text_beneath(
                root, arguments.relative, excluded=excluded, expired=call.expired
            )
        except ReadDeadline:
            raise _Outcome("read_deadline") from None

    def _list_beneath(self, arguments: ListBeneathArguments, call: _Call) -> object:
        try:
            root, excluded = self._read_root(
                arguments.root, arguments.relative, arguments.excluded, call
            )
        except _NothingThere:
            return None
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
        not in normal form, or one the local outside-input rule would never look at (hidden,
        credential-named, a system directory, beneath no path an owner may admit) is reported
        as not found: it is never an outside input, and the server learns nothing of it."""

        facts: list[LstatFacts | None] = []
        fenced = (self._root, *self._protected)
        for path in arguments.paths:
            if call.expired():
                raise _Outcome("read_deadline")
            if (
                posixpath.normpath(path) != path
                or _folded_within(path, fenced)
                or not _outside_candidate(path)
            ):
                facts.append(None)
                continue
            try:
                facts.append(LstatFacts.from_stat_result(os.lstat(path)))
            except (OSError, ValueError):
                facts.append(None)
        return tuple(facts)

    # --- observation ------------------------------------------------------------------------

    def _open_workspace(self, arguments: OpenWorkspaceArguments, call: _Call) -> object:
        self._workspace(arguments.workspace, call)
        opened = self._open_local(admitted_home_project=arguments.admitted_home_project)
        handle = self._keyed_opened_handle(arguments.admitted_home_project)
        if handle is None:
            handle = new_remote_workspace_handle()
        self._remember_opened(handle, opened)
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
        """Excerpts of this workspace's own changed paths only, never what the server picks.

        A local service only ever inspects ``list_changed_relative_paths``; here the server
        names the paths, so the agent takes that listing itself and inspects only paths in it,
        which leaves out Git-ignored files, unchanged files and everything under ``.git``. A
        credential-named path, or one in the home directory's private state when the workspace
        is the home directory, is left out too. A path left out is reported
        ``path_out_of_scope`` (``partial``, or ``rejected`` when none is left); its bytes are
        never read.
        """

        workspace = self._opened_workspace(arguments.handle)
        try:
            changed = frozenset(list_changed_relative_paths(workspace))
        except ValueError as exc:
            raise _Outcome(_unavailable(str(exc))) from None
        root = Path(self._root)
        allowed = tuple(
            path
            for path in arguments.relative_paths
            if path in changed
            and not credential_named_bytes(os.fsencode(path))
            and not home_private_path(root, os.fsencode(path))
        )
        if not allowed:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.PATH_OUT_OF_SCOPE,),
                None,
            )
        result = self._inspect.inspect(
            WorkspaceInspectCommand(workspace=workspace, relative_paths=allowed)
        )
        if len(allowed) == len(arguments.relative_paths):
            return result
        limitations = tuple(
            sorted(
                {*result.limitations, WorkspaceInspectLimitation.PATH_OUT_OF_SCOPE},
                key=lambda item: item.value.encode(),
            )
        )
        status = (
            WorkspaceInspectStatus.PARTIAL
            if result.status is WorkspaceInspectStatus.INSPECTED
            else result.status
        )
        return WorkspaceInspectResult(
            status, result.artifacts, limitations, result.selection_digest
        )

    def _policy_trusted(self, policy_digest: str) -> bool:
        if self._check_policy_trust is not None:
            return self._check_policy_trust(policy_digest)
        from finishup.client.observation_outbox import check_policy_trusted

        return check_policy_trusted(self._root, policy_digest)

    def _run_approved_check(self, arguments: RunApprovedCheckArguments, call: _Call) -> object:
        """Run one argv only when the policy the owner trusted on this client approves exactly it.

        The run ends within the call's deadline, less the time its result needs to reach the
        server: an approval longer than that (the transport caps a call at 300 s) is cut there
        and records ``timeout``, never a lost call. With too little time left to run at all, the
        call is answered ``deadline_exceeded`` and nothing runs.
        """

        workspace = self._opened_workspace(arguments.handle)
        try:
            policy, _raw = load_observation_check_policy(Path(self._root))
        except ObservationCheckPolicyAmbiguous:
            raise _Outcome("policy_ambiguous") from None
        except (OSError, ValueError):
            # No policy, or one that does not parse, approves nothing.
            raise _Outcome("check_not_approved") from None
        approval = arguments.approval
        # The owner's trust of this exact policy lives on this client (ADR-051 decision 12), never
        # on the server: an untrusted or edited policy approves nothing, whatever the server asks.
        if approval not in policy.checks or not self._policy_trusted(policy.raw_digest):
            raise _Outcome("check_not_approved")
        budget = call.remaining() - _APPROVED_CHECK_REPLY_RESERVE_SECONDS
        if budget < _MIN_APPROVED_CHECK_SECONDS:
            raise _Outcome("deadline_exceeded")
        capped = budget < approval.timeout_seconds
        if capped:
            record_bounded_event_without_raising(
                component=_COMPONENT,
                operation="workspace_call_run_approved_check",
                reason="run_capped_at_call_deadline",
            )
        captured: list[tuple[bytes, bool]] = []
        runner = ApprovedCheckRunner(
            {approval.approval_commitment: approval},
            sandbox=self._sandbox,
            output_sink=lambda output, redacted: captured.append((output, redacted)),
            run_seconds_cap=budget if capped else None,
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


# What a handler bound to no record, or whose record cannot be read, lets a server read outside
# the workspace: nothing.
_LISTED_NOTHING: Final = OutsideReads("listed", (), "unreadable")


def _listed_nothing() -> OutsideReads:
    """The outside reads of a handler bound to no record: ``listed`` with no folder."""

    return _LISTED_NOTHING


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


def _outside_candidate(path: str) -> bool:
    """Whether a normalized absolute ``path`` passes the local outside-input candidate rule.

    The rule a local service applies before it ever looks at a candidate's metadata
    (``outside_input_candidates``): no hidden component, not credential-named, in no system
    directory, and at or beneath a path an owner may admit as an input root. An honest server only
    asks about such candidates, so this changes no answer it needs; it keeps a server from
    learning whether anything else on this machine exists.
    """

    parts = path.split("/")[1:]
    if not parts or not parts[0] or any(part.startswith(".") for part in parts):
        return False
    if (
        credential_named_bytes(os.fsencode(path))
        or system_directory_path(path)
        or system_directory_path(path.casefold())
    ):
        return False
    ancestors = ("/" + "/".join(parts[:depth]) for depth in range(1, len(parts) + 1))
    return any(admitted_input_root_valid(ancestor) for ancestor in ancestors)


def _unavailable(reason: str) -> str:
    """A local adapter's closed failure token as a reply reason, or ``workspace_unavailable``."""

    return reason if reason in WORKSPACE_UNAVAILABLE_REASONS else "workspace_unavailable"
