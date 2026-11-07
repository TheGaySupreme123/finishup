"""The workspace-agent operation catalog: the one source of truth for workspace callbacks.

When a FinishUP client works with a server on another machine, the server never reads that
machine's disk itself (ADR-051). It sends a bounded ``workspace_call`` over the client's own
control connection and a client-side workspace agent answers it with a ``workspace_reply``,
running the same local adapters, with all their fences, that a local service runs. This module
defines every such operation: its closed name, its family, a strict codec for its arguments and
for its result over canonical JSON, and the byte bound each side keeps so every frame stays under
the control channel's 6 MiB frame ceiling.

Rules every codec here follows:

* A codec round-trips exactly: ``decode(encode(value)) == value``, and the encoded JSON is the
  only accepted spelling of that value (keys are exact sets, a ``bytes`` value is canonical
  standard base64 with padding, a set is a byte-sorted list).
* A ``bytes`` value travels as a base64 string; text a value already holds as validated UTF-8
  (a rendered change, a task input's text) keeps the existing codec's string form, so a capture
  carried by the agent is byte-identical to the object the service stores.
* No codec reads a file, a clock or the environment. Validation failures raise
  ``WorkspaceCodecError`` with a closed reason and never echo the offending value.
* Workspace evidence a reply carries is the client's attestation, not a service read; the
  server labels it so (``client_attested``). Nothing here decides that labelling.

This module imports ports, domain and protocol modules only, so a client process can load it
without the service.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Final, Literal, cast

from finishup.domain.values import SubjectStateRef
from finishup.ports.approved_checks import (
    MAX_APPROVED_CHECK_OUTPUT_BYTES,
    ApprovedCheckApproval,
    ApprovedCheckOutcome,
    ApprovedCheckResult,
    ApprovedCheckStatus,
    approved_check_result_digest,
)
from finishup.ports.change_capture import (
    CHANGE_CAPTURE_UNAVAILABLE_REASONS,
    MAX_SNAPSHOT_CANDIDATES,
    MAX_SNAPSHOT_FILE_BYTES,
    MAX_TASK_INPUT_FILES,
    ChangeBaseKind,
    ChangeLineCount,
    ChangeLineCounts,
    ChangeMetadataEntry,
    CheckChangeCapture,
    CheckChangeMetadata,
    OutsideSnapshotRead,
    RequestedPathProbe,
    TaskChangeBase,
    TaskInputFile,
    decode_check_change,
    decode_task_change_base,
    encode_check_change,
    encode_task_change_base,
    task_input_file_from_wire,
    task_input_file_wire,
)
from finishup.ports.subject_state import (
    MAX_SUBJECT_STATE_FILES,
    SubjectStateBound,
    SubjectStateCaptureResult,
    SubjectStateFormat,
    SubjectStateLimitation,
    SubjectStateLimitDetail,
    SubjectStateStatus,
)
from finishup.ports.workspace_inspect import (
    MAX_INSPECT_EXCERPT_BYTES,
    MAX_INSPECT_FILES,
    MAX_INSPECT_PATH_BYTES,
    InspectedArtifact,
    WorkspaceInspectLimitation,
    WorkspaceInspectResult,
    WorkspaceInspectStatus,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_encode,
    parse_canonical_integer_string,
    strict_json_parse,
)

__all__ = [
    "MAX_WORKSPACE_DEADLINE_MS",
    "MAX_WORKSPACE_FRAME_BYTES",
    "MAX_WORKSPACE_PAYLOAD_BYTES",
    "WORKSPACE_AGENT_SCHEMA_VERSION",
    "WORKSPACE_FAILURE_REASONS",
    "WORKSPACE_HANDLE_DOMAIN",
    "WORKSPACE_HANDLE_PREFIX",
    "WORKSPACE_OPERATION_CATALOG",
    "WORKSPACE_OPERATION_FAMILIES",
    "WORKSPACE_OPERATION_NAMES",
    "WORKSPACE_REFUSAL_REASONS",
    "WORKSPACE_REPLY_OUTCOMES",
    "WORKSPACE_REPLY_REASONS",
    "WORKSPACE_UNAVAILABLE_REASONS",
    "WORKSPACE_AGENT_UNAVAILABLE_REASONS",
    "ApprovedCheckRun",
    "CaptureArguments",
    "CaptureMetadataArguments",
    "CheckPolicyRead",
    "ClassifyUndeclaredReferencesArguments",
    "CountChangeLinesArguments",
    "InspectArguments",
    "ListBeneathArguments",
    "ListChangedPathsArguments",
    "LstatCandidatesArguments",
    "LstatFacts",
    "OpenWorkspaceArguments",
    "OutsideInputsRead",
    "OutsideSnapshotsRead",
    "ProbeRequestedPathsArguments",
    "ReadDeclaredTestArguments",
    "ReadOutsideInputsArguments",
    "ReadTextBeneathArguments",
    "RunApprovedCheckArguments",
    "SnapshotOutsideInputsArguments",
    "SubjectStateCaptureArguments",
    "WorkspaceAgentUnavailable",
    "WorkspaceCodecError",
    "WorkspaceOnlyArguments",
    "WorkspaceOperation",
    "WorkspaceOperationFamily",
    "WorkspaceOperationSpec",
    "WorkspaceReplyOutcome",
    "change_capture_unavailable_reason",
    "client_location_valid",
    "new_remote_workspace_handle",
    "operation_spec",
    "outcome_for_reason",
    "remote_workspace_handle_valid",
    "resolve_client_location",
    "workspace_handle_for_claim",
    "workspace_handle_valid",
]

WORKSPACE_AGENT_SCHEMA_VERSION: Final = "1.0.0"
# Mirrors ``finishup.service.control_protocol.MAX_CONTROL_FRAME_BYTES`` (a port cannot import the
# service package); a test holds the two equal. Workspace frames may use the whole frame.
MAX_WORKSPACE_FRAME_BYTES: Final = 6_291_456
# Room the ``workspace_call``/``workspace_reply`` envelope keeps around its arguments or result,
# so a payload within this bound always fits one frame.
_ENVELOPE_HEADROOM_BYTES: Final = 65_536
MAX_WORKSPACE_PAYLOAD_BYTES: Final = MAX_WORKSPACE_FRAME_BYTES - _ENVELOPE_HEADROOM_BYTES
# The control channel's call deadline ceiling (``deadline_ms`` on a control call).
MAX_WORKSPACE_DEADLINE_MS: Final = 300_000

_KIB: Final = 1024
_MIB: Final = 1024 * 1024
# Bounds the adapters enforce, mirrored as reviewed literals (the adapters are service modules a
# port does not import); a test holds each equal to its source.
_MAX_REQUESTED_PATH_PROBES: Final = 64  # git_change_capture._MAX_REQUESTED_PATH_PROBES
_MAX_REFERENCE_DELIVERABLES: Final = 16  # git_change_capture._MAX_REFERENCE_DELIVERABLES
_MAX_REFERENCE_CANDIDATES: Final = 1_024  # git_change_capture._MAX_REFERENCE_CANDIDATES
_MAX_REFERENCE_PAIRS: Final = 64  # git_change_capture._MAX_REFERENCE_PAIRS (per kind)
_MAX_TASK_INPUT_READ_BYTES: Final = 1024 * 1024  # task_input_read.MAX_TASK_INPUT_READ_BYTES
_MAX_POLICY_BYTES: Final = 256 * 1024  # observation_check_policy._MAX_POLICY_BYTES
# Catalog-owned bounds for values no adapter bounds by count.
_MAX_PATH_BYTES: Final = 8_192
_MAX_PATH_LIST: Final = 4_096
_MAX_LIST_INSPECT: Final = 1_024
_MAX_LSTAT_CANDIDATES: Final = 1_024
_MAX_LISTED_NAME_BYTES: Final = 1_024

WORKSPACE_HANDLE_PREFIX: Final = "client:"
# Domain of the handle a server derives from a claim commitment and its worktree digest.
WORKSPACE_HANDLE_DOMAIN: Final = b"yoetz/workspace-handle/v1\x00"
_WORKSPACE_HANDLE: Final = re.compile(r"^client:[0-9a-f]{16}$", re.ASCII)
_REMOTE_WORKSPACE_HANDLE: Final = re.compile(r"^rws_[0-9a-f]{32}$", re.ASCII)
_COMMITMENT: Final = re.compile(r"^hmac-sha256:[0-9a-f]{64}$", re.ASCII)
_HEX_COMMIT: Final = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.ASCII)
_SHA256: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_TIMEOUT_TEXT: Final = re.compile(r"^(?:0|[1-9][0-9]{0,2})\.[0-9]{1,17}$", re.ASCII)


class WorkspaceCodecError(ValueError):
    """A workspace-agent value failed its codec; the reason is closed and names no value."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _CODEC_REASONS:
            raise ValueError("workspace_codec_reason_invalid")
        self.reason = reason
        super().__init__(reason)


_CODEC_REASONS: Final = frozenset(
    {"arguments_invalid", "arguments_too_large", "result_invalid", "result_too_large"}
)


# --- workspace handles --------------------------------------------------------------------


def workspace_handle_valid(value: object) -> bool:
    """Whether ``value`` is a claim-bound connection's workspace handle (``client:<16 hex>``)."""

    return type(value) is str and _WORKSPACE_HANDLE.fullmatch(value) is not None


def workspace_handle_for_claim(commitment: str, worktree: str) -> str:
    """The workspace handle the server derives for one claimed worktree (ADR-051).

    ``commitment`` is the server's own commitment to the claim, shared by every linked worktree of
    one repository; ``worktree`` is the claim's worktree digest, which tells those worktrees
    apart. The handle is the first 16 hex of a domain-separated SHA-256 over both, so each
    worktree has its own handle, and with it its own task workspace and its own agent route,
    while the repository commitment (privacy authority and consent scope) stays the claim's.
    """

    if type(commitment) is not str or _COMMITMENT.fullmatch(commitment) is None:
        raise ValueError("workspace_commitment_invalid")
    if type(worktree) is not str or _SHA256.fullmatch(worktree) is None:
        raise ValueError("workspace_worktree_invalid")
    digest = hashlib.sha256(
        WORKSPACE_HANDLE_DOMAIN + commitment.encode("ascii") + b"\x00" + worktree.encode("ascii")
    ).hexdigest()
    return WORKSPACE_HANDLE_PREFIX + digest[:16]


def remote_workspace_handle_valid(value: object) -> bool:
    """Whether ``value`` is an agent's opaque opened-workspace handle (``rws_<32 hex>``)."""

    return type(value) is str and _REMOTE_WORKSPACE_HANDLE.fullmatch(value) is not None


def new_remote_workspace_handle() -> str:
    """A fresh, unguessable opened-workspace handle for an agent's own handle table."""

    return "rws_" + secrets.token_hex(16)


def client_location_valid(value: object, *, relative: bool = True) -> bool:
    """Whether ``value`` names a place on the client's machine a read may name.

    A location is an absolute path (one the task's own content or the owner's policy named), or
    the claimed workspace's handle standing for its root, optionally followed, when ``relative``,
    by ``/`` and a root-relative path with no empty, ``.`` or ``..`` component. The server never
    learns the root's path: the agent resolves the handle against its own claimed root
    (``resolve_client_location``).
    """

    try:
        _client_location(value, relative=relative)
    except _Invalid:
        return False
    return True


def resolve_client_location(value: str, handle: str, root: str) -> str | None:
    """The agent's own path for a client location, or None when it names another workspace.

    An absolute path stays as it is (the agent's own confinement then decides whether it may be
    read); the agent's own ``handle`` is its claimed ``root``; ``handle/relative`` is joined
    beneath that root. A handle the agent did not claim resolves to None (``workspace_not_claimed``).
    """

    if not client_location_valid(value) or not workspace_handle_valid(handle):
        raise ValueError("client_location_invalid")
    if type(root) is not str or not root.startswith("/"):
        raise ValueError("client_root_invalid")
    if value.startswith("/"):
        return value
    named, _separator, rest = value.partition("/")
    if named != handle:
        return None
    return root if not rest else root.rstrip("/") + "/" + rest


# --- typed unavailability -------------------------------------------------------------------

# Why the server could not get a workspace answer from the client's agent. Closed tokens only:
# none names a path, a host or anything the agent sent.
WORKSPACE_AGENT_UNAVAILABLE_REASONS: Final[frozenset[str]] = frozenset(
    {
        # No agent connection for the workspace arrived within the bounded wait.
        "no_agent",
        # The agent's connection closed while the call was pending.
        "agent_disconnected",
        # No reply within the call's deadline.
        "deadline_exceeded",
        # The agent's connection had no free call slot within the deadline.
        "agent_busy",
        # Every agent connection for the workspace declined to declare the operation.
        "operation_not_declared",
        # The reply did not decode as the operation's result within its bound.
        "reply_invalid",
        # The agent answered: unavailable, refused, or failed, with its own closed reason.
        "agent_unavailable",
        "agent_refused",
        "agent_failed",
        # The server could not encode the call within the operation's bound.
        "arguments_invalid",
        # No hub serves this process, or a blocking call came from the event loop's own thread.
        "hub_unavailable",
        # The control call this call served was cancelled or ran out of time; it was abandoned.
        "call_cancelled",
    }
)


class WorkspaceAgentUnavailable(Exception):
    """A workspace call got no usable answer from the client's workspace agent (ADR-051).

    ``reason`` is one of ``WORKSPACE_AGENT_UNAVAILABLE_REASONS``; ``agent_reason`` is the agent's
    own closed reply reason when it answered (``agent_unavailable``, ``agent_refused`` or
    ``agent_failed``). Neither carries a path or anything the agent sent besides that token.
    Every caller turns it into a recorded gap, never into a pass.
    """

    __slots__ = ("agent_reason", "reason")

    reason: str
    agent_reason: str | None

    def __init__(self, reason: str, agent_reason: str | None = None) -> None:
        if reason not in WORKSPACE_AGENT_UNAVAILABLE_REASONS:
            raise ValueError("workspace_agent_unavailable_reason_invalid")
        answered = reason in {"agent_unavailable", "agent_refused", "agent_failed"}
        if (agent_reason is not None) is not answered or (
            agent_reason is not None and agent_reason not in WORKSPACE_REPLY_REASONS
        ):
            raise ValueError("workspace_agent_reason_invalid")
        self.reason = reason
        self.agent_reason = agent_reason
        super().__init__(reason)

    @property
    def refused(self) -> bool:
        return self.reason == "agent_refused"


# --- operations, outcomes and reasons -------------------------------------------------------


class WorkspaceOperation(str, Enum):  # noqa: UP042 - exact wire enum
    # git: the check-time change and its metadata-only facts (ADR-031, ADR-035).
    READ_TASK_BASE = "read_task_base"
    CAPTURE = "capture"
    CAPTURE_METADATA = "capture_metadata"
    PROBE_REQUESTED_PATHS = "probe_requested_paths"
    COUNT_CHANGE_LINES = "count_change_lines"
    CLASSIFY_UNDECLARED_REFERENCES = "classify_undeclared_references"
    # reads: task inputs, declared tests and the reviewer's bounded file reads.
    READ_OUTSIDE_INPUTS = "read_outside_inputs"
    SNAPSHOT_OUTSIDE_INPUTS = "snapshot_outside_inputs"
    READ_DECLARED_TEST = "read_declared_test"
    READ_TEXT_BENEATH = "read_text_beneath"
    LIST_BENEATH = "list_beneath"
    LSTAT_CANDIDATES = "lstat_candidates"
    # observation: verification of an observed workspace and approved checks.
    OPEN_WORKSPACE = "open_workspace"
    LOAD_CHECK_POLICY = "load_check_policy"
    SUBJECT_STATE_CAPTURE = "subject_state_capture"
    LIST_CHANGED_PATHS = "list_changed_paths"
    INSPECT = "inspect"
    RUN_APPROVED_CHECK = "run_approved_check"


type WorkspaceOperationFamily = Literal["git", "reads", "observation"]
type WorkspaceReplyOutcome = Literal["ok", "unavailable", "refused", "failed"]

WORKSPACE_OPERATION_NAMES: Final[tuple[str, ...]] = tuple(
    sorted((operation.value for operation in WorkspaceOperation), key=str.encode)
)
WORKSPACE_REPLY_OUTCOMES: Final[tuple[str, ...]] = ("failed", "ok", "refused", "unavailable")

# The agent would not do it: the request falls outside what this agent answers for.
WORKSPACE_REFUSAL_REASONS: Final[frozenset[str]] = frozenset(
    {
        "arguments_invalid",
        "check_not_approved",
        "operation_not_declared",
        "operation_unknown",
        "root_not_admitted",
        "workspace_not_claimed",
    }
)
# The agent tried and could not produce the answer, for a closed operational reason. Change
# capture's own reasons (``ChangeCaptureUnavailable``) and the subject-state limitations keep their
# exact tokens, so the server raises the very typed failure a local read would have.
WORKSPACE_UNAVAILABLE_REASONS: Final[frozenset[str]] = frozenset(
    CHANGE_CAPTURE_UNAVAILABLE_REASONS
    | {limitation.value for limitation in SubjectStateLimitation}
    | {
        "agent_busy",
        "deadline_exceeded",
        "handle_unknown",
        "policy_absent",
        "policy_ambiguous",
        "policy_invalid",
        "read_deadline",
        "result_too_large",
        "workspace_unavailable",
    }
)
# Something the agent did not expect; the reply names no exception, path or output.
WORKSPACE_FAILURE_REASONS: Final[frozenset[str]] = frozenset({"internal_error"})
WORKSPACE_REPLY_REASONS: Final[frozenset[str]] = (
    WORKSPACE_REFUSAL_REASONS | WORKSPACE_UNAVAILABLE_REASONS | WORKSPACE_FAILURE_REASONS
)
if (
    WORKSPACE_REFUSAL_REASONS & WORKSPACE_UNAVAILABLE_REASONS
    or WORKSPACE_FAILURE_REASONS & (WORKSPACE_REFUSAL_REASONS | WORKSPACE_UNAVAILABLE_REASONS)
    or any(
        re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason) is None for reason in WORKSPACE_REPLY_REASONS
    )
):
    raise RuntimeError("workspace_reply_reasons_not_disjoint")


def outcome_for_reason(reason: str) -> WorkspaceReplyOutcome:
    """The one reply outcome a closed failure reason belongs to."""

    if reason in WORKSPACE_REFUSAL_REASONS:
        return "refused"
    if reason in WORKSPACE_UNAVAILABLE_REASONS:
        return "unavailable"
    if reason in WORKSPACE_FAILURE_REASONS:
        return "failed"
    raise ValueError("workspace_reply_reason_invalid")


def change_capture_unavailable_reason(reason: object) -> str | None:
    """The ``ChangeCaptureUnavailable`` reason a reply reason maps to, or None."""

    if type(reason) is str and reason in CHANGE_CAPTURE_UNAVAILABLE_REASONS:
        return reason
    return None


# --- strict JSON helpers ------------------------------------------------------------------


class _Invalid(ValueError):
    """Internal: one value failed validation; the public boundary names the side."""


def _fail() -> _Invalid:
    return _Invalid("workspace_codec_value_invalid")


def _thaw(value: object) -> JsonValue:
    """A plain, validated JSON copy of ``value`` (a frozen frame member included)."""

    return strict_json_parse(canonical_encode(cast(JsonValue, value)))


def _size(value: JsonValue) -> int:
    return len(canonical_encode(value))


def _object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(cast(dict[str, object], value)) != keys:
        raise _fail()
    return cast(dict[str, object], value)


def _list(value: object, max_items: int) -> list[object]:
    if type(value) is not list or len(cast(list[object], value)) > max_items:
        raise _fail()
    return cast(list[object], value)


def _bool(value: object) -> bool:
    if type(value) is not bool:
        raise _fail()
    return value


def _int(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _fail()
    return value


def _text(value: object, *, max_bytes: int = _MAX_PATH_BYTES, absolute: bool = False) -> str:
    """A string a path argument may be: UTF-8, no NUL, bounded; absolute when asked."""

    if type(value) is not str or "\x00" in value:
        raise _fail()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise _fail() from None
    if len(encoded) > max_bytes or (absolute and not value.startswith("/")):
        raise _fail()
    return value


def _texts(value: object, max_items: int, *, absolute: bool = False) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _fail()
    items = cast(tuple[object, ...], value)
    if len(items) > max_items:
        raise _fail()
    return tuple(_text(item, absolute=absolute) for item in items)


def _text_list(value: object, max_items: int, *, absolute: bool = False) -> tuple[str, ...]:
    return tuple(_text(item, absolute=absolute) for item in _list(value, max_items))


def _sorted_set(value: object, max_items: int) -> frozenset[str]:
    """A ``frozenset[str]`` travels as a byte-sorted, duplicate-free list."""

    items = _text_list(value, max_items)
    if list(items) != sorted(set(items), key=str.encode):
        raise _fail()
    return frozenset(items)


def _set_wire(value: frozenset[str]) -> list[JsonValue]:
    return list(sorted(value, key=str.encode))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object, max_bytes: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((max_bytes + 2) // 3):
        raise _fail()
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise _fail() from None
    # One spelling per value: the canonical padded encoding only.
    if len(decoded) > max_bytes or _b64(decoded) != value:
        raise _fail()
    return decoded


def _handle(value: object) -> str:
    if not workspace_handle_valid(value):
        raise _fail()
    return cast(str, value)


def _remote_handle(value: object) -> str:
    if not remote_workspace_handle_valid(value):
        raise _fail()
    return cast(str, value)


def _client_location(value: object, *, relative: bool) -> str:
    """An absolute path, or the claimed workspace's handle (``relative``: plus a sub-path)."""

    text = _text(value)
    if text.startswith("/"):
        return text
    named, separator, rest = text.partition("/")
    if not workspace_handle_valid(named):
        raise _fail()
    if separator and (
        not relative or not rest or any(part in {"", ".", ".."} for part in rest.split("/"))
    ):
        raise _fail()
    return text


def _client_locations(value: object, max_items: int) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _fail()
    items = cast(tuple[object, ...], value)
    if len(items) > max_items:
        raise _fail()
    return tuple(_client_location(item, relative=False) for item in items)


def _client_location_list(value: object, max_items: int) -> tuple[str, ...]:
    return _client_locations(tuple(_list(value, max_items)), max_items)


def _sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _fail()
    return value


def _optional_sha256(value: object) -> str | None:
    return None if value is None else _sha256(value)


# --- argument values ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WorkspaceOnlyArguments:
    """``read_task_base`` and ``load_check_policy``: the claimed workspace, nothing else."""

    workspace: str

    def __post_init__(self) -> None:
        _handle(self.workspace)


@dataclass(frozen=True, slots=True)
class CaptureArguments:
    """``ChangeCapturePort.capture`` against the claimed workspace."""

    workspace: str
    base: TaskChangeBase | None
    priority_paths: tuple[str, ...] = field(default=(), repr=False)
    input_paths: tuple[str, ...] = field(default=(), repr=False)
    space_cut_paths: frozenset[str] = field(default=frozenset(), repr=False)

    def __post_init__(self) -> None:
        _handle(self.workspace)
        if self.base is not None and type(self.base) is not TaskChangeBase:
            raise _fail()
        _texts(self.priority_paths, _MAX_PATH_LIST)
        _texts(self.input_paths, _MAX_PATH_LIST)
        if (
            type(self.space_cut_paths) is not frozenset
            or len(self.space_cut_paths) > _MAX_PATH_LIST
        ):
            raise _fail()
        for value in self.space_cut_paths:
            _text(value)


@dataclass(frozen=True, slots=True)
class CaptureMetadataArguments:
    """``ChangeCapturePort.capture_metadata`` against the claimed workspace."""

    workspace: str
    base: TaskChangeBase | None

    def __post_init__(self) -> None:
        _handle(self.workspace)
        if self.base is not None and type(self.base) is not TaskChangeBase:
            raise _fail()


@dataclass(frozen=True, slots=True)
class ProbeRequestedPathsArguments:
    workspace: str
    values: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _handle(self.workspace)
        _texts(self.values, _MAX_REQUESTED_PATH_PROBES)


@dataclass(frozen=True, slots=True)
class CountChangeLinesArguments:
    workspace: str
    base_commit: str = field(repr=False)
    base_paths: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _handle(self.workspace)
        if type(self.base_commit) is not str or _HEX_COMMIT.fullmatch(self.base_commit) is None:
            raise _fail()
        _texts(self.base_paths, _MAX_REQUESTED_PATH_PROBES)


@dataclass(frozen=True, slots=True)
class ClassifyUndeclaredReferencesArguments:
    workspace: str
    deliverables: tuple[str, ...] = field(repr=False)
    candidates: tuple[str, ...] = field(repr=False)
    declared: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _handle(self.workspace)
        _texts(self.deliverables, _MAX_REFERENCE_DELIVERABLES)
        _texts(self.candidates, _MAX_REFERENCE_CANDIDATES)
        _texts(self.declared, _MAX_REFERENCE_CANDIDATES)


@dataclass(frozen=True, slots=True)
class ReadOutsideInputsArguments:
    """``read_outside_inputs``: the roots the server's policy admits, read on the client."""

    roots: tuple[str, ...] = field(repr=False)
    values: tuple[str, ...] = field(repr=False)
    limit: int = MAX_TASK_INPUT_FILES
    excluded: tuple[str, ...] = field(default=(), repr=False)
    space_cut: frozenset[str] = field(default=frozenset(), repr=False)

    def __post_init__(self) -> None:
        _texts(self.roots, _MAX_PATH_LIST, absolute=True)
        _texts(self.values, _MAX_PATH_LIST)
        _int(self.limit, 0, MAX_TASK_INPUT_FILES)
        _client_locations(self.excluded, _MAX_PATH_LIST)
        if type(self.space_cut) is not frozenset or len(self.space_cut) > _MAX_PATH_LIST:
            raise _fail()
        for value in self.space_cut:
            _text(value)


@dataclass(frozen=True, slots=True)
class SnapshotOutsideInputsArguments:
    """``snapshot_outside_inputs``; ``budget_ms`` is the read's time bound (``seconds``)."""

    roots: tuple[str, ...] = field(repr=False)
    values: tuple[str, ...] = field(repr=False)
    limit: int
    max_bytes: int
    budget_ms: int
    excluded: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _texts(self.roots, _MAX_PATH_LIST, absolute=True)
        _texts(self.values, _MAX_PATH_LIST)
        _int(self.limit, 0, MAX_SNAPSHOT_CANDIDATES)
        _int(self.max_bytes, 0, MAX_SNAPSHOT_FILE_BYTES)
        _int(self.budget_ms, 0, MAX_WORKSPACE_DEADLINE_MS)
        _client_locations(self.excluded, _MAX_PATH_LIST)


@dataclass(frozen=True, slots=True)
class OutsideInputsRead:
    """``read_outside_inputs``'s answer: the task inputs the agent read, ``unlisted`` and
    ``listed``.

    ``unlisted`` are the indices, ascending, of the call's ``values`` the agent left unread
    because they name an existing file or folder beneath a named root that this client's owner
    has not listed for the server (``listed`` mode, ADR-051 decision 5). Every other value is
    read as a local service reads it; a value that names nothing is not reported, as a local read
    finds nothing there. Indices only: the answer never names a path the server did not send.

    ``listed`` are the indices, ascending, of the call's ``values`` that lie at or beneath a
    folder this client's owner listed for the server (``finishup server folders add``), in either
    mode: the agent reads beneath those folders even where the server's own policy names no root
    (ADR-051 decision 5, amended 2026-11-07), so the server leaves the decision on whether such an
    input was admitted to the agent. Reported only for a value the local outside-input candidate
    rule would look at, outside the claimed workspace and FinishUP's own directories; never which
    folder, never a path the server did not send.
    """

    inputs: tuple[TaskInputFile, ...] = field(repr=False)
    unlisted: tuple[int, ...] = ()
    listed: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class OutsideSnapshotsRead:
    """``snapshot_outside_inputs``'s answer: the rows read, and ``unlisted`` and ``listed`` as
    for ``OutsideInputsRead``."""

    reads: tuple[OutsideSnapshotRead, ...] = field(repr=False)
    unlisted: tuple[int, ...] = ()
    listed: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class ReadDeclaredTestArguments:
    """``read_declared_test``; ``location`` is absolute or beneath the claimed workspace's handle.

    Every ``excluded`` entry of the reads family is an absolute path or the workspace handle
    (``client_location_valid``): the agent resolves a handle against its own claimed root.
    """

    location: str = field(repr=False)
    excluded: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _client_location(self.location, relative=True)
        _client_locations(self.excluded, _MAX_PATH_LIST)


@dataclass(frozen=True, slots=True)
class ReadTextBeneathArguments:
    root: str = field(repr=False)
    relative: str = field(repr=False)
    excluded: tuple[str, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        _client_location(self.root, relative=False)
        _text(self.relative)
        _client_locations(self.excluded, _MAX_PATH_LIST)


@dataclass(frozen=True, slots=True)
class ListBeneathArguments:
    root: str = field(repr=False)
    relative: str = field(repr=False)
    excluded: tuple[str, ...] = field(default=(), repr=False)
    inspect: int = 128

    def __post_init__(self) -> None:
        _client_location(self.root, relative=False)
        _text(self.relative)
        _client_locations(self.excluded, _MAX_PATH_LIST)
        _int(self.inspect, 1, _MAX_LIST_INSPECT)


@dataclass(frozen=True, slots=True)
class LstatCandidatesArguments:
    """Metadata-only ``lstat`` of absolute candidate paths (``outside_inputs_not_admitted``)."""

    paths: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _texts(self.paths, _MAX_LSTAT_CANDIDATES, absolute=True)


@dataclass(frozen=True, slots=True)
class OpenWorkspaceArguments:
    """``open_local_workspace`` for the claimed workspace; the reply is an opaque handle."""

    workspace: str
    admitted_home_project: bool = False

    def __post_init__(self) -> None:
        _handle(self.workspace)
        _bool(self.admitted_home_project)


@dataclass(frozen=True, slots=True)
class SubjectStateCaptureArguments:
    handle: str
    expected_format: SubjectStateFormat = SubjectStateFormat.GIT_STRUCTURAL_V1

    def __post_init__(self) -> None:
        _remote_handle(self.handle)
        if type(self.expected_format) is not SubjectStateFormat:
            raise _fail()


@dataclass(frozen=True, slots=True)
class ListChangedPathsArguments:
    handle: str
    max_files: int = MAX_SUBJECT_STATE_FILES

    def __post_init__(self) -> None:
        _remote_handle(self.handle)
        _int(self.max_files, 1, MAX_SUBJECT_STATE_FILES)


@dataclass(frozen=True, slots=True)
class InspectArguments:
    handle: str
    relative_paths: tuple[str, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _remote_handle(self.handle)
        paths = _texts(self.relative_paths, MAX_INSPECT_FILES)
        if not paths or len(set(paths)) != len(paths):
            raise _fail()
        for path in paths:
            if (
                not path
                or path.startswith(("/", "\\"))
                or ".." in path.split("/")
                or len(path.encode("utf-8")) > MAX_INSPECT_PATH_BYTES
            ):
                raise _fail()


@dataclass(frozen=True, slots=True)
class RunApprovedCheckArguments:
    """One owner-approved argv; the agent runs it only when its own policy holds this approval."""

    handle: str
    approval: ApprovedCheckApproval
    subject_state_digest: str
    expected_subject_state_digest: str | None = None

    def __post_init__(self) -> None:
        _remote_handle(self.handle)
        if type(self.approval) is not ApprovedCheckApproval:
            raise _fail()
        _sha256(self.subject_state_digest)
        _optional_sha256(self.expected_subject_state_digest)


# --- result values ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LstatFacts:
    """The ``lstat`` fields an outside-input decision reads: file type and two times."""

    mode: int
    mtime_ns: int
    ctime_ns: int

    def __post_init__(self) -> None:
        _int(self.mode, 0, 0o177777)
        _int(self.mtime_ns, -(2**62), 2**62)
        _int(self.ctime_ns, -(2**62), 2**62)

    @classmethod
    def from_stat_result(cls, facts: os.stat_result) -> LstatFacts:
        return cls(facts.st_mode, facts.st_mtime_ns, facts.st_ctime_ns)

    def to_stat_result(self) -> os.stat_result:
        """A ``stat_result`` whose mode and float times equal the original ``lstat``'s."""

        def seconds(nanoseconds: int) -> float:
            whole, fraction = divmod(nanoseconds, 1_000_000_000)
            return whole + fraction * 1e-9

        return os.stat_result(
            (
                self.mode,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                self.mtime_ns // 1_000_000_000,
                self.ctime_ns // 1_000_000_000,
                0.0,
                seconds(self.mtime_ns),
                seconds(self.ctime_ns),
                0,
                self.mtime_ns,
                self.ctime_ns,
            )
        )

    @property
    def is_regular_file(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def is_directory(self) -> bool:
        return stat.S_ISDIR(self.mode)


@dataclass(frozen=True, slots=True)
class CheckPolicyRead:
    """The raw approved-check policy bytes and which of the two policy files held them."""

    location: Literal["current", "legacy"]
    raw: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if self.location not in {"current", "legacy"}:
            raise _fail()
        if type(self.raw) is not bytes or not 1 <= len(self.raw) <= _MAX_POLICY_BYTES:
            raise _fail()


@dataclass(frozen=True, slots=True)
class ApprovedCheckRun:
    """One approved check the agent ran: its result and the redacted output it captured.

    ``output`` is the redacted bounded buffer the runner handed its output sink, present exactly
    when the result names an output digest; ``output_redacted`` says whether redaction replaced
    bytes in it.
    """

    result: ApprovedCheckResult
    output: bytes | None = field(default=None, repr=False)
    output_redacted: bool = False

    def __post_init__(self) -> None:
        if type(self.result) is not ApprovedCheckResult:
            raise _fail()
        if (self.output is None) is not (self.result.output_digest is None):
            raise _fail()
        _bool(self.output_redacted)
        if self.output is None:
            if self.output_redacted:
                raise _fail()
            return
        if type(self.output) is not bytes or len(self.output) != self.result.output_bytes:
            raise _fail()
        if self.result.output_digest != "sha256:" + hashlib.sha256(self.output).hexdigest():
            raise _fail()


# --- codecs: git ----------------------------------------------------------------------------


def _base_wire(base: TaskChangeBase | None) -> JsonValue:
    return None if base is None else strict_json_parse(encode_task_change_base(base))


def _base_from_wire(value: object) -> TaskChangeBase | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise _fail()
    return decode_task_change_base(canonical_encode(cast(JsonValue, value)))


def _encode_workspace_only(value: WorkspaceOnlyArguments) -> dict[str, JsonValue]:
    return {"workspace": value.workspace}


def _decode_workspace_only(source: dict[str, object]) -> WorkspaceOnlyArguments:
    fields_ = _object(source, frozenset({"workspace"}))
    return WorkspaceOnlyArguments(_handle(fields_["workspace"]))


def _encode_capture(value: CaptureArguments) -> dict[str, JsonValue]:
    return {
        "base": _base_wire(value.base),
        "input_paths": list(value.input_paths),
        "priority_paths": list(value.priority_paths),
        "space_cut_paths": _set_wire(value.space_cut_paths),
        "workspace": value.workspace,
    }


def _decode_capture(source: dict[str, object]) -> CaptureArguments:
    fields_ = _object(
        source,
        frozenset({"base", "input_paths", "priority_paths", "space_cut_paths", "workspace"}),
    )
    return CaptureArguments(
        _handle(fields_["workspace"]),
        _base_from_wire(fields_["base"]),
        _text_list(fields_["priority_paths"], _MAX_PATH_LIST),
        _text_list(fields_["input_paths"], _MAX_PATH_LIST),
        _sorted_set(fields_["space_cut_paths"], _MAX_PATH_LIST),
    )


def _encode_capture_metadata(value: CaptureMetadataArguments) -> dict[str, JsonValue]:
    return {"base": _base_wire(value.base), "workspace": value.workspace}


def _decode_capture_metadata(source: dict[str, object]) -> CaptureMetadataArguments:
    fields_ = _object(source, frozenset({"base", "workspace"}))
    return CaptureMetadataArguments(_handle(fields_["workspace"]), _base_from_wire(fields_["base"]))


def _encode_probe(value: ProbeRequestedPathsArguments) -> dict[str, JsonValue]:
    return {"values": list(value.values), "workspace": value.workspace}


def _decode_probe(source: dict[str, object]) -> ProbeRequestedPathsArguments:
    fields_ = _object(source, frozenset({"values", "workspace"}))
    return ProbeRequestedPathsArguments(
        _handle(fields_["workspace"]), _text_list(fields_["values"], _MAX_REQUESTED_PATH_PROBES)
    )


def _encode_count(value: CountChangeLinesArguments) -> dict[str, JsonValue]:
    return {
        "base_commit": value.base_commit,
        "base_paths": list(value.base_paths),
        "workspace": value.workspace,
    }


def _decode_count(source: dict[str, object]) -> CountChangeLinesArguments:
    fields_ = _object(source, frozenset({"base_commit", "base_paths", "workspace"}))
    return CountChangeLinesArguments(
        _handle(fields_["workspace"]),
        cast(str, fields_["base_commit"]),
        _text_list(fields_["base_paths"], _MAX_REQUESTED_PATH_PROBES),
    )


def _encode_classify(value: ClassifyUndeclaredReferencesArguments) -> dict[str, JsonValue]:
    return {
        "candidates": list(value.candidates),
        "declared": list(value.declared),
        "deliverables": list(value.deliverables),
        "workspace": value.workspace,
    }


def _decode_classify(source: dict[str, object]) -> ClassifyUndeclaredReferencesArguments:
    fields_ = _object(source, frozenset({"candidates", "declared", "deliverables", "workspace"}))
    return ClassifyUndeclaredReferencesArguments(
        _handle(fields_["workspace"]),
        _text_list(fields_["deliverables"], _MAX_REFERENCE_DELIVERABLES),
        _text_list(fields_["candidates"], _MAX_REFERENCE_CANDIDATES),
        _text_list(fields_["declared"], _MAX_REFERENCE_CANDIDATES),
    )


def _encode_task_base(value: TaskChangeBase) -> JsonValue:
    if type(value) is not TaskChangeBase:
        raise _fail()
    return strict_json_parse(encode_task_change_base(value))


def _decode_task_base(value: object) -> TaskChangeBase:
    base = _base_from_wire(value)
    if base is None:
        raise _fail()
    return base


def _encode_check_change(value: CheckChangeCapture) -> JsonValue:
    if type(value) is not CheckChangeCapture:
        raise _fail()
    return strict_json_parse(encode_check_change(value))


def _decode_check_change(value: object) -> CheckChangeCapture:
    if type(value) is not dict:
        raise _fail()
    return decode_check_change(canonical_encode(cast(JsonValue, value)))


_METADATA_KEYS: Final = frozenset(
    {
        "base",
        "base_commit",
        "entries",
        "omitted_files",
        "tracked_files",
        "truncated",
        "unrepresentable_files",
        "untracked_files",
    }
)


def _metadata_wire(value: CheckChangeMetadata) -> dict[str, JsonValue]:
    return {
        "base": value.base,
        "base_commit": value.base_commit,
        "entries": [
            [entry.status, entry.path, entry.untracked, entry.original_path]
            for entry in value.entries
        ],
        "omitted_files": value.omitted_files,
        "tracked_files": value.tracked_files,
        "truncated": value.truncated,
        "unrepresentable_files": value.unrepresentable_files,
        "untracked_files": value.untracked_files,
    }


def _fit_metadata(value: CheckChangeMetadata, max_bytes: int) -> CheckChangeMetadata:
    """The listing cut to its first entries that fit, every dropped entry counted as omitted.

    A Git listing may outgrow one frame (T4). Dropping its tail is the existing truncation the
    metadata already expresses: each dropped path is counted in ``omitted_files`` and the listing
    is marked ``truncated``, so accounting reads it as a lower bound, never as complete.
    """

    if _size(_metadata_wire(value)) <= max_bytes:
        return value
    count = len(value.entries)

    def cut(kept: int) -> CheckChangeMetadata:
        return replace(
            value,
            entries=value.entries[:kept],
            omitted_files=value.omitted_files + (count - kept),
            truncated=True,
        )

    low, high = 0, count - 1
    best: CheckChangeMetadata | None = None
    while low <= high:
        middle = (low + high) // 2
        candidate = cut(middle)
        if _size(_metadata_wire(candidate)) <= max_bytes:
            best, low = candidate, middle + 1
        else:
            high = middle - 1
    if best is None:
        raise _fail()
    return best


def _encode_metadata(value: CheckChangeMetadata) -> JsonValue:
    if type(value) is not CheckChangeMetadata:
        raise _fail()
    return _metadata_wire(value)


def _decode_metadata(value: object) -> CheckChangeMetadata:
    fields_ = _object(value, _METADATA_KEYS)
    entries: list[ChangeMetadataEntry] = []
    for row in _list(fields_["entries"], 1_000_000):
        items = _list(row, 4)
        if len(items) != 4:
            raise _fail()
        status, path, untracked, original = items
        entries.append(
            ChangeMetadataEntry(
                cast(str, status),
                cast(str, path),
                _bool(untracked),
                None if original is None else cast(str, original),
            )
        )
    return CheckChangeMetadata(
        base=cast(ChangeBaseKind, fields_["base"]),
        entries=tuple(entries),
        tracked_files=cast(int, fields_["tracked_files"]),
        untracked_files=cast(int, fields_["untracked_files"]),
        omitted_files=cast(int, fields_["omitted_files"]),
        truncated=_bool(fields_["truncated"]),
        base_commit=cast(str, fields_["base_commit"]),
        unrepresentable_files=cast(int, fields_["unrepresentable_files"]),
    )


_PROBE_KEYS: Final = frozenset(
    {
        "exists",
        "holds_file",
        "ignore_file",
        "ignore_source",
        "ignored",
        "location",
        "relative",
        "size_bytes",
    }
)


def _optional_bool(value: object) -> bool | None:
    return None if value is None else _bool(value)


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _encode_probes(value: tuple[RequestedPathProbe, ...]) -> JsonValue:
    if type(value) is not tuple or len(value) > _MAX_REQUESTED_PATH_PROBES:
        raise _fail()
    rows: list[JsonValue] = []
    for probe in value:
        if type(probe) is not RequestedPathProbe:
            raise _fail()
        rows.append(
            {
                "exists": probe.exists,
                "holds_file": probe.holds_file,
                "ignore_file": probe.ignore_file,
                "ignore_source": probe.ignore_source,
                "ignored": probe.ignored,
                "location": probe.location,
                "relative": probe.relative,
                "size_bytes": probe.size_bytes,
            }
        )
    return rows


def _decode_probes(value: object) -> tuple[RequestedPathProbe, ...]:
    probes: list[RequestedPathProbe] = []
    for row in _list(value, _MAX_REQUESTED_PATH_PROBES):
        fields_ = _object(row, _PROBE_KEYS)
        size = fields_["size_bytes"]
        probes.append(
            RequestedPathProbe(
                location=_text(fields_["location"]),
                relative=_optional_text(fields_["relative"]),
                exists=_optional_bool(fields_["exists"]),
                ignored=_optional_bool(fields_["ignored"]),
                ignore_source=_optional_text(fields_["ignore_source"]),
                ignore_file=_optional_text(fields_["ignore_file"]),
                holds_file=_optional_bool(fields_["holds_file"]),
                size_bytes=None if size is None else cast(int, size),
            )
        )
    return tuple(probes)


def _line_counts_wire(value: ChangeLineCounts) -> dict[str, JsonValue]:
    return {
        "base_lines": list(value.base_lines),
        "changed": [
            [item.path, item.added, item.removed, item.untracked] for item in value.changed
        ],
        "truncated": value.truncated,
    }


def _fit_line_counts(value: ChangeLineCounts, max_bytes: int) -> ChangeLineCounts:
    """Counts cut to the changed files that fit; the read is then marked ``truncated``.

    ``truncated`` already means "some changed file was left out, so any total is a lower bound"
    (ADR-035), which is exactly what dropping the tail of an oversized read is.
    """

    if _size(_line_counts_wire(value)) <= max_bytes:
        return value
    low, high = 0, len(value.changed) - 1
    best: ChangeLineCounts | None = None
    while low <= high:
        middle = (low + high) // 2
        candidate = replace(value, changed=value.changed[:middle], truncated=True)
        if _size(_line_counts_wire(candidate)) <= max_bytes:
            best, low = candidate, middle + 1
        else:
            high = middle - 1
    if best is None:
        raise _fail()
    return best


def _encode_line_counts(value: ChangeLineCounts) -> JsonValue:
    if type(value) is not ChangeLineCounts or len(value.base_lines) > _MAX_REQUESTED_PATH_PROBES:
        raise _fail()
    return _line_counts_wire(value)


def _optional_count(value: object) -> int | None:
    return None if value is None else cast(int, value)


def _decode_line_counts(value: object) -> ChangeLineCounts:
    fields_ = _object(value, frozenset({"base_lines", "changed", "truncated"}))
    changed: list[ChangeLineCount] = []
    for row in _list(fields_["changed"], 1_000_000):
        items = _list(row, 4)
        if len(items) != 4:
            raise _fail()
        path, added, removed, untracked = items
        changed.append(
            ChangeLineCount(
                cast(str, path), _optional_count(added), _optional_count(removed), _bool(untracked)
            )
        )
    base_lines = tuple(
        _optional_count(item) for item in _list(fields_["base_lines"], _MAX_REQUESTED_PATH_PROBES)
    )
    return ChangeLineCounts(tuple(changed), base_lines, _bool(fields_["truncated"]))


_REFERENCE_KINDS: Final = frozenset({"dependency", "ambiguous"})


def _reference_row(deliverable: object, candidate: object, kind: object) -> tuple[int, int, str]:
    if kind not in _REFERENCE_KINDS:
        raise _fail()
    return (
        _int(deliverable, 0, _MAX_REFERENCE_DELIVERABLES - 1),
        _int(candidate, 0, _MAX_REFERENCE_CANDIDATES - 1),
        cast(str, kind),
    )


def _encode_references(value: tuple[tuple[int, int, str], ...]) -> JsonValue:
    if type(value) is not tuple or len(value) > 2 * _MAX_REFERENCE_PAIRS:
        raise _fail()
    rows: list[JsonValue] = []
    for row in value:
        if type(row) is not tuple or len(row) != 3:
            raise _fail()
        deliverable, candidate, kind = _reference_row(*row)
        rows.append([deliverable, candidate, kind])
    return rows


def _decode_references(value: object) -> tuple[tuple[int, int, str], ...]:
    rows: list[tuple[int, int, str]] = []
    for row in _list(value, 2 * _MAX_REFERENCE_PAIRS):
        items = _list(row, 3)
        if len(items) != 3:
            raise _fail()
        rows.append(_reference_row(*items))
    return tuple(rows)


# --- codecs: reads --------------------------------------------------------------------------


def _encode_outside(value: ReadOutsideInputsArguments) -> dict[str, JsonValue]:
    return {
        "excluded": list(value.excluded),
        "limit": value.limit,
        "roots": list(value.roots),
        "space_cut": _set_wire(value.space_cut),
        "values": list(value.values),
    }


def _decode_outside(source: dict[str, object]) -> ReadOutsideInputsArguments:
    fields_ = _object(source, frozenset({"excluded", "limit", "roots", "space_cut", "values"}))
    return ReadOutsideInputsArguments(
        _text_list(fields_["roots"], _MAX_PATH_LIST, absolute=True),
        _text_list(fields_["values"], _MAX_PATH_LIST),
        _int(fields_["limit"], 0, MAX_TASK_INPUT_FILES),
        _client_location_list(fields_["excluded"], _MAX_PATH_LIST),
        _sorted_set(fields_["space_cut"], _MAX_PATH_LIST),
    )


def _encode_snapshot(value: SnapshotOutsideInputsArguments) -> dict[str, JsonValue]:
    return {
        "budget_ms": value.budget_ms,
        "excluded": list(value.excluded),
        "limit": value.limit,
        "max_bytes": value.max_bytes,
        "roots": list(value.roots),
        "values": list(value.values),
    }


def _decode_snapshot(source: dict[str, object]) -> SnapshotOutsideInputsArguments:
    fields_ = _object(
        source, frozenset({"budget_ms", "excluded", "limit", "max_bytes", "roots", "values"})
    )
    return SnapshotOutsideInputsArguments(
        roots=_text_list(fields_["roots"], _MAX_PATH_LIST, absolute=True),
        values=_text_list(fields_["values"], _MAX_PATH_LIST),
        limit=_int(fields_["limit"], 0, MAX_SNAPSHOT_CANDIDATES),
        max_bytes=_int(fields_["max_bytes"], 0, MAX_SNAPSHOT_FILE_BYTES),
        budget_ms=_int(fields_["budget_ms"], 0, MAX_WORKSPACE_DEADLINE_MS),
        excluded=_client_location_list(fields_["excluded"], _MAX_PATH_LIST),
    )


def _encode_declared(value: ReadDeclaredTestArguments) -> dict[str, JsonValue]:
    return {"excluded": list(value.excluded), "location": value.location}


def _decode_declared(source: dict[str, object]) -> ReadDeclaredTestArguments:
    fields_ = _object(source, frozenset({"excluded", "location"}))
    return ReadDeclaredTestArguments(
        _client_location(fields_["location"], relative=True),
        _client_location_list(fields_["excluded"], _MAX_PATH_LIST),
    )


def _encode_text_beneath(value: ReadTextBeneathArguments) -> dict[str, JsonValue]:
    return {"excluded": list(value.excluded), "relative": value.relative, "root": value.root}


def _decode_text_beneath(source: dict[str, object]) -> ReadTextBeneathArguments:
    fields_ = _object(source, frozenset({"excluded", "relative", "root"}))
    return ReadTextBeneathArguments(
        _client_location(fields_["root"], relative=False),
        _text(fields_["relative"]),
        _client_location_list(fields_["excluded"], _MAX_PATH_LIST),
    )


def _encode_list_beneath(value: ListBeneathArguments) -> dict[str, JsonValue]:
    return {
        "excluded": list(value.excluded),
        "inspect": value.inspect,
        "relative": value.relative,
        "root": value.root,
    }


def _decode_list_beneath(source: dict[str, object]) -> ListBeneathArguments:
    fields_ = _object(source, frozenset({"excluded", "inspect", "relative", "root"}))
    return ListBeneathArguments(
        _client_location(fields_["root"], relative=False),
        _text(fields_["relative"]),
        _client_location_list(fields_["excluded"], _MAX_PATH_LIST),
        _int(fields_["inspect"], 1, _MAX_LIST_INSPECT),
    )


def _encode_lstat_args(value: LstatCandidatesArguments) -> dict[str, JsonValue]:
    return {"paths": list(value.paths)}


def _decode_lstat_args(source: dict[str, object]) -> LstatCandidatesArguments:
    fields_ = _object(source, frozenset({"paths"}))
    return LstatCandidatesArguments(
        _text_list(fields_["paths"], _MAX_LSTAT_CANDIDATES, absolute=True)
    )


def _encode_task_inputs(value: tuple[TaskInputFile, ...]) -> JsonValue:
    if type(value) is not tuple or len(value) > MAX_TASK_INPUT_FILES:
        raise _fail()
    return [cast(JsonValue, task_input_file_wire(item)) for item in value]


def _decode_task_inputs(value: object) -> tuple[TaskInputFile, ...]:
    return tuple(task_input_file_from_wire(row) for row in _list(value, MAX_TASK_INPUT_FILES))


def _unlisted_valid(value: object) -> tuple[int, ...]:
    """Indices into a call's ``values``: ascending, unique, each within the argument bound."""

    if type(value) is not tuple:
        raise _fail()
    items = cast(tuple[object, ...], value)
    if len(items) > _MAX_PATH_LIST or any(
        type(item) is not int or not 0 <= item < _MAX_PATH_LIST for item in items
    ):
        raise _fail()
    indices = cast(tuple[int, ...], items)
    if list(indices) != sorted(set(indices)):
        raise _fail()
    return indices


def _decode_unlisted(value: object) -> tuple[int, ...]:
    return _unlisted_valid(
        tuple(_int(item, 0, _MAX_PATH_LIST - 1) for item in _list(value, _MAX_PATH_LIST))
    )


def _encode_outside_read(value: OutsideInputsRead) -> JsonValue:
    if type(value) is not OutsideInputsRead:
        raise _fail()
    return {
        "inputs": _encode_task_inputs(value.inputs),
        "listed": list(_unlisted_valid(value.listed)),
        "unlisted": list(_unlisted_valid(value.unlisted)),
    }


def _decode_outside_read(value: object) -> OutsideInputsRead:
    fields_ = _object(value, frozenset({"inputs", "listed", "unlisted"}))
    return OutsideInputsRead(
        _decode_task_inputs(fields_["inputs"]),
        _decode_unlisted(fields_["unlisted"]),
        _decode_unlisted(fields_["listed"]),
    )


_SNAPSHOT_REASONS: Final = frozenset({"too_large", "not_text", "unreadable"})


def _snapshot_row_valid(row: OutsideSnapshotRead) -> None:
    _text(row.root, absolute=True)
    _text(row.path, absolute=True)
    _int(row.size, 0, (1 << 53) - 1)
    if row.reason is None:
        if type(row.text) is not bytes or len(row.text) > MAX_SNAPSHOT_FILE_BYTES:
            raise _fail()
    elif row.reason not in _SNAPSHOT_REASONS or row.text is not None:
        raise _fail()


def _encode_snapshot_reads(value: tuple[OutsideSnapshotRead, ...]) -> JsonValue:
    if type(value) is not tuple or len(value) > MAX_SNAPSHOT_CANDIDATES:
        raise _fail()
    rows: list[JsonValue] = []
    for row in value:
        if type(row) is not OutsideSnapshotRead:
            raise _fail()
        _snapshot_row_valid(row)
        rows.append(
            {
                "path": row.path,
                "reason": row.reason,
                "root": row.root,
                "size": row.size,
                "text": None if row.text is None else _b64(row.text),
            }
        )
    return rows


def _decode_snapshot_reads(value: object) -> tuple[OutsideSnapshotRead, ...]:
    reads: list[OutsideSnapshotRead] = []
    for raw in _list(value, MAX_SNAPSHOT_CANDIDATES):
        fields_ = _object(raw, frozenset({"path", "reason", "root", "size", "text"}))
        text = fields_["text"]
        reason = fields_["reason"]
        row = OutsideSnapshotRead(
            cast(str, fields_["root"]),
            cast(str, fields_["path"]),
            cast(int, fields_["size"]),
            None if text is None else _unb64(text, MAX_SNAPSHOT_FILE_BYTES),
            cast(Literal["too_large", "not_text", "unreadable"] | None, reason),
        )
        _snapshot_row_valid(row)
        reads.append(row)
    return tuple(reads)


def _encode_snapshots_read(value: OutsideSnapshotsRead) -> JsonValue:
    if type(value) is not OutsideSnapshotsRead:
        raise _fail()
    return {
        "listed": list(_unlisted_valid(value.listed)),
        "reads": _encode_snapshot_reads(value.reads),
        "unlisted": list(_unlisted_valid(value.unlisted)),
    }


def _decode_snapshots_read(value: object) -> OutsideSnapshotsRead:
    fields_ = _object(value, frozenset({"listed", "reads", "unlisted"}))
    return OutsideSnapshotsRead(
        _decode_snapshot_reads(fields_["reads"]),
        _decode_unlisted(fields_["unlisted"]),
        _decode_unlisted(fields_["listed"]),
    )


def _encode_optional_bytes(value: bytes | None) -> JsonValue:
    if value is None:
        return None
    if type(value) is not bytes or len(value) > _MAX_TASK_INPUT_READ_BYTES:
        raise _fail()
    return _b64(value)


def _decode_optional_bytes(value: object) -> bytes | None:
    return None if value is None else _unb64(value, _MAX_TASK_INPUT_READ_BYTES)


def _encode_text_read(value: tuple[bytes, int] | None) -> JsonValue:
    if value is None:
        return None
    if type(value) is not tuple or len(value) != 2:
        raise _fail()
    data, size = value
    if type(data) is not bytes or len(data) > _MAX_TASK_INPUT_READ_BYTES:
        raise _fail()
    _int(size, 0, (1 << 53) - 1)
    if data and len(data) != size:
        raise _fail()
    return {"data": _b64(data), "size": size}


def _decode_text_read(value: object) -> tuple[bytes, int] | None:
    if value is None:
        return None
    fields_ = _object(value, frozenset({"data", "size"}))
    data = _unb64(fields_["data"], _MAX_TASK_INPUT_READ_BYTES)
    size = _int(fields_["size"], 0, (1 << 53) - 1)
    # A whole read (data and its size agree) or a withheld one (no bytes, the size alone).
    if data and len(data) != size:
        raise _fail()
    return (data, size)


def _listed_name(value: object) -> str:
    name = _text(value, max_bytes=_MAX_LISTED_NAME_BYTES)
    if not name or "/" in name:
        raise _fail()
    return name


def _encode_listing(value: tuple[tuple[tuple[str, bool], ...], bool] | None) -> JsonValue:
    if value is None:
        return None
    if type(value) is not tuple or len(value) != 2:
        raise _fail()
    entries, truncated = value
    if type(entries) is not tuple or len(entries) > _MAX_LIST_INSPECT:
        raise _fail()
    rows: list[JsonValue] = []
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 2:
            raise _fail()
        rows.append([_listed_name(entry[0]), _bool(entry[1])])
    return {"entries": rows, "truncated": _bool(truncated)}


def _decode_listing(value: object) -> tuple[tuple[tuple[str, bool], ...], bool] | None:
    if value is None:
        return None
    fields_ = _object(value, frozenset({"entries", "truncated"}))
    entries: list[tuple[str, bool]] = []
    for row in _list(fields_["entries"], _MAX_LIST_INSPECT):
        items = _list(row, 2)
        if len(items) != 2:
            raise _fail()
        entries.append((_listed_name(items[0]), _bool(items[1])))
    return tuple(entries), _bool(fields_["truncated"])


def _encode_lstat(value: tuple[LstatFacts | None, ...]) -> JsonValue:
    if type(value) is not tuple or len(value) > _MAX_LSTAT_CANDIDATES:
        raise _fail()
    rows: list[JsonValue] = []
    for facts in value:
        if facts is None:
            rows.append(None)
        elif type(facts) is LstatFacts:
            # Nanosecond times exceed the JSON-safe integer range: canonical decimal strings.
            rows.append([facts.mode, str(facts.mtime_ns), str(facts.ctime_ns)])
        else:
            raise _fail()
    return rows


def _decode_lstat(value: object) -> tuple[LstatFacts | None, ...]:
    facts: list[LstatFacts | None] = []
    for row in _list(value, _MAX_LSTAT_CANDIDATES):
        if row is None:
            facts.append(None)
            continue
        items = _list(row, 3)
        if len(items) != 3:
            raise _fail()
        mtime, ctime = items[1], items[2]
        if type(mtime) is not str or type(ctime) is not str:
            raise _fail()
        facts.append(
            LstatFacts(
                cast(int, items[0]),
                parse_canonical_integer_string(mtime, signed=True),
                parse_canonical_integer_string(ctime, signed=True),
            )
        )
    return tuple(facts)


# --- codecs: observation --------------------------------------------------------------------


def _encode_open(value: OpenWorkspaceArguments) -> dict[str, JsonValue]:
    return {"admitted_home_project": value.admitted_home_project, "workspace": value.workspace}


def _decode_open(source: dict[str, object]) -> OpenWorkspaceArguments:
    fields_ = _object(source, frozenset({"admitted_home_project", "workspace"}))
    return OpenWorkspaceArguments(
        _handle(fields_["workspace"]), _bool(fields_["admitted_home_project"])
    )


def _encode_remote_handle(value: str) -> JsonValue:
    return _remote_handle(value)


def _decode_remote_handle(value: object) -> str:
    return _remote_handle(value)


def _encode_policy(value: CheckPolicyRead) -> JsonValue:
    if type(value) is not CheckPolicyRead:
        raise _fail()
    return {"location": value.location, "policy": _b64(value.raw)}


def _decode_policy(value: object) -> CheckPolicyRead:
    fields_ = _object(value, frozenset({"location", "policy"}))
    return CheckPolicyRead(
        cast(Literal["current", "legacy"], fields_["location"]),
        _unb64(fields_["policy"], _MAX_POLICY_BYTES),
    )


def _encode_subject_args(value: SubjectStateCaptureArguments) -> dict[str, JsonValue]:
    return {"expected_format": value.expected_format.value, "handle": value.handle}


def _decode_subject_args(source: dict[str, object]) -> SubjectStateCaptureArguments:
    fields_ = _object(source, frozenset({"expected_format", "handle"}))
    return SubjectStateCaptureArguments(
        _remote_handle(fields_["handle"]), SubjectStateFormat(cast(str, fields_["expected_format"]))
    )


_SUBJECT_KEYS: Final = frozenset(
    {
        "bytes_hashed",
        "files_hashed",
        "format",
        "limit_detail",
        "limitations",
        "status",
        "subject_state",
    }
)


def _encode_subject_result(value: SubjectStateCaptureResult) -> JsonValue:
    if type(value) is not SubjectStateCaptureResult:
        raise _fail()
    state = value.subject_state
    return {
        "bytes_hashed": value.bytes_hashed,
        "files_hashed": value.files_hashed,
        "format": value.format.value,
        "limit_detail": [
            [detail.bound.value, detail.observed, detail.limit] for detail in value.limit_detail
        ],
        "limitations": [limitation.value for limitation in value.limitations],
        "status": value.status.value,
        "subject_state": None
        if state is None
        else {
            "described_state": state.described_state,
            "diff_digest": state.diff_digest,
            "tree_digest": state.tree_digest,
        },
    }


def _decode_subject_result(value: object) -> SubjectStateCaptureResult:
    fields_ = _object(value, _SUBJECT_KEYS)
    raw_state = fields_["subject_state"]
    state: SubjectStateRef | None = None
    if raw_state is not None:
        state_fields = _object(
            raw_state, frozenset({"described_state", "diff_digest", "tree_digest"})
        )
        state = SubjectStateRef(
            tree_digest=_optional_text(state_fields["tree_digest"]),
            diff_digest=_optional_text(state_fields["diff_digest"]),
            described_state=_optional_text(state_fields["described_state"]),
        )
    details: list[SubjectStateLimitDetail] = []
    for row in _list(fields_["limit_detail"], len(SubjectStateLimitation)):
        items = _list(row, 3)
        if len(items) != 3:
            raise _fail()
        details.append(
            SubjectStateLimitDetail(
                SubjectStateBound(cast(str, items[0])), cast(int, items[1]), cast(int, items[2])
            )
        )
    return SubjectStateCaptureResult(
        status=SubjectStateStatus(cast(str, fields_["status"])),
        subject_state=state,
        format=SubjectStateFormat(cast(str, fields_["format"])),
        limitations=tuple(
            SubjectStateLimitation(cast(str, item))
            for item in _list(fields_["limitations"], len(SubjectStateLimitation))
        ),
        bytes_hashed=cast(int, fields_["bytes_hashed"]),
        files_hashed=cast(int, fields_["files_hashed"]),
        limit_detail=tuple(details),
    )


def _encode_changed_args(value: ListChangedPathsArguments) -> dict[str, JsonValue]:
    return {"handle": value.handle, "max_files": value.max_files}


def _decode_changed_args(source: dict[str, object]) -> ListChangedPathsArguments:
    fields_ = _object(source, frozenset({"handle", "max_files"}))
    return ListChangedPathsArguments(
        _remote_handle(fields_["handle"]), _int(fields_["max_files"], 1, MAX_SUBJECT_STATE_FILES)
    )


def _changed_paths(value: tuple[str, ...]) -> tuple[str, ...]:
    if len(value) > MAX_INSPECT_FILES or list(value) != sorted(set(value), key=str.encode):
        raise _fail()
    for path in value:
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise _fail()
    return value


def _encode_changed(value: tuple[str, ...]) -> JsonValue:
    return list(_changed_paths(_texts(value, MAX_INSPECT_FILES)))


def _decode_changed(value: object) -> tuple[str, ...]:
    return _changed_paths(_text_list(value, MAX_INSPECT_FILES))


def _encode_inspect_args(value: InspectArguments) -> dict[str, JsonValue]:
    return {"handle": value.handle, "relative_paths": list(value.relative_paths)}


def _decode_inspect_args(source: dict[str, object]) -> InspectArguments:
    fields_ = _object(source, frozenset({"handle", "relative_paths"}))
    return InspectArguments(
        _remote_handle(fields_["handle"]), _text_list(fields_["relative_paths"], MAX_INSPECT_FILES)
    )


_ARTIFACT_KEYS: Final = frozenset(
    {"byte_length", "content_digest", "excerpt", "excerpt_truncated", "relative_path"}
)


def _encode_inspect(value: WorkspaceInspectResult) -> JsonValue:
    if type(value) is not WorkspaceInspectResult:
        raise _fail()
    return {
        "artifacts": [
            {
                "byte_length": artifact.byte_length,
                "content_digest": artifact.content_digest,
                "excerpt": _b64(artifact.excerpt),
                "excerpt_truncated": artifact.excerpt_truncated,
                "relative_path": artifact.relative_path,
            }
            for artifact in value.artifacts
        ],
        "limitations": [limitation.value for limitation in value.limitations],
        "selection_digest": value.selection_digest,
        "status": value.status.value,
    }


def _decode_inspect(value: object) -> WorkspaceInspectResult:
    fields_ = _object(value, frozenset({"artifacts", "limitations", "selection_digest", "status"}))
    artifacts: list[InspectedArtifact] = []
    for raw in _list(fields_["artifacts"], MAX_INSPECT_FILES):
        artifact = _object(raw, _ARTIFACT_KEYS)
        artifacts.append(
            InspectedArtifact(
                relative_path=cast(str, artifact["relative_path"]),
                content_digest=cast(str, artifact["content_digest"]),
                excerpt=_unb64(artifact["excerpt"], MAX_INSPECT_EXCERPT_BYTES),
                excerpt_truncated=_bool(artifact["excerpt_truncated"]),
                byte_length=cast(int, artifact["byte_length"]),
            )
        )
    return WorkspaceInspectResult(
        status=WorkspaceInspectStatus(cast(str, fields_["status"])),
        artifacts=tuple(artifacts),
        limitations=tuple(
            WorkspaceInspectLimitation(cast(str, item))
            for item in _list(fields_["limitations"], len(WorkspaceInspectLimitation))
        ),
        selection_digest=_optional_sha256(fields_["selection_digest"]),
    )


_APPROVAL_KEYS: Final = frozenset(
    {"allow_network", "approval_commitment", "approval_id", "argv", "timeout_seconds"}
)


def _approval_wire(value: ApprovedCheckApproval) -> dict[str, JsonValue]:
    # Canonical JSON admits no float: the owner's timeout travels as the exact ``repr`` of its
    # float, which ``float`` reads back bit for bit.
    return {
        "allow_network": value.allow_network,
        "approval_commitment": value.approval_commitment,
        "approval_id": value.approval_id,
        "argv": list(value.argv),
        "timeout_seconds": repr(value.timeout_seconds),
    }


def _approval_from_wire(value: object) -> ApprovedCheckApproval:
    fields_ = _object(value, _APPROVAL_KEYS)
    timeout = fields_["timeout_seconds"]
    if type(timeout) is not str or _TIMEOUT_TEXT.fullmatch(timeout) is None:
        raise _fail()
    seconds = float(timeout)
    if repr(seconds) != timeout:
        raise _fail()
    return ApprovedCheckApproval(
        approval_id=cast(str, fields_["approval_id"]),
        argv=tuple(cast(str, item) for item in _list(fields_["argv"], 32)),
        allow_network=_bool(fields_["allow_network"]),
        timeout_seconds=seconds,
        approval_commitment=cast(str, fields_["approval_commitment"]),
    )


def _encode_run_args(value: RunApprovedCheckArguments) -> dict[str, JsonValue]:
    return {
        "approval": _approval_wire(value.approval),
        "expected_subject_state_digest": value.expected_subject_state_digest,
        "handle": value.handle,
        "subject_state_digest": value.subject_state_digest,
    }


def _decode_run_args(source: dict[str, object]) -> RunApprovedCheckArguments:
    fields_ = _object(
        source,
        frozenset({"approval", "expected_subject_state_digest", "handle", "subject_state_digest"}),
    )
    return RunApprovedCheckArguments(
        _remote_handle(fields_["handle"]),
        _approval_from_wire(fields_["approval"]),
        _sha256(fields_["subject_state_digest"]),
        _optional_sha256(fields_["expected_subject_state_digest"]),
    )


_CHECK_RESULT_KEYS: Final = frozenset(
    {
        "approval_commitment",
        "duration_ms",
        "exit_status",
        "outcome",
        "output_bytes",
        "output_digest",
        "result_digest",
        "status",
        "subject_state_digest",
    }
)


def _encode_run(value: ApprovedCheckRun) -> JsonValue:
    if type(value) is not ApprovedCheckRun:
        raise _fail()
    result = value.result
    return {
        "output": None if value.output is None else _b64(value.output),
        "output_redacted": value.output_redacted,
        "result": {
            "approval_commitment": result.approval_commitment,
            "duration_ms": result.duration_ms,
            "exit_status": result.exit_status,
            "outcome": result.outcome.value,
            "output_bytes": result.output_bytes,
            "output_digest": result.output_digest,
            "result_digest": result.result_digest,
            "status": result.status.value,
            "subject_state_digest": result.subject_state_digest,
        },
    }


def _decode_run(value: object) -> ApprovedCheckRun:
    fields_ = _object(value, frozenset({"output", "output_redacted", "result"}))
    raw = _object(fields_["result"], _CHECK_RESULT_KEYS)
    status = ApprovedCheckStatus(cast(str, raw["status"]))
    outcome = ApprovedCheckOutcome(cast(str, raw["outcome"]))
    exit_status = cast(int | None, raw["exit_status"])
    output_digest = _optional_sha256(raw["output_digest"])
    output_bytes = cast(int, raw["output_bytes"])
    subject_state_digest = cast(str, raw["subject_state_digest"])
    approval_commitment = cast(str, raw["approval_commitment"])
    duration_ms = cast(int, raw["duration_ms"])
    result = ApprovedCheckResult(
        status=status,
        outcome=outcome,
        exit_status=exit_status,
        output_digest=output_digest,
        output_bytes=output_bytes,
        subject_state_digest=subject_state_digest,
        approval_commitment=approval_commitment,
        result_digest=cast(str, raw["result_digest"]),
        duration_ms=duration_ms,
    )
    # The digest must be the one the runner computes over exactly these fields.
    if result.result_digest != approved_check_result_digest(
        status,
        outcome,
        exit_status,
        output_digest,
        output_bytes,
        subject_state_digest,
        approval_commitment,
        duration_ms,
    ):
        raise _fail()
    output = fields_["output"]
    return ApprovedCheckRun(
        result,
        None if output is None else _unb64(output, MAX_APPROVED_CHECK_OUTPUT_BYTES),
        _bool(fields_["output_redacted"]),
    )


# --- the catalog ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WorkspaceOperationSpec[A, R]:
    """One operation: its name, family, codecs and byte bounds.

    ``encode_arguments``/``decode_result`` are the server's side, ``decode_arguments``/
    ``encode_result`` the agent's. Every method raises ``WorkspaceCodecError`` with a closed
    reason and nothing else; sizes are the canonical JSON bytes of the arguments object or the
    result value.
    """

    operation: WorkspaceOperation
    family: WorkspaceOperationFamily
    arguments_type: type[A]
    max_argument_bytes: int
    max_result_bytes: int
    _encode_arguments: Callable[[A], dict[str, JsonValue]] = field(repr=False)
    _decode_arguments: Callable[[dict[str, object]], A] = field(repr=False)
    _encode_result: Callable[[R], JsonValue] = field(repr=False)
    _decode_result: Callable[[object], R] = field(repr=False)
    _fit_result: Callable[[R, int], R] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for bound in (self.max_argument_bytes, self.max_result_bytes):
            if type(bound) is not int or not 1 <= bound <= MAX_WORKSPACE_PAYLOAD_BYTES:
                raise ValueError("workspace_operation_bound_invalid")

    def encode_arguments(self, value: A) -> dict[str, JsonValue]:
        if type(value) is not self.arguments_type:
            raise WorkspaceCodecError("arguments_invalid")
        try:
            wire = self._encode_arguments(value)
            size = _size(wire)
        except (TypeError, ValueError):
            raise WorkspaceCodecError("arguments_invalid") from None
        if size > self.max_argument_bytes:
            raise WorkspaceCodecError("arguments_too_large")
        return wire

    def decode_arguments(self, value: object) -> A:
        try:
            plain = _thaw(value)
            if _size(plain) > self.max_argument_bytes:
                raise WorkspaceCodecError("arguments_too_large")
            if type(plain) is not dict:
                raise _fail()
            decoded = self._decode_arguments(cast(dict[str, object], plain))
            # One spelling per value: the arguments must be exactly what the encoder writes.
            if self._encode_arguments(decoded) != plain:
                raise _fail()
            return decoded
        except WorkspaceCodecError:
            raise
        except (TypeError, ValueError, KeyError):
            raise WorkspaceCodecError("arguments_invalid") from None

    def encode_result(self, value: R) -> JsonValue:
        """The result's JSON; a listing that may outgrow a frame is cut honestly first."""

        try:
            if self._fit_result is not None:
                value = self._fit_result(value, self.max_result_bytes)
            wire = self._encode_result(value)
            size = _size(wire)
        except (TypeError, ValueError):
            raise WorkspaceCodecError("result_invalid") from None
        if size > self.max_result_bytes:
            raise WorkspaceCodecError("result_too_large")
        return wire

    def decode_result(self, value: object) -> R:
        try:
            plain = _thaw(value)
            if _size(plain) > self.max_result_bytes:
                raise WorkspaceCodecError("result_too_large")
            decoded = self._decode_result(plain)
            if self._encode_result(decoded) != plain:
                raise _fail()
            return decoded
        except WorkspaceCodecError:
            raise
        except (TypeError, ValueError, KeyError):
            raise WorkspaceCodecError("result_invalid") from None


def _fit_metadata_result(value: CheckChangeMetadata, max_bytes: int) -> CheckChangeMetadata:
    if type(value) is not CheckChangeMetadata:
        raise _fail()
    return _fit_metadata(value, max_bytes)


def _fit_line_counts_result(value: ChangeLineCounts, max_bytes: int) -> ChangeLineCounts:
    if type(value) is not ChangeLineCounts:
        raise _fail()
    return _fit_line_counts(value, max_bytes)


_SPECS: Final[tuple[WorkspaceOperationSpec[Any, Any], ...]] = (
    WorkspaceOperationSpec[WorkspaceOnlyArguments, TaskChangeBase](
        WorkspaceOperation.READ_TASK_BASE,
        "git",
        WorkspaceOnlyArguments,
        _KIB,
        4 * _MIB,
        _encode_workspace_only,
        _decode_workspace_only,
        _encode_task_base,
        _decode_task_base,
    ),
    WorkspaceOperationSpec[CaptureArguments, CheckChangeCapture](
        WorkspaceOperation.CAPTURE,
        "git",
        CaptureArguments,
        MAX_WORKSPACE_PAYLOAD_BYTES,
        4 * _MIB,
        _encode_capture,
        _decode_capture,
        _encode_check_change,
        _decode_check_change,
    ),
    WorkspaceOperationSpec[CaptureMetadataArguments, CheckChangeMetadata](
        WorkspaceOperation.CAPTURE_METADATA,
        "git",
        CaptureMetadataArguments,
        MAX_WORKSPACE_PAYLOAD_BYTES,
        MAX_WORKSPACE_PAYLOAD_BYTES,
        _encode_capture_metadata,
        _decode_capture_metadata,
        _encode_metadata,
        _decode_metadata,
        _fit_metadata_result,
    ),
    WorkspaceOperationSpec[ProbeRequestedPathsArguments, tuple[RequestedPathProbe, ...]](
        WorkspaceOperation.PROBE_REQUESTED_PATHS,
        "git",
        ProbeRequestedPathsArguments,
        _MIB,
        _MIB,
        _encode_probe,
        _decode_probe,
        _encode_probes,
        _decode_probes,
    ),
    WorkspaceOperationSpec[CountChangeLinesArguments, ChangeLineCounts](
        WorkspaceOperation.COUNT_CHANGE_LINES,
        "git",
        CountChangeLinesArguments,
        _MIB,
        MAX_WORKSPACE_PAYLOAD_BYTES,
        _encode_count,
        _decode_count,
        _encode_line_counts,
        _decode_line_counts,
        _fit_line_counts_result,
    ),
    WorkspaceOperationSpec[ClassifyUndeclaredReferencesArguments, tuple[tuple[int, int, str], ...]](
        WorkspaceOperation.CLASSIFY_UNDECLARED_REFERENCES,
        "git",
        ClassifyUndeclaredReferencesArguments,
        4 * _MIB,
        64 * _KIB,
        _encode_classify,
        _decode_classify,
        _encode_references,
        _decode_references,
    ),
    WorkspaceOperationSpec[ReadOutsideInputsArguments, OutsideInputsRead](
        WorkspaceOperation.READ_OUTSIDE_INPUTS,
        "reads",
        ReadOutsideInputsArguments,
        _MIB,
        _MIB + 64 * _KIB,
        _encode_outside,
        _decode_outside,
        _encode_outside_read,
        _decode_outside_read,
    ),
    WorkspaceOperationSpec[SnapshotOutsideInputsArguments, OutsideSnapshotsRead](
        WorkspaceOperation.SNAPSHOT_OUTSIDE_INPUTS,
        "reads",
        SnapshotOutsideInputsArguments,
        _MIB,
        MAX_WORKSPACE_PAYLOAD_BYTES,
        _encode_snapshot,
        _decode_snapshot,
        _encode_snapshots_read,
        _decode_snapshots_read,
    ),
    WorkspaceOperationSpec[ReadDeclaredTestArguments, bytes | None](
        WorkspaceOperation.READ_DECLARED_TEST,
        "reads",
        ReadDeclaredTestArguments,
        256 * _KIB,
        2 * _MIB,
        _encode_declared,
        _decode_declared,
        _encode_optional_bytes,
        _decode_optional_bytes,
    ),
    WorkspaceOperationSpec[ReadTextBeneathArguments, tuple[bytes, int] | None](
        WorkspaceOperation.READ_TEXT_BENEATH,
        "reads",
        ReadTextBeneathArguments,
        256 * _KIB,
        2 * _MIB,
        _encode_text_beneath,
        _decode_text_beneath,
        _encode_text_read,
        _decode_text_read,
    ),
    WorkspaceOperationSpec[ListBeneathArguments, tuple[tuple[tuple[str, bool], ...], bool] | None](
        WorkspaceOperation.LIST_BENEATH,
        "reads",
        ListBeneathArguments,
        256 * _KIB,
        2 * _MIB,
        _encode_list_beneath,
        _decode_list_beneath,
        _encode_listing,
        _decode_listing,
    ),
    WorkspaceOperationSpec[LstatCandidatesArguments, tuple[LstatFacts | None, ...]](
        WorkspaceOperation.LSTAT_CANDIDATES,
        "reads",
        LstatCandidatesArguments,
        4 * _MIB,
        256 * _KIB,
        _encode_lstat_args,
        _decode_lstat_args,
        _encode_lstat,
        _decode_lstat,
    ),
    WorkspaceOperationSpec[OpenWorkspaceArguments, str](
        WorkspaceOperation.OPEN_WORKSPACE,
        "observation",
        OpenWorkspaceArguments,
        _KIB,
        _KIB,
        _encode_open,
        _decode_open,
        _encode_remote_handle,
        _decode_remote_handle,
    ),
    WorkspaceOperationSpec[WorkspaceOnlyArguments, CheckPolicyRead](
        WorkspaceOperation.LOAD_CHECK_POLICY,
        "observation",
        WorkspaceOnlyArguments,
        _KIB,
        512 * _KIB,
        _encode_workspace_only,
        _decode_workspace_only,
        _encode_policy,
        _decode_policy,
    ),
    WorkspaceOperationSpec[SubjectStateCaptureArguments, SubjectStateCaptureResult](
        WorkspaceOperation.SUBJECT_STATE_CAPTURE,
        "observation",
        SubjectStateCaptureArguments,
        _KIB,
        16 * _KIB,
        _encode_subject_args,
        _decode_subject_args,
        _encode_subject_result,
        _decode_subject_result,
    ),
    WorkspaceOperationSpec[ListChangedPathsArguments, tuple[str, ...]](
        WorkspaceOperation.LIST_CHANGED_PATHS,
        "observation",
        ListChangedPathsArguments,
        _KIB,
        4 * _MIB,
        _encode_changed_args,
        _decode_changed_args,
        _encode_changed,
        _decode_changed,
    ),
    WorkspaceOperationSpec[InspectArguments, WorkspaceInspectResult](
        WorkspaceOperation.INSPECT,
        "observation",
        InspectArguments,
        256 * _KIB,
        2 * _MIB,
        _encode_inspect_args,
        _decode_inspect_args,
        _encode_inspect,
        _decode_inspect,
    ),
    WorkspaceOperationSpec[RunApprovedCheckArguments, ApprovedCheckRun](
        WorkspaceOperation.RUN_APPROVED_CHECK,
        "observation",
        RunApprovedCheckArguments,
        64 * _KIB,
        256 * _KIB,
        _encode_run_args,
        _decode_run_args,
        _encode_run,
        _decode_run,
    ),
)

WORKSPACE_OPERATION_CATALOG: Final[
    Mapping[WorkspaceOperation, WorkspaceOperationSpec[Any, Any]]
] = {spec.operation: spec for spec in _SPECS}
WORKSPACE_OPERATION_FAMILIES: Final[Mapping[str, WorkspaceOperationFamily]] = {
    spec.operation.value: spec.family for spec in _SPECS
}
if set(WORKSPACE_OPERATION_CATALOG) != set(WorkspaceOperation) or len(_SPECS) != len(
    WorkspaceOperation
):
    raise RuntimeError("workspace_operation_catalog_incomplete")


def operation_spec(operation: object) -> WorkspaceOperationSpec[Any, Any] | None:
    """The catalog entry for an operation name or member, or None (``operation_unknown``)."""

    if type(operation) is not str and type(operation) is not WorkspaceOperation:
        return None
    try:
        member = WorkspaceOperation(operation)
    except ValueError:
        return None
    return WORKSPACE_OPERATION_CATALOG[member]
