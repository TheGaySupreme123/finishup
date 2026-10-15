"""Structural, content-withholding subject-state capture boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol, Self, final

from finishup.domain.values import SubjectStateRef
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "MAX_SUBJECT_STATE_FILES",
    "MAX_SUBJECT_STATE_HASH_BYTES",
    "LocalWorkspaceHandle",
    "SubjectStateBound",
    "SubjectStateCaptureCommand",
    "SubjectStateCapturePort",
    "SubjectStateCaptureResult",
    "SubjectStateFormat",
    "SubjectStateLimitation",
    "SubjectStateLimitDetail",
    "SubjectStateStatus",
]

MAX_SUBJECT_STATE_HASH_BYTES: Final = 67_108_864
MAX_SUBJECT_STATE_FILES: Final = 10_000


class SubjectStateStatus(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    CAPTURED = "captured"
    STATE_NOT_OBSERVED = "state_not_observed"
    UNSUPPORTED = "unsupported"
    CHANGED_DURING_CAPTURE = "changed_during_capture"


class SubjectStateFormat(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    GIT_STRUCTURAL_V1 = "git_structural_v1"


class SubjectStateLimitation(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    NOT_GIT = "not_git"
    UNSAFE_ROOT = "unsafe_root"
    SUBMODULE_PRESENT = "submodule_present"
    SYMLINK_UNSUPPORTED = "symlink_unsupported"
    OBJECT_FORMAT_UNSUPPORTED = "object_format_unsupported"
    GIT_CONFIG_LIMIT_EXCEEDED = "git_config_limit_exceeded"
    READ_LIMIT_EXCEEDED = "read_limit_exceeded"
    FILE_LIMIT_EXCEEDED = "file_limit_exceeded"
    GIT_FAILED = "git_failed"
    INPUT_CHANGED = "input_changed"


class SubjectStateBound(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    """Which walk/bound a ``FILE_LIMIT_EXCEEDED`` trip counted against.

    Sibling detail for ``SubjectStateLimitation``, not a replacement: the closed
    limitation vocabulary stays pinned, this only names which bound tripped.
    """

    UNSAFE_TREE_ENTRIES = "unsafe_tree_entries"
    UNTRACKED_FILE_COUNT = "untracked_file_count"


@dataclass(frozen=True, slots=True)
class SubjectStateLimitDetail:
    """Observed count and limit for one bound trip. Carries no content, only integers."""

    bound: SubjectStateBound
    observed: int
    limit: int

    def __post_init__(self) -> None:
        if type(self.bound) is not SubjectStateBound:
            raise ProtocolValueError("invalid_subject_state")
        if type(self.observed) is not int or self.observed < 0:
            raise ProtocolValueError("invalid_subject_state")
        if type(self.limit) is not int or self.limit < 0:
            raise ProtocolValueError("invalid_subject_state")
        if self.observed <= self.limit:
            raise ProtocolValueError("invalid_subject_state")


@final
class LocalWorkspaceHandle:
    """Opaque, adapter-created descriptor for one validated local workspace.

    The public constructor is deliberately unavailable. The client-local adapter creates a handle
    only after completing its no-follow path checks and retains the private descriptor payload.
    """

    __slots__ = ("__descriptor", "__validated")

    def __new__(cls) -> Self:
        raise TypeError("local_workspace_handle_factory_required")

    @classmethod
    def _from_validated_descriptor(cls, descriptor: object) -> Self:
        """Create a handle after adapter-owned validation.

        This is an implementation seam for the sole trusted local adapter, not a wire codec or a
        validation bypass: the adapter remains responsible for proving the descriptor safe.
        """

        if descriptor is None:
            raise ValueError("local_workspace_descriptor_invalid")
        instance = object.__new__(cls)
        object.__setattr__(instance, "_LocalWorkspaceHandle__descriptor", descriptor)
        object.__setattr__(instance, "_LocalWorkspaceHandle__validated", True)
        return instance

    def _validated_descriptor(self) -> object:
        """Return the opaque payload to the trusted client-local adapter only."""

        if not self.is_validated():
            raise ValueError("local_workspace_handle_invalid")
        return self.__descriptor

    def is_validated(self) -> bool:
        try:
            return self.__validated is True and self.__descriptor is not None
        except AttributeError:
            return False

    def __repr__(self) -> str:
        return "LocalWorkspaceHandle(<redacted>)"

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("local_workspace_handle_not_serializable")


@dataclass(frozen=True, slots=True)
class SubjectStateCaptureCommand:
    workspace: LocalWorkspaceHandle
    expected_format: SubjectStateFormat

    def __post_init__(self) -> None:
        if type(self.workspace) is not LocalWorkspaceHandle or not self.workspace.is_validated():
            raise ProtocolValueError("invalid_subject_state")
        if type(self.expected_format) is not SubjectStateFormat:
            raise ProtocolValueError("invalid_subject_state")


@dataclass(frozen=True, slots=True)
class SubjectStateCaptureResult:
    status: SubjectStateStatus
    subject_state: SubjectStateRef | None
    format: SubjectStateFormat
    limitations: tuple[SubjectStateLimitation, ...]
    bytes_hashed: int
    files_hashed: int
    limit_detail: tuple[SubjectStateLimitDetail, ...] = ()

    def __post_init__(self) -> None:
        if type(self.status) is not SubjectStateStatus:
            raise ProtocolValueError("invalid_subject_state")
        if type(self.format) is not SubjectStateFormat:
            raise ProtocolValueError("invalid_subject_state")
        if type(self.limitations) is not tuple or any(
            type(value) is not SubjectStateLimitation for value in self.limitations
        ):
            raise ProtocolValueError("invalid_subject_state")
        limitation_values = tuple(value.value for value in self.limitations)
        if limitation_values != tuple(sorted(set(limitation_values), key=str.encode)):
            raise ProtocolValueError("invalid_subject_state")
        if type(self.limit_detail) is not tuple or any(
            type(value) is not SubjectStateLimitDetail for value in self.limit_detail
        ):
            raise ProtocolValueError("invalid_subject_state")
        if self.limit_detail and SubjectStateLimitation.FILE_LIMIT_EXCEEDED not in self.limitations:
            raise ProtocolValueError("invalid_subject_state")
        if (
            type(self.bytes_hashed) is not int
            or not 0 <= self.bytes_hashed <= MAX_SUBJECT_STATE_HASH_BYTES
            or type(self.files_hashed) is not int
            or not 0 <= self.files_hashed <= MAX_SUBJECT_STATE_FILES
        ):
            raise ProtocolValueError("invalid_subject_state")

        if self.status is SubjectStateStatus.CAPTURED:
            if (
                type(self.subject_state) is not SubjectStateRef
                or self.limitations
                or self.limit_detail
            ):
                raise ProtocolValueError("invalid_subject_state")
            state = self.subject_state
            if (
                state.tree_digest is None
                or state.diff_digest is None
                or state.described_state != SubjectStateFormat.GIT_STRUCTURAL_V1.value
                or self.format is not SubjectStateFormat.GIT_STRUCTURAL_V1
            ):
                raise ProtocolValueError("invalid_subject_state")
        else:
            if self.subject_state is not None or not self.limitations:
                raise ProtocolValueError("invalid_subject_state")
            if len(self.limit_detail) > len(self.limitations):
                raise ProtocolValueError("invalid_subject_state")
            if (
                self.status is SubjectStateStatus.CHANGED_DURING_CAPTURE
                and SubjectStateLimitation.INPUT_CHANGED not in self.limitations
            ):
                raise ProtocolValueError("invalid_subject_state")


class SubjectStateCapturePort(Protocol):
    """Capture a bounded comparable state without returning repository content."""

    def capture(self, command: SubjectStateCaptureCommand) -> SubjectStateCaptureResult: ...
