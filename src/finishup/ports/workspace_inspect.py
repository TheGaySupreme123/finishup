"""Descriptor-safe, bounded workspace artifact inspection boundary."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final, Protocol

from finishup.ports.subject_state import LocalWorkspaceHandle
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "MAX_INSPECT_EXCERPT_BYTES",
    "MAX_INSPECT_FILES",
    "MAX_INSPECT_PATH_BYTES",
    "InspectedArtifact",
    "WorkspaceInspectCommand",
    "WorkspaceInspectLimitation",
    "WorkspaceInspectPort",
    "WorkspaceInspectResult",
    "WorkspaceInspectStatus",
]

MAX_INSPECT_FILES: Final = 64
MAX_INSPECT_EXCERPT_BYTES: Final = 4_096
MAX_INSPECT_PATH_BYTES: Final = 512


class WorkspaceInspectStatus(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    INSPECTED = "inspected"
    REJECTED = "rejected"
    PARTIAL = "partial"


class WorkspaceInspectLimitation(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    UNSAFE_ROOT = "unsafe_root"
    PATH_OUT_OF_SCOPE = "path_out_of_scope"
    SYMLINK_ESCAPE = "symlink_escape"
    OVERSIZED_CONTENT = "oversized_content"
    FILE_LIMIT_EXCEEDED = "file_limit_exceeded"
    NOT_A_FILE = "not_a_file"
    READ_FAILED = "read_failed"
    EMPTY_SELECTION = "empty_selection"


@dataclass(frozen=True, slots=True)
class InspectedArtifact:
    """One relative-path structural digest with an optional size-capped excerpt."""

    relative_path: str
    content_digest: str
    excerpt: bytes
    excerpt_truncated: bool
    byte_length: int

    def __post_init__(self) -> None:
        if (
            type(self.relative_path) is not str
            or not self.relative_path
            or len(self.relative_path.encode("utf-8")) > MAX_INSPECT_PATH_BYTES
            or self.relative_path.startswith(("/", "\\"))
            or ".." in self.relative_path.split("/")
            or "\x00" in self.relative_path
        ):
            raise ProtocolValueError("invalid_workspace_inspect")
        if (
            type(self.content_digest) is not str
            or not self.content_digest.startswith("sha256:")
            or len(self.content_digest) != 71
        ):
            raise ProtocolValueError("invalid_workspace_inspect")
        if type(self.excerpt) is not bytes or len(self.excerpt) > MAX_INSPECT_EXCERPT_BYTES:
            raise ProtocolValueError("invalid_workspace_inspect")
        if type(self.excerpt_truncated) is not bool:
            raise ProtocolValueError("invalid_workspace_inspect")
        if type(self.byte_length) is not int or not 0 <= self.byte_length <= 67_108_864:
            raise ProtocolValueError("invalid_workspace_inspect")


@dataclass(frozen=True, slots=True)
class WorkspaceInspectCommand:
    workspace: LocalWorkspaceHandle
    relative_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.workspace) is not LocalWorkspaceHandle or not self.workspace.is_validated():
            raise ProtocolValueError("invalid_workspace_inspect")
        if type(self.relative_paths) is not tuple:
            raise ProtocolValueError("invalid_workspace_inspect")
        if not 1 <= len(self.relative_paths) <= MAX_INSPECT_FILES:
            raise ProtocolValueError("invalid_workspace_inspect")
        seen: set[str] = set()
        for path in self.relative_paths:
            if (
                type(path) is not str
                or not path
                or path.startswith(("/", "\\"))
                or ".." in path.split("/")
                or "\x00" in path
                or len(path.encode("utf-8")) > MAX_INSPECT_PATH_BYTES
            ):
                raise ProtocolValueError("invalid_workspace_inspect")
            if path in seen:
                raise ProtocolValueError("invalid_workspace_inspect")
            seen.add(path)


@dataclass(frozen=True, slots=True)
class WorkspaceInspectResult:
    status: WorkspaceInspectStatus
    artifacts: tuple[InspectedArtifact, ...]
    limitations: tuple[WorkspaceInspectLimitation, ...]
    selection_digest: str | None

    def __post_init__(self) -> None:
        if type(self.status) is not WorkspaceInspectStatus:
            raise ProtocolValueError("invalid_workspace_inspect")
        if type(self.artifacts) is not tuple or any(
            type(item) is not InspectedArtifact for item in self.artifacts
        ):
            raise ProtocolValueError("invalid_workspace_inspect")
        if len(self.artifacts) > MAX_INSPECT_FILES:
            raise ProtocolValueError("invalid_workspace_inspect")
        if type(self.limitations) is not tuple or any(
            type(item) is not WorkspaceInspectLimitation for item in self.limitations
        ):
            raise ProtocolValueError("invalid_workspace_inspect")
        values = tuple(item.value for item in self.limitations)
        if values != tuple(sorted(set(values), key=str.encode)):
            raise ProtocolValueError("invalid_workspace_inspect")
        if self.status is WorkspaceInspectStatus.INSPECTED:
            if not self.artifacts or self.limitations or self.selection_digest is None:
                raise ProtocolValueError("invalid_workspace_inspect")
        elif self.status is WorkspaceInspectStatus.REJECTED:
            if self.artifacts or not self.limitations or self.selection_digest is not None:
                raise ProtocolValueError("invalid_workspace_inspect")
        else:
            if self.selection_digest is None or not self.limitations:
                raise ProtocolValueError("invalid_workspace_inspect")
        if self.selection_digest is not None and (
            type(self.selection_digest) is not str
            or not self.selection_digest.startswith("sha256:")
            or len(self.selection_digest) != 71
        ):
            raise ProtocolValueError("invalid_workspace_inspect")


class WorkspaceInspectPort(Protocol):
    """Read bounded relative artifacts under a consented workspace root only."""

    def inspect(self, command: WorkspaceInspectCommand) -> WorkspaceInspectResult: ...
