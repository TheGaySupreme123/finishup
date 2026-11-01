"""Descriptor-safe bounded workspace artifact inspection adapter."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from finishup.ports.subject_state import LocalWorkspaceHandle
from finishup.ports.workspace_inspect import (
    MAX_INSPECT_EXCERPT_BYTES,
    MAX_INSPECT_FILES,
    InspectedArtifact,
    WorkspaceInspectCommand,
    WorkspaceInspectLimitation,
    WorkspaceInspectResult,
    WorkspaceInspectStatus,
)
from finishup.protocol.canonical import canonical_digest

__all__ = [
    "WORKSPACE_INSPECT_FORMAT",
    "LocalWorkspaceInspectAdapter",
    "open_inspect_workspace",
]

WORKSPACE_INSPECT_FORMAT: Final = "yoetz.workspace-inspect/1"
_MAX_FILE_BYTES: Final = 1_048_576
_MAX_SYMLINK_DEPTH: Final = 8
_READ_CHUNK: Final = 65_536
_DOMAIN: Final = b"yoetz/workspace-inspect/v1\x00"


@dataclass(slots=True)
class _InspectRoot:
    root: Path
    descriptor: int
    device: int
    inode: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


class _InspectFailure(Exception):
    __slots__ = ("limitation",)

    def __init__(self, limitation: WorkspaceInspectLimitation) -> None:
        self.limitation = limitation
        super().__init__(limitation.value)


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _same_file_snapshot(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    )


def _lexically_safe_absolute(path: Path) -> Path:
    if path.is_absolute() is False:
        path = path.resolve(strict=False)
    text = os.fspath(path)
    if "\x00" in text:
        raise ValueError("unsafe_root")
    return Path(os.path.abspath(text))


def _platform_supports_boundary() -> bool:
    return (
        os.open in os.supports_dir_fd
        and hasattr(os, "O_NOFOLLOW")
        and os.O_NOFOLLOW != 0
        and os.stat in os.supports_dir_fd
        and os.readlink in os.supports_dir_fd
    )


def open_inspect_workspace(path: Path) -> LocalWorkspaceHandle:
    """Validate one explicit local workspace root for inspection.

    The returned handle retains an authenticated root directory descriptor for its
    lifetime. Inspection opens descendants descriptor-relatively with no-follow
    semantics against that descriptor; callers must not close it.
    """

    if not _platform_supports_boundary():
        raise ValueError("unsafe_root")
    root = _lexically_safe_absolute(path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe_root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(os.fspath(root), flags)
        facts = os.fstat(descriptor)
        if not stat.S_ISDIR(facts.st_mode):
            raise ValueError("unsafe_root")
        payload = _InspectRoot(
            root=root,
            descriptor=descriptor,
            device=facts.st_dev,
            inode=facts.st_ino,
        )
        descriptor = -1
        return LocalWorkspaceHandle._from_validated_descriptor(  # pyright: ignore[reportPrivateUsage]
            payload
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _split_relative_components(relative: str) -> list[str] | None:
    components = relative.split("/")
    if not components or any(part in {"", ".", ".."} for part in components):
        return None
    if any("\x00" in part for part in components):
        return None
    return components


def _join_symlink_target(parent_components: list[str], target: str) -> list[str] | None:
    """Lexically join a relative symlink target onto its parent path under the root.

    Pure string work: no filesystem access. Absolute targets and climbs above the
    root return None (caller maps to SYMLINK_ESCAPE).
    """

    if not target or target.startswith("/") or "\x00" in target:
        return None
    parts = list(parent_components)
    for part in target.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return parts


def _component_is_symlink(parent_fd: int, component: str) -> bool:
    try:
        facts = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISLNK(facts.st_mode)


class LocalWorkspaceInspectAdapter:
    """Read only relative files under a consented workspace; never emit absolute paths."""

    def inspect(self, command: WorkspaceInspectCommand) -> WorkspaceInspectResult:
        if type(command) is not WorkspaceInspectCommand:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.UNSAFE_ROOT,),
                None,
            )
        try:
            descriptor = command.workspace._validated_descriptor()  # pyright: ignore[reportPrivateUsage]
        except ValueError:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.UNSAFE_ROOT,),
                None,
            )
        root_identity = self._root_from_descriptor(descriptor)
        if root_identity is None:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.UNSAFE_ROOT,),
                None,
            )
        root_fd, device, inode = root_identity
        try:
            facts = os.fstat(root_fd)
        except OSError:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.UNSAFE_ROOT,),
                None,
            )
        if not stat.S_ISDIR(facts.st_mode) or facts.st_dev != device or facts.st_ino != inode:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.UNSAFE_ROOT,),
                None,
            )

        artifacts: list[InspectedArtifact] = []
        limitations: set[WorkspaceInspectLimitation] = set()
        if len(command.relative_paths) > MAX_INSPECT_FILES:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.FILE_LIMIT_EXCEEDED,),
                None,
            )

        for relative in command.relative_paths:
            artifact, limitation = self._inspect_one(root_fd, relative)
            if artifact is not None:
                artifacts.append(artifact)
            if limitation is not None:
                limitations.add(limitation)

        if not artifacts and limitations:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                tuple(sorted(limitations, key=lambda item: item.value.encode("ascii"))),
                None,
            )
        if not artifacts:
            return WorkspaceInspectResult(
                WorkspaceInspectStatus.REJECTED,
                (),
                (WorkspaceInspectLimitation.EMPTY_SELECTION,),
                None,
            )

        selection = canonical_digest(
            {
                "format": WORKSPACE_INSPECT_FORMAT,
                "artifacts": tuple(
                    {
                        "relative_path": item.relative_path,
                        "content_digest": item.content_digest,
                        "byte_length": item.byte_length,
                        "excerpt_truncated": item.excerpt_truncated,
                    }
                    for item in artifacts
                ),
            }
        )
        ordered_limitations = tuple(
            sorted(limitations, key=lambda item: item.value.encode("ascii"))
        )
        status = (
            WorkspaceInspectStatus.PARTIAL
            if ordered_limitations
            else WorkspaceInspectStatus.INSPECTED
        )
        return WorkspaceInspectResult(status, tuple(artifacts), ordered_limitations, selection)

    def _root_from_descriptor(self, descriptor: object) -> tuple[int, int, int] | None:
        if type(descriptor) is _InspectRoot:
            if type(descriptor.descriptor) is not int or descriptor.descriptor < 0:
                return None
            return descriptor.descriptor, descriptor.device, descriptor.inode
        root = getattr(descriptor, "root", None)
        fd = getattr(descriptor, "descriptor", None)
        device = getattr(descriptor, "device", None)
        inode = getattr(descriptor, "inode", None)
        if (
            not isinstance(root, Path)
            or type(fd) is not int
            or fd < 0
            or type(device) is not int
            or type(inode) is not int
        ):
            return None
        return fd, device, inode

    def _inspect_one(
        self, root_fd: int, relative: str
    ) -> tuple[InspectedArtifact | None, WorkspaceInspectLimitation | None]:
        components = _split_relative_components(relative)
        if components is None:
            return None, WorkspaceInspectLimitation.PATH_OUT_OF_SCOPE
        fd = -1
        try:
            fd = self._open_relative(root_fd, components)
            data = self._read_regular_file(fd)
        except _InspectFailure as exc:
            return None, exc.limitation
        except OSError:
            return None, WorkspaceInspectLimitation.READ_FAILED
        finally:
            if fd >= 0:
                os.close(fd)
        truncated = len(data) > MAX_INSPECT_EXCERPT_BYTES
        excerpt = data[:MAX_INSPECT_EXCERPT_BYTES]
        digest = _sha256(_DOMAIN + relative.encode("utf-8") + b"\x00" + data)
        return (
            InspectedArtifact(
                relative_path=relative,
                content_digest=digest,
                excerpt=excerpt,
                excerpt_truncated=truncated,
                byte_length=len(data),
            ),
            None,
        )

    def _open_relative(self, root_fd: int, components: list[str]) -> int:
        """Open the final component descriptor-relatively from ``root_fd``.

        Intermediate directory and final-component symlinks are resolved only within
        the root, with a shared resolution budget of ``_MAX_SYMLINK_DEPTH``. The
        returned fd is owned by the caller; intermediate fds are closed before return.
        """

        if not components:
            raise _InspectFailure(WorkspaceInspectLimitation.PATH_OUT_OF_SCOPE)
        remaining_symlinks = _MAX_SYMLINK_DEPTH
        path_components = list(components)
        base_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW

        while True:
            parent_fd = root_fd
            owned: list[int] = []
            try:
                for index, component in enumerate(path_components):
                    is_final = index == len(path_components) - 1
                    flags = base_flags if is_final else base_flags | os.O_DIRECTORY
                    try:
                        new_fd = os.open(component, flags, dir_fd=parent_fd)
                    except OSError as exc:
                        if _component_is_symlink(parent_fd, component):
                            if remaining_symlinks <= 0:
                                raise _InspectFailure(
                                    WorkspaceInspectLimitation.SYMLINK_ESCAPE
                                ) from exc
                            try:
                                target = os.readlink(component, dir_fd=parent_fd)
                            except OSError as read_exc:
                                raise _InspectFailure(
                                    WorkspaceInspectLimitation.SYMLINK_ESCAPE
                                ) from read_exc
                            if os.path.isabs(target):
                                raise _InspectFailure(
                                    WorkspaceInspectLimitation.SYMLINK_ESCAPE
                                ) from exc
                            joined = _join_symlink_target(path_components[:index], target)
                            if joined is None:
                                raise _InspectFailure(
                                    WorkspaceInspectLimitation.SYMLINK_ESCAPE
                                ) from exc
                            remaining_symlinks -= 1
                            path_components = joined + path_components[index + 1 :]
                            if not path_components:
                                raise _InspectFailure(
                                    WorkspaceInspectLimitation.NOT_A_FILE
                                ) from exc
                            break
                        if exc.errno in {errno.ENOENT, errno.ENOTDIR}:
                            raise _InspectFailure(WorkspaceInspectLimitation.NOT_A_FILE) from exc
                        raise _InspectFailure(WorkspaceInspectLimitation.READ_FAILED) from exc
                    if is_final:
                        for intermediate in owned:
                            os.close(intermediate)
                        owned.clear()
                        return new_fd
                    owned.append(new_fd)
                    parent_fd = new_fd
                else:
                    # for-loop completed without opening a final component.
                    raise _InspectFailure(WorkspaceInspectLimitation.NOT_A_FILE)
            finally:
                for intermediate in owned:
                    try:
                        os.close(intermediate)
                    except OSError:
                        pass

    def _read_regular_file(self, fd: int) -> bytes:
        try:
            before = os.fstat(fd)
        except OSError as exc:
            raise _InspectFailure(WorkspaceInspectLimitation.READ_FAILED) from exc
        if not stat.S_ISREG(before.st_mode):
            raise _InspectFailure(WorkspaceInspectLimitation.NOT_A_FILE)
        if before.st_size > _MAX_FILE_BYTES:
            raise _InspectFailure(WorkspaceInspectLimitation.OVERSIZED_CONTENT)

        chunks: list[bytes] = []
        total = 0
        limit = _MAX_FILE_BYTES + 1
        try:
            while total < limit:
                chunk = os.read(fd, min(_READ_CHUNK, limit - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except OSError as exc:
            raise _InspectFailure(WorkspaceInspectLimitation.READ_FAILED) from exc
        if total > _MAX_FILE_BYTES:
            raise _InspectFailure(WorkspaceInspectLimitation.OVERSIZED_CONTENT)
        try:
            after = os.fstat(fd)
        except OSError as exc:
            raise _InspectFailure(WorkspaceInspectLimitation.READ_FAILED) from exc
        if total != before.st_size or not _same_file_snapshot(before, after):
            raise _InspectFailure(WorkspaceInspectLimitation.READ_FAILED)
        return b"".join(chunks)
