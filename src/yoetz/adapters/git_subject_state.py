"""Bounded, read-only, content-withholding Git structural-state capture."""

from __future__ import annotations

import hashlib
import math
import os
import selectors
import shutil
import stat
import struct
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from yoetz.adapters.git_rev_parse import absolute_rev_parse_path
from yoetz.adapters.git_version import require_supported_git
from yoetz.config.foreign_write import writable_by_others
from yoetz.domain.values import SubjectStateRef
from yoetz.ports.subject_state import (
    MAX_SUBJECT_STATE_FILES,
    MAX_SUBJECT_STATE_HASH_BYTES,
    LocalWorkspaceHandle,
    SubjectStateBound,
    SubjectStateCaptureCommand,
    SubjectStateCaptureResult,
    SubjectStateFormat,
    SubjectStateLimitation,
    SubjectStateLimitDetail,
    SubjectStateStatus,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest

__all__ = [
    "GIT_SUBJECT_STATE_FORMAT",
    "GitStateComponents",
    "GitOutputTruncated",
    "GitSubjectStateAdapter",
    "discover_workspace_root",
    "list_changed_relative_paths",
    "local_workspace_root",
    "open_local_workspace",
    "run_read_only_git",
]

GIT_SUBJECT_STATE_FORMAT: Final = "yoetz.git-subject-state/1"

_FORMAT_TOKEN: Final = SubjectStateFormat.GIT_STRUCTURAL_V1.value
_GIT_TIMEOUT_SECONDS: Final = 10.0
_STDERR_LIMIT: Final = 16_384
_GIT_CONFIG_LIMIT: Final = 1_048_576
_COMMAND_OUTPUT_LIMIT: Final = MAX_SUBJECT_STATE_HASH_BYTES + 1
_PATH_OUTPUT_LIMIT: Final = 8_388_608
_READ_CHUNK: Final = 65_536
_UNTRACKED_DOMAIN: Final = b"yoetz/git-untracked/v1\0"
_INDEX_DOMAIN: Final = b"yoetz/git-index-delta/v1\0"
_WORKTREE_DOMAIN: Final = b"yoetz/git-worktree-delta/v1\0"
_STATUS_DOMAIN: Final = b"yoetz/git-snapshot-identity/v1\0"
_U32: Final = struct.Struct(">I")
_U64: Final = struct.Struct(">Q")
_GIT_SAFE_PREFIX: Final = (
    "-c",
    "alias.diff=!false",
    "-c",
    "core.filemode=true",
    "-c",
    # Empty disables fsmonitor on every supported Git. ``false`` does only from Git 2.36; an
    # older Git runs it as the fsmonitor hook command (``git_version``).
    "core.fsmonitor=",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "core.excludesFile=/dev/null",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "diff.external=",
)
_DIFF_ARGS: Final = (
    "--binary",
    "--full-index",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--no-renames",
    "--src-prefix=a/",
    "--dst-prefix=b/",
)


@dataclass(frozen=True, slots=True)
class GitStateComponents:
    """Canonical private component set; never returned from ``capture``."""

    object_format: Literal["sha1", "sha256"]
    head_state: str
    index_digest: str
    worktree_digest: str
    untracked_digest: str

    def __post_init__(self) -> None:
        if self.object_format not in {"sha1", "sha256"}:
            raise ValueError("object_format_unsupported")
        expected_length = 40 if self.object_format == "sha1" else 64
        if self.head_state != "unborn" and (
            len(self.head_state) != expected_length
            or any(character not in "0123456789abcdef" for character in self.head_state)
        ):
            raise ValueError("git_head_invalid")
        for digest in (self.index_digest, self.worktree_digest, self.untracked_digest):
            if (
                type(digest) is not str
                or len(digest) != 71
                or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])
            ):
                raise ValueError("git_component_digest_invalid")


@dataclass(slots=True)
class _WorkspaceDescriptor:
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


@dataclass(frozen=True, slots=True)
class _SnapshotIdentity:
    object_format: Literal["sha1", "sha256"]
    head_state: str
    status_digest: bytes


@dataclass(frozen=True, slots=True)
class _CaptureCounts:
    bytes_hashed: int
    files_hashed: int


class _CaptureFailure(Exception):
    __slots__ = ("detail", "limitation", "status")

    def __init__(
        self,
        limitation: SubjectStateLimitation,
        status: SubjectStateStatus = SubjectStateStatus.STATE_NOT_OBSERVED,
        *,
        detail: SubjectStateLimitDetail | None = None,
    ) -> None:
        self.limitation = limitation
        self.status = status
        self.detail = detail
        super().__init__(limitation.value)


class _GitProcessFailure(Exception):
    __slots__ = ("returncode",)

    def __init__(self, returncode: int | None = None) -> None:
        self.returncode = returncode
        super().__init__("git_failed")


class _OutputLimit(Exception):
    def __init__(self, prefix: bytes = b"") -> None:
        super().__init__("git_output_limit")
        # Only set when the caller asked for it: the stdout bytes that fit before the limit.
        self.prefix = prefix


class GitOutputTruncated(ValueError):
    """Stdout exceeded its limit; ``prefix`` holds the stdout bytes read before it (ADR-031).

    Raised only by ``run_read_only_git(..., keep_prefix_on_limit=True)``. It is still a
    ``ValueError("git_output_limit")``, so callers that ignore the prefix see the usual error.
    """

    def __init__(self, prefix: bytes) -> None:
        super().__init__("git_output_limit")
        self.prefix = prefix


@dataclass(slots=True)
class _GitRunner:
    executable: Path
    timeout_seconds: float

    def run(
        self,
        root: Path,
        arguments: Sequence[str],
        *,
        stdout_limit: int,
        accepted_returncodes: frozenset[int] = frozenset({0}),
        keep_prefix_on_limit: bool = False,
    ) -> tuple[int, bytearray]:
        argv = (os.fspath(self.executable), *_GIT_SAFE_PREFIX, *arguments)
        # ``GIT_CONFIG_GLOBAL`` exists only since Git 2.32. An older Git reads its global
        # configuration from ``$HOME/.gitconfig`` and ``$XDG_CONFIG_HOME/git/config`` instead,
        # so both point at ``os.devnull``: a ``HOME`` naming the workspace would have made a
        # ``.gitconfig`` committed to the repository (a filter driver, say) Git's global
        # configuration. A ``~`` in a repository's path settings expands under ``os.devnull``
        # and names nothing.
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": os.devnull,
            "LANG": "C",
            "LC_ALL": "C",
            "PAGER": "cat",
            "PATH": os.defpath,
            "XDG_CONFIG_HOME": os.devnull,
        }
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                argv,
                cwd=root,
                env=environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            stdout, stderr = _bounded_communicate(
                process,
                stdout_limit=stdout_limit,
                stderr_limit=_STDERR_LIMIT,
                timeout_seconds=self.timeout_seconds,
                keep_prefix_on_limit=keep_prefix_on_limit,
            )
            _overwrite(stderr)
            if process.returncode not in accepted_returncodes:
                raise _GitProcessFailure(process.returncode)
            return cast(int, process.returncode), stdout
        except _OutputLimit:
            if process is not None:
                _terminate(process)
            raise
        except _GitProcessFailure:
            if process is not None:
                _terminate(process)
            raise
        except (KeyboardInterrupt, subprocess.SubprocessError, OSError) as exc:
            if process is not None:
                _terminate(process)
            raise _GitProcessFailure() from exc
        finally:
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()


def open_local_workspace(
    path: Path, *, timeout_seconds: float = _GIT_TIMEOUT_SECONDS
) -> LocalWorkspaceHandle:
    """Validate one explicit local Git root and return an opaque descriptor handle."""

    root = _lexically_safe_absolute(path)
    _reject_ambiguous_root(root)
    descriptor = -1
    try:
        descriptor = _open_root_descriptor(root)
        facts = os.fstat(descriptor)
        _verify_root_facts(facts)
        runner = _default_runner(timeout_seconds)
        _verify_git_metadata(root)
        _verify_git_root(root, runner)
        payload = _WorkspaceDescriptor(root, descriptor, facts.st_dev, facts.st_ino)
        descriptor = -1
        return LocalWorkspaceHandle._from_validated_descriptor(  # pyright: ignore[reportPrivateUsage]
            payload
        )
    except _CaptureFailure as exc:
        raise ValueError(exc.limitation.value) from exc
    except (_GitProcessFailure, _OutputLimit) as exc:
        raise ValueError("not_git") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def list_changed_relative_paths(
    workspace: LocalWorkspaceHandle,
    *,
    max_files: int = MAX_SUBJECT_STATE_FILES,
) -> tuple[str, ...]:
    """Return a bounded, sorted set of project-relative changed/untracked paths.

    Sibling to ``capture``: uses the same descriptor-safe Git runner but returns path
    names only (never file contents). Overflow beyond ``max_files`` raises ValueError
    rather than silently truncating.
    """

    from yoetz.ports.workspace_inspect import MAX_INSPECT_FILES

    limit = min(max_files, MAX_INSPECT_FILES, MAX_SUBJECT_STATE_FILES)
    if type(limit) is not int or limit < 1:
        raise ValueError("changed_path_limit_invalid")
    try:
        payload = _workspace_payload(workspace)
        runner = _default_runner()
        _verify_git_root(payload.root, runner)
        collected: set[str] = set()
        for args in (
            ("diff", "--name-only", "-z", "--cached"),
            ("diff", "--name-only", "-z"),
            ("ls-files", "--others", "--exclude-standard", "-z"),
        ):
            _, raw = runner.run(payload.root, args, stdout_limit=_PATH_OUTPUT_LIMIT)
            try:
                for entry in _nul_entries(raw):
                    _validate_relative_git_path(entry)
                    collected.add(os.fsdecode(entry))
            finally:
                _overwrite(raw)
        if len(collected) > limit:
            raise ValueError("file_limit_exceeded")
        return tuple(sorted(collected, key=str.encode))
    except _CaptureFailure as exc:
        raise ValueError(exc.limitation.value) from exc
    except (_GitProcessFailure, _OutputLimit) as exc:
        raise ValueError("not_git") from exc


def discover_workspace_root(path: Path, *, timeout_seconds: float = _GIT_TIMEOUT_SECONDS) -> Path:
    """Return the Git top level containing ``path`` without opening any file.

    A control connection may name a subdirectory of its repository. This resolves the root with
    the same hardened, no-shell runner before ``open_local_workspace`` applies its full root and
    metadata fences to the answer. The repository Git found for ``path`` must be the one whose
    top level it reports, with its ``.git`` directly beneath, and ``path`` must lie inside it: a
    ``core.worktree`` (or any other redirection) that points one repository's metadata at another
    directory is ``unsafe_root`` (ADR-031). Raises ``ValueError`` with a closed token on failure.
    """

    candidate = _lexically_safe_absolute(path)
    try:
        runner = _default_runner(timeout_seconds)
        _, top = runner.run(
            candidate,
            # No ``--path-format=absolute``: Git before 2.31 echoes it as an extra output line
            # (#1040). Both queries print absolute paths on every supported Git; each answer is
            # still canonicalised against the directory Git ran in (``git_rev_parse``).
            ("rev-parse", "--show-toplevel", "--absolute-git-dir"),
            stdout_limit=8_192,
        )
    except (_GitProcessFailure, _OutputLimit) as exc:
        raise ValueError("not_git") from exc
    try:
        lines = bytes(top).rstrip(b"\n").split(b"\n")
    finally:
        _overwrite(top)
    if len(lines) != 2:
        raise ValueError("not_git")
    try:
        root = absolute_rev_parse_path(lines[0], candidate)
        git_dir = absolute_rev_parse_path(lines[1], candidate)
    except ValueError as exc:
        raise ValueError("not_git") from exc
    if not root.is_absolute() or git_dir != root / ".git" or not candidate.is_relative_to(root):
        raise ValueError("unsafe_root")
    return _lexically_safe_absolute(root)


def local_workspace_root(workspace: LocalWorkspaceHandle) -> tuple[Path, int]:
    """Return a validated handle's root path and its open no-follow directory descriptor.

    The check-time change capture (ADR-031) reads untracked files relative to this descriptor so a
    path component swapped for a symlink after validation cannot lead outside the root.
    """

    try:
        payload = _workspace_payload(workspace)
    except _CaptureFailure as exc:
        raise ValueError(exc.limitation.value) from exc
    return payload.root, payload.descriptor


def run_read_only_git(
    workspace: LocalWorkspaceHandle,
    arguments: Sequence[str],
    *,
    stdout_limit: int,
    timeout_seconds: float = _GIT_TIMEOUT_SECONDS,
    accepted_returncodes: frozenset[int] = frozenset({0}),
    keep_prefix_on_limit: bool = False,
) -> tuple[int, bytes]:
    """Run one hardened Git subcommand at a validated workspace root.

    Shared with the check-time change capture (ADR-031) so both adapters run Git with the same
    disabled global/system config, hooks, fsmonitor, external diff, textconv and credential
    helpers. ``ValueError("git_output_limit")`` means stdout exceeded ``stdout_limit``; every
    other failure is ``ValueError("git_failed")``. Neither carries Git output, except that
    ``keep_prefix_on_limit`` turns the limit error into ``GitOutputTruncated`` holding the stdout
    bytes that fit, for a listing whose caller can use and disclose a partial answer.
    """

    if type(stdout_limit) is not int or stdout_limit < 1:
        raise ValueError("git_output_limit_invalid")
    try:
        payload = _workspace_payload(workspace)
        runner = _default_runner(timeout_seconds)
        returncode, output = runner.run(
            payload.root,
            arguments,
            stdout_limit=stdout_limit,
            accepted_returncodes=accepted_returncodes,
            keep_prefix_on_limit=keep_prefix_on_limit,
        )
    except _OutputLimit as exc:
        if keep_prefix_on_limit:
            raise GitOutputTruncated(exc.prefix) from None
        raise ValueError("git_output_limit") from exc
    except (_CaptureFailure, _GitProcessFailure) as exc:
        raise ValueError("git_failed") from exc
    try:
        return returncode, bytes(output)
    finally:
        _overwrite(output)


class GitSubjectStateAdapter:
    """Capture complete stable Git structural state without disclosing components."""

    def __init__(
        self,
        *,
        _git_executable: Path | None = None,
        _timeout_seconds: float = _GIT_TIMEOUT_SECONDS,
        _max_hash_bytes: int = MAX_SUBJECT_STATE_HASH_BYTES,
        _max_files: int = MAX_SUBJECT_STATE_FILES,
        _before_second_capture: Callable[[], None] | None = None,
    ) -> None:
        if (
            type(_timeout_seconds) is not float
            or not math.isfinite(_timeout_seconds)
            or _timeout_seconds <= 0.0
        ):
            raise ValueError("git_timeout_invalid")
        if (
            type(_max_hash_bytes) is not int
            or not 1 <= _max_hash_bytes <= MAX_SUBJECT_STATE_HASH_BYTES
        ):
            raise ValueError("git_hash_limit_invalid")
        if type(_max_files) is not int or not 1 <= _max_files <= MAX_SUBJECT_STATE_FILES:
            raise ValueError("git_file_limit_invalid")
        runner = (
            _GitRunner(_git_executable, _timeout_seconds)
            if _git_executable is not None
            else _default_runner(_timeout_seconds)
        )
        self._runner = runner
        self._max_hash_bytes = _max_hash_bytes
        self._max_files = _max_files
        self._before_second_capture = _before_second_capture

    def capture(self, command: SubjectStateCaptureCommand) -> SubjectStateCaptureResult:
        if command.expected_format is not SubjectStateFormat.GIT_STRUCTURAL_V1:
            return _closed_result(
                SubjectStateStatus.UNSUPPORTED,
                SubjectStateLimitation.OBJECT_FORMAT_UNSUPPORTED,
            )
        try:
            workspace = _workspace_payload(command.workspace)
            self._verify_still_same_root(workspace)
            self._verify_still_same_git_dir(workspace)
            _verify_git_root(workspace.root, self._runner)
            before = self._snapshot_identity(workspace.root)
            first, counts = self._capture_components(workspace)
            if self._before_second_capture is not None:
                self._before_second_capture()
            second, _ = self._capture_components(workspace)
            after = self._snapshot_identity(workspace.root)
            self._verify_still_same_root(workspace)
            if before != after or first != second:
                raise _CaptureFailure(
                    SubjectStateLimitation.INPUT_CHANGED,
                    SubjectStateStatus.CHANGED_DURING_CAPTURE,
                )
            diff_digest = canonical_digest(
                cast(
                    JsonValue,
                    {
                        "format": GIT_SUBJECT_STATE_FORMAT,
                        "index_digest": first.index_digest,
                        "untracked_digest": first.untracked_digest,
                        "worktree_digest": first.worktree_digest,
                    },
                )
            )
            tree_digest = canonical_digest(
                cast(
                    JsonValue,
                    {
                        "diff_digest": diff_digest,
                        "format": GIT_SUBJECT_STATE_FORMAT,
                        "head_state": first.head_state,
                        "object_format": first.object_format,
                    },
                )
            )
            return SubjectStateCaptureResult(
                SubjectStateStatus.CAPTURED,
                SubjectStateRef(tree_digest, diff_digest, _FORMAT_TOKEN),
                SubjectStateFormat.GIT_STRUCTURAL_V1,
                (),
                counts.bytes_hashed,
                counts.files_hashed,
            )
        except _CaptureFailure as exc:
            return _closed_result(exc.status, exc.limitation, exc.detail)
        except _OutputLimit:
            return _closed_result(
                SubjectStateStatus.UNSUPPORTED,
                SubjectStateLimitation.READ_LIMIT_EXCEEDED,
            )
        except _GitProcessFailure, OSError, ValueError:
            return _closed_result(
                SubjectStateStatus.STATE_NOT_OBSERVED,
                SubjectStateLimitation.GIT_FAILED,
            )
        except KeyboardInterrupt:
            return _closed_result(
                SubjectStateStatus.STATE_NOT_OBSERVED,
                SubjectStateLimitation.GIT_FAILED,
            )

    def _snapshot_identity(self, root: Path) -> _SnapshotIdentity:
        object_format, head_state = self._head_identity(root)
        _, status = self._runner.run(
            root,
            (
                "status",
                "--porcelain=v2",
                "-z",
                "--branch",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ),
            stdout_limit=_COMMAND_OUTPUT_LIMIT,
        )
        try:
            status_hasher = hashlib.sha256()
            status_hasher.update(_STATUS_DOMAIN)
            status_hasher.update(status)
            status_digest = status_hasher.digest()
        finally:
            _overwrite(status)
        return _SnapshotIdentity(object_format, head_state, status_digest)

    def _capture_components(
        self, workspace: _WorkspaceDescriptor
    ) -> tuple[GitStateComponents, _CaptureCounts]:
        root = workspace.root
        object_format, head_state = self._head_identity(root)
        self._reject_unsupported_index_entries(workspace)
        self._reject_unsafe_tree_entries(workspace)
        _, index = self._runner.run(
            root,
            ("diff", "--cached", *_DIFF_ARGS),
            stdout_limit=self._max_hash_bytes + 1,
        )
        _, worktree = self._runner.run(
            root,
            ("diff", *_DIFF_ARGS),
            stdout_limit=self._max_hash_bytes + 1,
        )
        try:
            delta_bytes = len(index) + len(worktree)
            if delta_bytes > self._max_hash_bytes:
                raise _CaptureFailure(
                    SubjectStateLimitation.READ_LIMIT_EXCEEDED,
                    SubjectStateStatus.UNSUPPORTED,
                )
            index_digest = _digest_bytes(_INDEX_DOMAIN, index)
            worktree_digest = _digest_bytes(_WORKTREE_DOMAIN, worktree)
            untracked_digest, untracked_bytes, untracked_files = self._hash_untracked(
                workspace, delta_bytes
            )
            return (
                GitStateComponents(
                    object_format,
                    head_state,
                    index_digest,
                    worktree_digest,
                    untracked_digest,
                ),
                _CaptureCounts(delta_bytes + untracked_bytes, untracked_files),
            )
        finally:
            _overwrite(index)
            _overwrite(worktree)

    def _head_identity(self, root: Path) -> tuple[Literal["sha1", "sha256"], str]:
        _, object_format_bytes = self._runner.run(
            root,
            ("rev-parse", "--show-object-format"),
            stdout_limit=32,
        )
        try:
            object_format_text = _one_line_ascii(object_format_bytes)
        finally:
            _overwrite(object_format_bytes)
        if object_format_text not in {"sha1", "sha256"}:
            raise _CaptureFailure(
                SubjectStateLimitation.OBJECT_FORMAT_UNSUPPORTED,
                SubjectStateStatus.UNSUPPORTED,
            )
        object_format = cast(Literal["sha1", "sha256"], object_format_text)
        returncode, head_bytes = self._runner.run(
            root,
            ("rev-parse", "--verify", "--quiet", "HEAD"),
            stdout_limit=128,
            accepted_returncodes=frozenset({0, 1}),
        )
        if returncode == 1:
            _overwrite(head_bytes)
            _, symbolic = self._runner.run(
                root,
                ("symbolic-ref", "--quiet", "HEAD"),
                stdout_limit=512,
            )
            try:
                _one_line_ascii(symbolic)
            finally:
                _overwrite(symbolic)
            head_state = "unborn"
        else:
            try:
                head_state = _one_line_ascii(head_bytes)
            finally:
                _overwrite(head_bytes)
        return object_format, head_state

    def _reject_unsupported_index_entries(self, workspace: _WorkspaceDescriptor) -> None:
        _, staged = self._runner.run(
            workspace.root,
            ("ls-files", "--stage", "-z"),
            stdout_limit=_PATH_OUTPUT_LIMIT,
        )
        tracked_paths: list[bytes] = []
        entries = _nul_entries(staged)
        _overwrite(staged)
        for entry in entries:
            metadata, separator, path = entry.partition(b"\t")
            fields = metadata.split(b" ")
            if not separator or len(fields) != 3:
                raise _GitProcessFailure()
            mode = fields[0]
            _validate_relative_git_path(path)
            if mode == b"160000":
                raise _CaptureFailure(
                    SubjectStateLimitation.SUBMODULE_PRESENT,
                    SubjectStateStatus.UNSUPPORTED,
                )
            if mode == b"120000":
                raise _CaptureFailure(
                    SubjectStateLimitation.SYMLINK_UNSUPPORTED,
                    SubjectStateStatus.UNSUPPORTED,
                )
            tracked_paths.append(path)
        for path in tracked_paths:
            try:
                facts = os.stat(path, dir_fd=workspace.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(facts.st_mode):
                raise _CaptureFailure(
                    SubjectStateLimitation.SYMLINK_UNSUPPORTED,
                    SubjectStateStatus.UNSUPPORTED,
                )

    def _hash_untracked(
        self, workspace: _WorkspaceDescriptor, already_hashed: int
    ) -> tuple[str, int, int]:
        _, inventory = self._runner.run(
            workspace.root,
            ("ls-files", "--others", "--exclude-standard", "-z"),
            stdout_limit=_PATH_OUTPUT_LIMIT,
        )
        paths = _nul_entries(inventory)
        _overwrite(inventory)
        if len(paths) > self._max_files:
            raise _CaptureFailure(
                SubjectStateLimitation.FILE_LIMIT_EXCEEDED,
                SubjectStateStatus.UNSUPPORTED,
                detail=SubjectStateLimitDetail(
                    SubjectStateBound.UNTRACKED_FILE_COUNT, len(paths), self._max_files
                ),
            )
        hasher = hashlib.sha256()
        hasher.update(_UNTRACKED_DOMAIN)
        total_bytes = 0
        previous: bytes | None = None
        for path in paths:
            _validate_relative_git_path(path)
            if previous is not None and path <= previous:
                raise _GitProcessFailure()
            previous = path
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = -1
            try:
                descriptor = os.open(path, flags, dir_fd=workspace.descriptor)
                before = os.fstat(descriptor)
                _verify_untracked_file(before)
                if already_hashed + total_bytes + before.st_size > self._max_hash_bytes:
                    raise _CaptureFailure(
                        SubjectStateLimitation.READ_LIMIT_EXCEEDED,
                        SubjectStateStatus.UNSUPPORTED,
                    )
                hasher.update(_U32.pack(len(path)))
                hasher.update(path)
                hasher.update(_U32.pack(stat.S_IMODE(before.st_mode)))
                hasher.update(_U64.pack(before.st_size))
                file_bytes = 0
                while True:
                    chunk = os.read(descriptor, min(_READ_CHUNK, before.st_size - file_bytes + 1))
                    if not chunk:
                        break
                    file_bytes += len(chunk)
                    if already_hashed + total_bytes + file_bytes > self._max_hash_bytes:
                        raise _CaptureFailure(
                            SubjectStateLimitation.READ_LIMIT_EXCEEDED,
                            SubjectStateStatus.UNSUPPORTED,
                        )
                    hasher.update(chunk)
                after = os.fstat(descriptor)
                if file_bytes != before.st_size or not _same_file_snapshot(before, after):
                    raise _CaptureFailure(
                        SubjectStateLimitation.INPUT_CHANGED,
                        SubjectStateStatus.CHANGED_DURING_CAPTURE,
                    )
                total_bytes += file_bytes
            except OSError as exc:
                raise _CaptureFailure(SubjectStateLimitation.SYMLINK_UNSUPPORTED) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        return f"sha256:{hasher.hexdigest()}", total_bytes, len(paths)

    def _reject_unsafe_tree_entries(self, workspace: _WorkspaceDescriptor) -> None:
        # Ignored subtrees are never opened by capture (`_hash_untracked` restricts itself
        # to `ls-files --others --exclude-standard`), so recursion may skip them entirely.
        # This is one bounded git call, not a walk: `--directory` collapses a fully-ignored
        # directory to a single trailing-slash entry without descending into it.
        ignored_prefixes = _collect_ignored_prefixes(workspace.root, self._runner)
        pending: list[tuple[Path, bytes]] = [(workspace.root, b"")]
        entries_seen = 0
        path_bytes_seen = 0
        while pending:
            directory, relative_dir = pending.pop()
            try:
                with os.scandir(directory) as entries:
                    ordered = sorted(entries, key=lambda entry: os.fsencode(entry.name))
            except OSError as exc:
                raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
            for entry in ordered:
                entries_seen += 1
                path_bytes_seen += len(os.fsencode(entry.name))
                if entries_seen > self._max_files:
                    raise _CaptureFailure(
                        SubjectStateLimitation.FILE_LIMIT_EXCEEDED,
                        SubjectStateStatus.UNSUPPORTED,
                        detail=SubjectStateLimitDetail(
                            SubjectStateBound.UNSAFE_TREE_ENTRIES, entries_seen, self._max_files
                        ),
                    )
                if path_bytes_seen > _PATH_OUTPUT_LIMIT:
                    raise _CaptureFailure(
                        SubjectStateLimitation.READ_LIMIT_EXCEEDED,
                        SubjectStateStatus.UNSUPPORTED,
                    )
                try:
                    facts = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
                expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
                if facts.st_uid != expected_uid or writable_by_others(facts):
                    raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
                if stat.S_ISLNK(facts.st_mode) or not (
                    stat.S_ISREG(facts.st_mode) or stat.S_ISDIR(facts.st_mode)
                ):
                    raise _CaptureFailure(
                        SubjectStateLimitation.SYMLINK_UNSUPPORTED,
                        SubjectStateStatus.UNSUPPORTED,
                    )
                if stat.S_ISDIR(facts.st_mode):
                    if entry.name == ".git":
                        if directory != workspace.root:
                            raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
                        # Root .git is already verified by _verify_git_metadata and is
                        # never opened directly; only the hardened git subprocess touches
                        # the object store, so its internals need no per-file walk.
                        continue
                    name_bytes = os.fsencode(entry.name)
                    relative = name_bytes if not relative_dir else relative_dir + b"/" + name_bytes
                    if relative in ignored_prefixes or relative + b"/" in ignored_prefixes:
                        continue  # gitignore-excluded subtree: capture never opens files inside it
                    pending.append((Path(entry.path), relative))

    def _verify_still_same_root(self, workspace: _WorkspaceDescriptor) -> None:
        facts = os.fstat(workspace.descriptor)
        current = workspace.root.lstat()
        _verify_root_facts(facts)
        _verify_root_facts(current)
        if (
            facts.st_dev != workspace.device
            or facts.st_ino != workspace.inode
            or current.st_dev != workspace.device
            or current.st_ino != workspace.inode
        ):
            raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)

    @staticmethod
    def _verify_still_same_git_dir(workspace: _WorkspaceDescriptor) -> None:
        _verify_git_metadata(workspace.root)


def _verify_git_metadata(root: Path) -> None:
    """Reject repository metadata that can escape the root or execute helpers."""

    git_root = root / ".git"
    try:
        facts = git_root.lstat()
    except FileNotFoundError as exc:
        raise _CaptureFailure(SubjectStateLimitation.NOT_GIT) from exc
    except OSError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != expected_uid:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    alternates = git_root / "objects" / "info" / "alternates"
    try:
        alternates.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
    else:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    config = git_root / "config"
    try:
        encoded = _read_small_mutable(config, _GIT_CONFIG_LIMIT)
    except OSError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
    except _CaptureFailure as exc:
        if exc.limitation is SubjectStateLimitation.READ_LIMIT_EXCEEDED:
            raise _CaptureFailure(
                SubjectStateLimitation.GIT_CONFIG_LIMIT_EXCEEDED,
                exc.status,
            ) from exc
        raise
    try:
        for line in encoded.splitlines():
            section = line.lstrip().lower()
            if section.startswith((b"[include", b"[filter")):
                raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    finally:
        _overwrite(encoded)


def _default_runner(timeout_seconds: float = _GIT_TIMEOUT_SECONDS) -> _GitRunner:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise ValueError("git_executable_missing")
    # ``ValueError("git_version_unsupported")`` below the documented minimum (``git_version``).
    require_supported_git(executable)
    return _GitRunner(Path(executable), timeout_seconds)


def _workspace_payload(handle: LocalWorkspaceHandle) -> _WorkspaceDescriptor:
    payload = handle._validated_descriptor()  # pyright: ignore[reportPrivateUsage]
    if type(payload) is not _WorkspaceDescriptor or payload.descriptor < 0:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    return payload


def _lexically_safe_absolute(path: Path) -> Path:
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise ValueError("unsafe_root")
    encoded = os.fsencode(path)
    if b"\x00" in encoded or b"\n" in encoded or b"\r" in encoded:
        raise ValueError("unsafe_root")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            facts = current.lstat()
        except OSError as exc:
            raise ValueError("unsafe_root") from exc
        if stat.S_ISLNK(facts.st_mode):
            raise ValueError("unsafe_root")
    return path


def _reject_ambiguous_root(root: Path) -> None:
    home = Path.home()
    if root == Path(root.anchor) or root == home:
        raise ValueError("unsafe_root")


def _open_root_descriptor(root: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(root, flags)
    except OSError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc


def _verify_root_facts(facts: os.stat_result) -> None:
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != expected_uid or writable_by_others(facts):
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)


def _verify_git_root(root: Path, runner: _GitRunner) -> None:
    _, bare = runner.run(
        root,
        ("rev-parse", "--is-bare-repository"),
        stdout_limit=32,
    )
    try:
        is_bare = _one_line_ascii(bare)
    finally:
        _overwrite(bare)
    if is_bare != "false":
        raise _CaptureFailure(SubjectStateLimitation.NOT_GIT)
    _, top = runner.run(
        root,
        ("rev-parse", "--show-toplevel"),
        stdout_limit=4_096,
    )
    try:
        top_path = absolute_rev_parse_path(bytes(top).rstrip(b"\n"), root)
    except ValueError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
    finally:
        _overwrite(top)
    if not top_path.is_absolute() or top_path != root:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    try:
        top_facts = top_path.lstat()
    except OSError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
    root_facts = root.lstat()
    if (top_facts.st_dev, top_facts.st_ino) != (root_facts.st_dev, root_facts.st_ino):
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    _, git_dir = runner.run(
        root,
        ("rev-parse", "--absolute-git-dir"),
        stdout_limit=4_096,
    )
    try:
        git_path = absolute_rev_parse_path(bytes(git_dir).rstrip(b"\n"), root)
    except ValueError as exc:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT) from exc
    finally:
        _overwrite(git_dir)
    expected_git_path = root / ".git"
    if git_path != expected_git_path:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
    try:
        git_facts = git_path.lstat()
    except OSError as exc:
        raise _CaptureFailure(SubjectStateLimitation.NOT_GIT) from exc
    if not stat.S_ISDIR(git_facts.st_mode) or git_facts.st_uid != root_facts.st_uid:
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)


def _bounded_communicate(
    process: subprocess.Popen[bytes],
    *,
    stdout_limit: int,
    stderr_limit: int,
    timeout_seconds: float,
    keep_prefix_on_limit: bool = False,
) -> tuple[bytearray, bytearray]:
    if process.stdout is None or process.stderr is None:
        raise _GitProcessFailure()
    selector = selectors.DefaultSelector()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    streams: dict[int, tuple[bytearray, int]] = {}
    for stream, buffer, limit in (
        (process.stdout, stdout_buffer, stdout_limit),
        (process.stderr, stderr_buffer, stderr_limit),
    ):
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        streams[descriptor] = (buffer, limit)
    deadline = time.monotonic() + timeout_seconds
    try:
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                raise _GitProcessFailure()
            events = selector.select(remaining)
            if not events:
                raise _GitProcessFailure()
            for key, _ in events:
                descriptor = key.fd
                buffer, limit = streams[descriptor]
                try:
                    chunk = os.read(descriptor, _READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(descriptor)
                    del streams[descriptor]
                    continue
                if len(buffer) + len(chunk) > limit:
                    if keep_prefix_on_limit and buffer is stdout_buffer:
                        raise _OutputLimit(bytes(buffer) + chunk[: limit - len(buffer)])
                    raise _OutputLimit
                buffer.extend(chunk)
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise _GitProcessFailure() from exc
        return stdout_buffer, stderr_buffer
    finally:
        selector.close()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)


def _read_small_mutable(path: Path, limit: int) -> bytearray:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        facts = os.fstat(descriptor)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != expected_uid
            or writable_by_others(facts)
            or facts.st_nlink != 1
        ):
            raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)
        result = bytearray()
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK, limit - len(result) + 1))
            if not chunk:
                return result
            result.extend(chunk)
            if len(result) > limit:
                _overwrite(result)
                raise _CaptureFailure(
                    SubjectStateLimitation.READ_LIMIT_EXCEEDED,
                    SubjectStateStatus.UNSUPPORTED,
                )
    finally:
        os.close(descriptor)


def _digest_bytes(domain: bytes, payload: bytes | bytearray) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(payload)
    return f"sha256:{hasher.hexdigest()}"


def _one_line_ascii(payload: bytes | bytearray) -> str:
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        raise _GitProcessFailure()
    line = payload[:-1]
    if b"\x00" in line or b"\r" in line or b"\n" in line:
        raise _GitProcessFailure()
    try:
        return line.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise _GitProcessFailure() from exc


def _nul_entries(payload: bytes | bytearray) -> list[bytes]:
    if not payload:
        return []
    if not payload.endswith(b"\x00"):
        raise _GitProcessFailure()
    entries = bytes(payload[:-1]).split(b"\x00")
    if any(not entry for entry in entries):
        raise _GitProcessFailure()
    return entries


def _validate_relative_git_path(path: bytes) -> None:
    if (
        not path
        or path.startswith(b"/")
        or b"\x00" in path
        or any(part in {b"", b".", b".."} for part in path.split(b"/"))
    ):
        raise _CaptureFailure(SubjectStateLimitation.UNSAFE_ROOT)


def _validate_relative_git_tree_path(path: bytes) -> None:
    """Like ``_validate_relative_git_path``, but allows exactly one trailing ``/``.

    ``ls-files --directory`` reports a fully-ignored directory as ``name/``; the prune
    set must accept that form without weakening the underlying traversal validation.
    """

    _validate_relative_git_path(path[:-1] if path.endswith(b"/") else path)


def _collect_ignored_prefixes(root: Path, runner: _GitRunner) -> frozenset[bytes]:
    """Return the set of gitignore-excluded top-level paths the walk must not recurse into.

    One bounded git call, mirroring `_hash_untracked`'s own technique. `--directory` makes
    git collapse a fully-ignored directory to a single trailing-slash entry instead of
    listing its contents, so this is cheap regardless of how large the ignored subtree is.
    """

    _, raw = runner.run(
        root,
        ("ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"),
        stdout_limit=_PATH_OUTPUT_LIMIT,
    )
    try:
        entries = _nul_entries(raw)
    finally:
        _overwrite(raw)
    for entry in entries:
        _validate_relative_git_tree_path(entry)
    return frozenset(entries)


def _verify_untracked_file(facts: os.stat_result) -> None:
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
    if not stat.S_ISREG(facts.st_mode) or facts.st_uid != expected_uid or facts.st_nlink != 1:
        raise _CaptureFailure(
            SubjectStateLimitation.SYMLINK_UNSUPPORTED,
            SubjectStateStatus.UNSUPPORTED,
        )


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


def _overwrite(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


def _closed_result(
    status: SubjectStateStatus,
    limitation: SubjectStateLimitation,
    detail: SubjectStateLimitDetail | None = None,
) -> SubjectStateCaptureResult:
    return SubjectStateCaptureResult(
        status,
        None,
        SubjectStateFormat.GIT_STRUCTURAL_V1,
        (limitation,),
        0,
        0,
        (detail,) if detail is not None else (),
    )
