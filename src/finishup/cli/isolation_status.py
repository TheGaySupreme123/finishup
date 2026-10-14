"""Connection-free proof of the runtime's resolved FinishUP identity roots (issues #518, #567).

``finishup service isolation`` resolves — locally, without touching any service, lock, or ledger —
which identity roots this exact process environment would use: state directory (service lock and
generation), runtime endpoint directory, effective storage bundle, selected config file, and the
FinishUP launcher. It reports each as a **path-identity digest** over the canonical resolved path,
never as a raw path. A dogfood preflight combines one exact normal-target report with one exact
isolated report, so relocated normal storage cannot be mistaken for separation.

Path identity is not byte content: an in-place edit of the selected config leaves
``config_path_digest`` unchanged. Only the opt-in content lane (``content=True``) binds the
config's bytes, as one bounded content observation carrying SHA-256, size, existence, and
observation time — never the bytes themselves (``yoetz.isolation-report/1``).

A set but unusable ``FINISHUP_ISOLATED_ROOT`` propagates as the bounded ``PathSafetyError`` — the
mode is then unprovable and callers must fail closed, never report ``ambient``.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, TypedDict

from finishup.config.installation import (
    ReportedLifecycle,
    format_rfc3339_ms,
    read_instance_identity,
)
from finishup.config.load import parse_minimal_safe_config
from finishup.config.paths import (
    IsolationBinding,
    bundle_root,
    config_file_path,
    isolated_root,
    isolation_binding,
    runtime_dir,
    state_dir,
)
from finishup.protocol.isolation_report import (
    CONTENT_OBSERVATION_BYTE_LIMIT,
    ISOLATION_REPORT_SCHEMA,
    ContentPresence,
)

__all__ = [
    "ContentObservationRow",
    "IsolationReport",
    "PathIdentity",
    "isolation_report",
    "observe_file_content",
    "path_identity_digest",
]

_CHUNK: Final = 65_536
# Bounded retries when the file changes underneath one observation; then ``unstable``.
_STABLE_ATTEMPTS: Final = 3

type _ReadOutcome = tuple[ContentPresence, str | None, int | None]


class PathIdentity(TypedDict):
    state_path_digest: str
    endpoint_path_digest: str
    storage_path_digest: str
    config_path_digest: str
    executable_path_digest: str


class ContentObservationRow(TypedDict):
    path_digest: str
    presence: ContentPresence
    content_digest: str | None
    size_bytes: int | None
    observed_at: str


class IsolationReport(TypedDict):
    schema: Literal["yoetz.isolation-report/1"]
    mode: Literal["isolated", "ambient"]
    binding: IsolationBinding
    lifecycle: ReportedLifecycle
    path_identity: PathIdentity
    config_content: ContentObservationRow | None


def _resolved(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError, RuntimeError:
        return path


def path_identity_digest(path: Path) -> str:
    """Digest over the canonical resolved path identity; never binds bytes or publishes the path."""

    return "sha256:" + hashlib.sha256(str(_resolved(path)).encode("utf-8")).hexdigest()


def _stat_key(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read_once(resolved: Path) -> _ReadOutcome | None:
    """One bounded read of ``resolved``; ``None`` means it changed underneath the read."""

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        descriptor = os.open(resolved, flags)
    except FileNotFoundError, NotADirectoryError:
        return ("absent", None, None)
    except OSError as error:
        # ELOOP means the resolved final component became a symlink after resolution: a
        # concurrent replacement, observed again like any other change.
        return None if error.errno == errno.ELOOP else ("unreadable", None, None)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return ("not_regular", None, None)
        if before.st_size > CONTENT_OBSERVATION_BYTE_LIMIT:
            return ("oversized", None, None)
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, _CHUNK):
            total += len(chunk)
            if total > before.st_size:
                return None
            digest.update(chunk)
        after = os.fstat(descriptor)
    except OSError:
        return ("unreadable", None, None)
    finally:
        os.close(descriptor)
    if _stat_key(before) != _stat_key(after) or total != before.st_size:
        return None
    try:
        current = os.stat(resolved, follow_symlinks=False)
    except OSError:
        return None
    if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
        # The path was atomically replaced while it was read: the digest no longer names the
        # bytes the path holds, so observe again.
        return None
    return ("present", "sha256:" + digest.hexdigest(), total)


def observe_file_content(
    path: Path, *, now: Callable[[], datetime] | None = None
) -> ContentObservationRow:
    """Observe one file's bytes as SHA-256, size, existence, and time — never its content.

    Symlinks are followed to the canonical target, whose path identity is ``path_digest``; so a
    retargeted link with identical bytes changes ``path_digest`` and not ``content_digest``, while
    an in-place edit changes ``content_digest`` and not ``path_digest``. A file that keeps
    changing across ``_STABLE_ATTEMPTS`` reads is ``unstable``; nothing partial is digested.
    """

    clock = now or (lambda: datetime.now(UTC))
    resolved = _resolved(path)
    observed_at = format_rfc3339_ms(clock())
    outcome: _ReadOutcome = ("unstable", None, None)
    for _ in range(_STABLE_ATTEMPTS):
        attempt = _read_once(resolved)
        if attempt is not None:
            outcome = attempt
            break
    presence, content_digest, size_bytes = outcome
    return ContentObservationRow(
        path_digest=path_identity_digest(path),
        presence=presence,
        content_digest=content_digest,
        size_bytes=size_bytes,
        observed_at=observed_at,
    )


def _selected_config_path() -> Path:
    explicit = os.environ.get("FINISHUP_CONFIG", "")
    return Path(explicit) if explicit else config_file_path()


def _effective_storage_dir() -> Path:
    """The storage bundle the runtime would actually open, honoring config and env overrides."""

    minimal = parse_minimal_safe_config(os.environ, {})
    if minimal.data_dir is not None:
        return minimal.data_dir
    return bundle_root()


def isolation_report(
    *, content: bool = False, now: Callable[[], datetime] | None = None
) -> IsolationReport:
    """Resolve only this exact environment's identity roots.

    ``content=True`` adds the bounded byte-content observation of the selected config file;
    otherwise ``config_content`` is ``null`` and the report binds path identity only.

    Raises ``PathSafetyError`` when ``FINISHUP_ISOLATED_ROOT`` or the runtime pin is set but
    unusable (or the two conflict), ``InstanceIdentityError`` when the root's instance marker is
    malformed, and ``ConfigError`` when the selected configuration cannot be minimally parsed;
    all mean the isolation state is unprovable and the caller must fail closed. A dogfood
    preflight compares this report with a second report captured from the exact normal target;
    platform defaults are not a substitute because that target may use relocated config or
    storage.
    """

    root = isolated_root()
    mode: Literal["isolated", "ambient"] = "ambient" if root is None else "isolated"
    binding = isolation_binding()
    # The everyday install is the permanent instance and carries no marker; an isolated root
    # without a marker is a legacy ADR-026 root and stays isolated, just unlabeled (issue #604).
    # A malformed marker propagates as ``InstanceIdentityError``: unprovable, never ambient.
    lifecycle: ReportedLifecycle = "permanent"
    if root is not None:
        marker = read_instance_identity(state_dir())
        lifecycle = "unlabeled" if marker is None else marker.lifecycle
    config_path = _selected_config_path()
    path_identity = PathIdentity(
        state_path_digest=path_identity_digest(state_dir()),
        endpoint_path_digest=path_identity_digest(runtime_dir()),
        storage_path_digest=path_identity_digest(_effective_storage_dir()),
        config_path_digest=path_identity_digest(config_path),
        # ``sys.argv[0]`` is the exact selected FinishUP launcher. ``sys.executable`` would identify
        # only the shared Python interpreter and could make two distinct installed targets look
        # identical (or the reverse when wrappers share one interpreter).
        executable_path_digest=path_identity_digest(Path(sys.argv[0])),
    )
    return IsolationReport(
        schema=ISOLATION_REPORT_SCHEMA,
        mode=mode,
        binding=binding,
        lifecycle=lifecycle,
        path_identity=path_identity,
        config_content=observe_file_content(config_path, now=now) if content else None,
    )
