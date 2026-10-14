"""``finishup instance``: create, inspect, and dispose independent FinishUP instances (issue #604).

Every operation here is connection-free and bounded by the instance-identity contract in
``config/installation.py`` and the runtime pin in ``config/paths.py``. ``create`` provisions one
isolated root and seals its identity; ``status`` reports what the invoking runtime would use,
digest-only; ``dispose`` removes exactly one marked persistent or disposable root after stopping
only the service that holds that root's singleton. The everyday (permanent) install and unlabeled
ADR-026 roots are never disposed by this module.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import signal
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, cast

from finishup import __version__
from finishup.cli.isolation_status import isolation_report
from finishup.config.installation import (
    InstanceIdentity,
    InstanceIdentityError,
    InstanceLifecycle,
    SourceState,
    format_rfc3339_ms,
    is_expired,
    new_instance_identity,
    parse_rfc3339_ms,
    read_instance_identity,
    remove_runtime_pin,
    runtime_prefix_digest,
    validate_package_digest,
    validate_source_ref,
    write_instance_identity,
    write_runtime_pin,
)
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    PathSafetyError,
    ensure_owner_only_dir,
    read_runtime_pin,
    runtime_pin_path,
    state_dir,
    verify_private_local_bundle,
)
from finishup.protocol.canonical import JsonValue
from finishup.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder_identity

__all__ = [
    "MAX_SOCKET_PATH_BYTES",
    "STOP_WAIT_SECONDS",
    "create_instance",
    "dispose_instance",
    "instance_status",
    "parse_expiry",
]

# Conservative bound for ``sun_path``: macOS allows 104 bytes including the terminator, Linux
# 108. The longest endpoint beneath a root is ``<root>/run/secret-ingress.sock``.
MAX_SOCKET_PATH_BYTES: Final = 100
_LONGEST_ENDPOINT: Final = Path("run") / "secret-ingress.sock"
# Bounded shutdown: the daemon drains for at most STOP_DRAIN_SECONDS (30 s) after SIGTERM.
STOP_WAIT_SECONDS: Final = 35.0
_STOP_POLL_SECONDS: Final = 0.1
_STATE_DIR_NAME: Final = "state"
_LOG_DIR_NAME: Final = "log"


def parse_expiry(
    *, now: datetime, expires_in_hours: float | None, expires_at: str | None
) -> datetime | None:
    """Resolve the optional expiry from exactly one of the two spellings."""

    if expires_in_hours is None and expires_at is None:
        return None
    if expires_in_hours is not None and expires_at is not None:
        raise InstanceIdentityError("instance_expiry_invalid")
    if expires_in_hours is not None:
        if type(expires_in_hours) not in {int, float} or not expires_in_hours > 0:
            raise InstanceIdentityError("instance_expiry_invalid")
        return now + timedelta(hours=float(expires_in_hours))
    try:
        return parse_rfc3339_ms(expires_at)
    except ValueError as exc:
        raise InstanceIdentityError("instance_expiry_invalid") from exc


def _check_root_shape(root: Path) -> None:
    if not root.is_absolute() or root.parent == root:
        raise InstanceIdentityError("instance_root_invalid")
    home = Path.home()
    if root == home or home.is_relative_to(root):
        raise InstanceIdentityError("instance_root_invalid")
    if len(os.fsencode(root / _LONGEST_ENDPOINT)) > MAX_SOCKET_PATH_BYTES:
        raise InstanceIdentityError("instance_root_too_long")


def create_instance(
    *,
    root: Path,
    lifecycle: InstanceLifecycle,
    now: datetime | None = None,
    expires_at: datetime | None = None,
    source_ref: str | None = None,
    source_state: SourceState = "unknown",
    package_digest: str | None = None,
    bind_runtime: bool = False,
    runtime_prefix: Path | None = None,
) -> dict[str, JsonValue]:
    """Create one isolated root with a sealed identity and optionally pin this runtime to it.

    The root is created here (owner-only; its parent must already exist) under the same
    path-safety gate every private directory passes. The exact root is echoed once for local
    review, like an MCP registration preview; ``status`` afterwards is digest-only.
    """

    when = now or datetime.now(UTC)
    prefix = runtime_prefix or Path(sys.prefix)
    _check_root_shape(root)
    if source_ref is not None:
        try:
            validate_source_ref(source_ref)
        except ValueError as exc:
            raise InstanceIdentityError("instance_identity_invalid") from exc
    if package_digest is not None:
        try:
            validate_package_digest(package_digest)
        except ValueError as exc:
            raise InstanceIdentityError("instance_identity_invalid") from exc
    if not root.parent.is_dir() or root.parent.is_symlink():
        raise InstanceIdentityError("instance_root_invalid")
    if root.is_symlink():
        raise InstanceIdentityError("instance_root_invalid")
    if root.exists():
        if not root.is_dir():
            raise InstanceIdentityError("instance_root_invalid")
        if read_instance_identity(root / _STATE_DIR_NAME) is not None:
            raise InstanceIdentityError("instance_exists")
        if any(root.iterdir()):
            raise InstanceIdentityError("instance_root_invalid")
    verify_private_local_bundle(root)
    if bind_runtime:
        existing = read_runtime_pin()
        if existing is not None and existing.isolated_root != root:
            raise InstanceIdentityError("runtime_pin_conflict")
    identity = new_instance_identity(
        lifecycle,
        now=when,
        package_version=__version__,
        runtime_prefix=prefix,
        expires_at=expires_at,
        source_ref=source_ref,
        source_state=source_state,
        package_digest=package_digest,
    )
    ensure_owner_only_dir(root)
    ensure_owner_only_dir(root / _STATE_DIR_NAME)
    write_instance_identity(root / _STATE_DIR_NAME, identity)
    pin_state = "none"
    if bind_runtime:
        write_runtime_pin(prefix, root, identity.installation_id)
        pin_state = "bound"
    return {
        "created": True,
        "isolated_root": str(root),
        "environment_export": f"{ISOLATED_ROOT_ENV}={root}",
        "runtime_pin": pin_state,
        **_identity_fields(identity),
    }


def _identity_fields(identity: InstanceIdentity) -> dict[str, JsonValue]:
    return {
        "installation_id": identity.installation_id,
        "lifecycle": identity.lifecycle,
        "created_at": identity.created_at,
        "expires_at": identity.expires_at,
        "source_ref": identity.source_ref,
        "source_state": identity.source_state,
        "package_version": identity.package_version,
        "package_digest": identity.package_digest,
    }


def instance_status(*, now: datetime | None = None) -> dict[str, JsonValue]:
    """Report the invoking runtime's instance, digest-only and without connecting to a service."""

    when = now or datetime.now(UTC)
    report = isolation_report()
    body: dict[str, JsonValue] = {
        "mode": report["mode"],
        "binding": report["binding"],
        "lifecycle": report["lifecycle"],
        "path_identity": cast(JsonValue, dict(report["path_identity"])),
        "runtime_package_version": __version__,
        "runtime_prefix_digest": runtime_prefix_digest(Path(sys.prefix)),
        "runtime_pin": "bound" if runtime_pin_path().is_file() else "none",
    }
    identity = None if report["mode"] == "ambient" else read_instance_identity(state_dir())
    if identity is not None:
        body.update(_identity_fields(identity))
        body["expired"] = is_expired(identity, when)
        body["runtime_provenance"] = (
            "matched"
            if identity.runtime_prefix_digest == body["runtime_prefix_digest"]
            and identity.package_version == __version__
            else "drifted"
        )
    else:
        body["runtime_provenance"] = "unrecorded"
    holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
    if holder is None:
        body["service_holder"] = None
    else:
        body["service_holder"] = {
            "pid": holder.pid,
            "service_version": holder.service_version,
            "instance_lifecycle": holder.instance_lifecycle,
            "source_ref": holder.source_ref,
        }
    body["observed_at"] = format_rfc3339_ms(when)
    return body


def _lock_held(lock: Path) -> bool:
    """Probe the flock without ever taking it for longer than the probe itself."""

    try:
        descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def _stop_owned_service(lock: Path, *, stop_service: bool, deadline: float) -> bool:
    """Stop the service holding ``lock``; return whether one was signalled.

    Only the process stamped in *this root's* lock file is ever signalled, and only after the
    flock probe confirms the singleton is actually held. Nothing is matched by name, path, or
    pattern. A holder that does not release within the bounded window leaves the root in place.
    """

    if not _lock_held(lock):
        return False
    holder = probe_singleton_holder_identity(lock)
    if holder is None or not stop_service:
        raise InstanceIdentityError("instance_service_running")
    try:
        os.kill(holder.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as exc:
        raise InstanceIdentityError("instance_service_running") from exc
    while _lock_held(lock):
        if time.monotonic() >= deadline:
            raise InstanceIdentityError("instance_service_running")
        time.sleep(_STOP_POLL_SECONDS)
    return True


def _retain_logs(root: Path, destination: Path, installation_id: str) -> bool:
    source = root / _LOG_DIR_NAME
    if not source.is_dir() or source.is_symlink():
        return False
    if not destination.is_absolute() or not destination.parent.is_dir():
        raise InstanceIdentityError("instance_root_invalid")
    ensure_owner_only_dir(destination)
    target = destination / installation_id
    if target.exists():
        raise InstanceIdentityError("instance_root_invalid")
    target.mkdir(mode=0o700)
    for entry in sorted(source.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            continue
        shutil.copyfile(entry, target / entry.name)
        os.chmod(target / entry.name, 0o600)
    return True


def dispose_instance(
    *,
    root: Path,
    retain_logs: Path | None = None,
    stop_service: bool = True,
    runtime_prefix: Path | None = None,
    wait_seconds: float = STOP_WAIT_SECONDS,
) -> dict[str, JsonValue]:
    """Remove exactly one marked persistent or disposable root; repeated calls are a no-op."""

    prefix = runtime_prefix or Path(sys.prefix)
    if not root.is_absolute() or root.parent == root:
        raise InstanceIdentityError("instance_root_invalid")
    if root.is_symlink():
        raise InstanceIdentityError("instance_root_invalid")
    if not root.exists():
        pin_removed = remove_runtime_pin(prefix, root)
        return {"disposed": False, "state": "absent", "runtime_pin_removed": pin_removed}
    if not root.is_dir():
        raise InstanceIdentityError("instance_root_invalid")
    home = Path.home()
    if root == home or home.is_relative_to(root) or prefix.is_relative_to(root):
        raise InstanceIdentityError("instance_root_invalid")
    verify_private_local_bundle(root)
    identity = read_instance_identity(root / _STATE_DIR_NAME)
    if identity is None:
        raise InstanceIdentityError("instance_not_disposable")
    lock = root / _STATE_DIR_NAME / SINGLETON_LOCK_NAME
    stopped = _stop_owned_service(
        lock, stop_service=stop_service, deadline=time.monotonic() + wait_seconds
    )
    retained = False
    if retain_logs is not None:
        retained = _retain_logs(root, retain_logs, identity.installation_id)
    shutil.rmtree(root)
    pin_removed = remove_runtime_pin(prefix, root)
    return {
        "disposed": True,
        "state": "removed",
        "installation_id": identity.installation_id,
        "lifecycle": identity.lifecycle,
        "service_stopped": stopped,
        "logs_retained": retained,
        "runtime_pin_removed": pin_removed,
    }


def instance_failure_line(error: InstanceIdentityError | PathSafetyError) -> str:
    """Operator-facing line: bounded token first, remediation second, directive beneath.

    The directive lines come from the shared registry (ADR-030, issue #741), so an instance or
    path refusal explains what to do next in a shell exactly as it does over MCP.
    """

    from finishup.cli.exits import remediation_message
    from finishup.cli.render import render_local_recovery_lines

    reason = error.reason if isinstance(error, InstanceIdentityError) else error.reason_code
    remediation = remediation_message(reason)
    head = (
        f"{reason}: the instance root or runtime identity cannot be used as requested"
        if remediation is None
        else f"{reason}: {remediation}"
    )
    return "\n".join([head, *render_local_recovery_lines(reason)])
