"""Durable record of the last applied Codex MCP route.

The installer writes which FinishUP route (policy or strict) it applied and what the
post-write observation saw, so later drift is attributable to either the install or a
subsequent mutation. The owner-only record carries validated FinishUP argv (including an
absolute launcher and an explicit home-project prefix) and structural digests, never raw
config bytes or arbitrary user text.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.domain.values import validate_sha256_digest
from finishup.ports.harness_mcp import (
    MCP_LEGACY_SERVE_COMMAND,
    MCP_LEGACY_STRICT_SERVE_COMMAND,
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    mcp_command_profile,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode

__all__ = [
    "AppliedMcpRouteStoreError",
    "clear_applied_route",
    "read_applied_route",
    "record_applied_route",
]

# Frozen legacy identifier (ADR-048): the record tag and digest domain are stored and re-verified.
_SCHEMA: Final = "yoetz.applied-mcp-route/1"
_HOST: Final = "codex"
_STORE_DIRNAME: Final = "integrations"
_STORE_NAME: Final = "applied-mcp-routes.json"
_LOCK_NAME: Final = "applied-mcp-routes.lock"
_MAX_STORE_BYTES: Final = 8 * 1024
_RECORD_DOMAIN: Final = b"yoetz/applied-mcp-route/v1\x00"
_RECORD_KEYS: Final = frozenset(
    {
        "schema",
        "host",
        "applied_profile",
        "applied_serve_command",
        "observed_serve_command_post_write",
        "preview_digest",
        "applied_at",
        "observation_digest",
        "record_digest",
    }
)


class AppliedMcpRouteStoreError(Exception):
    """A bounded failure durably writing the applied Codex MCP route."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        if reason_code not in {
            "applied_mcp_route_store_unsafe",
            "applied_mcp_route_store_write_failed",
        }:
            raise ValueError("applied_mcp_route_reason_invalid")
        self.reason_code = reason_code
        super().__init__(reason_code)


def _store_path(root: Path | None) -> Path:
    return (state_dir() if root is None else root) / _STORE_DIRNAME / _STORE_NAME


def _expected_command(profile: str) -> tuple[str, ...]:
    return MCP_STRICT_SERVE_COMMAND if profile == "strict" else MCP_SERVE_COMMAND


def _validate_profile(value: object) -> str:
    if type(value) is not str or value not in {"policy", "strict"}:
        raise ValueError("applied_mcp_route_profile_invalid")
    return value


def _validate_command(value: object, *, allowed: tuple[tuple[str, ...], ...]) -> list[str] | None:
    if value is None:
        return None
    if type(value) is list:
        candidates: list[object] = cast(list[object], value)
    elif type(value) is tuple:
        candidates = list(cast(tuple[object, ...], value))
    else:
        raise ValueError("applied_mcp_route_command_invalid")
    items: list[str] = []
    for entry in candidates:
        if type(entry) is not str:
            raise ValueError("applied_mcp_route_command_invalid")
        items.append(entry)
    command = tuple(items)
    # Use the shared closed command classifier, including its exact-home prefix validation.
    # Comparing raw tails rejects a valid --home-project command after the adapter accepts it,
    # silently losing the applied record. Preserve the exact accepted argv in the digest.
    profile = mcp_command_profile(command)
    if profile is None or profile not in {mcp_command_profile(template) for template in allowed}:
        raise ValueError("applied_mcp_route_command_invalid")
    return items


def _validate_digest(value: object) -> str:
    if type(value) is not str:
        raise ValueError("applied_mcp_route_digest_invalid")
    try:
        validate_sha256_digest(value)
    except ValueError as exc:
        raise ValueError("applied_mcp_route_digest_invalid") from exc
    return value


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("applied_mcp_route_time_naive")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(raw: object) -> str:
    if type(raw) is not str or not raw or len(raw) > 64:
        raise ValueError("applied_mcp_route_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("applied_mcp_route_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("applied_mcp_route_timestamp_invalid")
    return raw


def _record_digest(body: Mapping[str, object]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(_RECORD_DOMAIN + canonical_encode(cast(JsonValue, body))).hexdigest()
    )


def _reject_json_constant(_value: str) -> object:
    raise ValueError("nonstandard_json_constant")


def _reject_duplicate_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate_json_key")
        parsed[key] = value
    return parsed


def _parse_document(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("applied_mcp_route_document_invalid") from exc
    try:
        loaded: object = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except ValueError as exc:
        raise ValueError("applied_mcp_route_document_invalid") from exc
    if type(loaded) is not dict:
        raise ValueError("applied_mcp_route_document_invalid")
    return cast(dict[str, object], loaded)


def _parse_record(raw: object) -> dict[str, object]:
    if type(raw) is not dict:
        raise ValueError("applied_mcp_route_record_invalid")
    row = cast(dict[str, object], raw)
    if frozenset(row) != _RECORD_KEYS:
        raise ValueError("applied_mcp_route_record_invalid")
    if row["schema"] != _SCHEMA or row["host"] != _HOST:
        raise ValueError("applied_mcp_route_record_invalid")
    profile = _validate_profile(row["applied_profile"])
    expected = _expected_command(profile)
    legacy = MCP_LEGACY_STRICT_SERVE_COMMAND if profile == "strict" else MCP_LEGACY_SERVE_COMMAND
    applied = _validate_command(row["applied_serve_command"], allowed=(expected, legacy))
    if applied is None:
        raise ValueError("applied_mcp_route_record_invalid")
    observed = _validate_command(
        row["observed_serve_command_post_write"],
        allowed=(
            MCP_SERVE_COMMAND,
            MCP_STRICT_SERVE_COMMAND,
            MCP_LEGACY_SERVE_COMMAND,
            MCP_LEGACY_STRICT_SERVE_COMMAND,
        ),
    )
    preview_digest = _validate_digest(row["preview_digest"])
    observation_digest = _validate_digest(row["observation_digest"])
    record_digest = _validate_digest(row["record_digest"])
    applied_at = _parse_timestamp(row["applied_at"])
    if observation_digest != canonical_digest(cast(JsonValue, observed)):
        raise ValueError("applied_mcp_route_record_invalid")
    body: dict[str, object] = {
        "schema": _SCHEMA,
        "host": _HOST,
        "applied_profile": profile,
        "applied_serve_command": applied,
        "observed_serve_command_post_write": observed,
        "preview_digest": preview_digest,
        "applied_at": applied_at,
        "observation_digest": observation_digest,
    }
    if not hmac.compare_digest(record_digest, _record_digest(body)):
        raise ValueError("applied_mcp_route_record_invalid")
    return {**body, "record_digest": record_digest}


@contextmanager
def _store_lock(path: Path) -> Generator[None]:
    """Serialize applied-route read-modify-write transitions across local processes."""

    lock_path = path.with_name(_LOCK_NAME)
    descriptor: int | None = None
    try:
        ensure_owner_only_dir(lock_path.parent)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            raise AppliedMcpRouteStoreError("applied_mcp_route_store_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except AppliedMcpRouteStoreError:
        raise
    except PathSafetyError as exc:
        raise AppliedMcpRouteStoreError("applied_mcp_route_store_unsafe") from exc
    except OSError as exc:
        raise AppliedMcpRouteStoreError("applied_mcp_route_store_unsafe") from exc
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _write_private_atomic(path: Path, encoded: bytes) -> None:
    ensure_owner_only_dir(path.parent)
    temporary = path.with_name(f".{path.name}.{os.urandom(12).hex()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short_write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _serialize_document(document: Mapping[str, object]) -> bytes:
    payload = canonical_encode(cast(JsonValue, document)) + b"\n"
    if len(payload) > _MAX_STORE_BYTES:
        raise AppliedMcpRouteStoreError("applied_mcp_route_store_write_failed")
    return payload


def record_applied_route(
    applied_profile: str,
    serve_command: list[str] | tuple[str, ...],
    observed_command: list[str] | tuple[str, ...] | None,
    preview_digest: str,
    *,
    _state: Path | None = None,
) -> dict[str, object]:
    """Atomically record the applied Codex MCP route; later registrations overwrite."""

    profile = _validate_profile(applied_profile)
    expected = _expected_command(profile)
    legacy = MCP_LEGACY_STRICT_SERVE_COMMAND if profile == "strict" else MCP_LEGACY_SERVE_COMMAND
    applied = _validate_command(serve_command, allowed=(expected, legacy))
    if applied is None:
        raise ValueError("applied_mcp_route_command_invalid")
    observed = _validate_command(
        observed_command,
        allowed=(
            MCP_SERVE_COMMAND,
            MCP_STRICT_SERVE_COMMAND,
            MCP_LEGACY_SERVE_COMMAND,
            MCP_LEGACY_STRICT_SERVE_COMMAND,
        ),
    )
    digest = _validate_digest(preview_digest)
    observation_digest = canonical_digest(cast(JsonValue, observed))
    body: dict[str, object] = {
        "schema": _SCHEMA,
        "host": _HOST,
        "applied_profile": profile,
        "applied_serve_command": applied,
        "observed_serve_command_post_write": observed,
        "preview_digest": digest,
        "applied_at": _timestamp_text(datetime.now(UTC)),
        "observation_digest": observation_digest,
    }
    record: dict[str, object] = {**body, "record_digest": _record_digest(body)}
    path = _store_path(_state)
    try:
        with _store_lock(path):
            try:
                raw = path.read_bytes()
            except FileNotFoundError:
                document: dict[str, object] = {}
            except OSError as exc:
                raise AppliedMcpRouteStoreError("applied_mcp_route_store_unsafe") from exc
            else:
                if not raw or len(raw) > _MAX_STORE_BYTES:
                    document = {}
                else:
                    try:
                        parsed = _parse_document(raw)
                    except ValueError:
                        # An explicit new record supersedes an unreadable file.
                        document = {}
                    else:
                        document = dict(parsed)
            # Preserve any future per-host entries; only the Codex route is ours to set.
            document[_HOST] = record
            _write_private_atomic(path, _serialize_document(document))
    except AppliedMcpRouteStoreError:
        raise
    except PathSafetyError as exc:
        raise AppliedMcpRouteStoreError("applied_mcp_route_store_unsafe") from exc
    except (OSError, ValueError) as exc:
        raise AppliedMcpRouteStoreError("applied_mcp_route_store_write_failed") from exc
    return record


def read_applied_route(*, _state: Path | None = None) -> dict[str, object] | None:
    """Return the recorded Codex route, or None when missing, corrupt, or unsafe."""

    try:
        path = _store_path(_state)
    except (OSError, PathSafetyError, ValueError):
        return None
    try:
        facts = path.lstat()
        if (
            stat.S_ISLNK(facts.st_mode)
            or not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            return None
        raw = path.read_bytes()
    except (OSError, PathSafetyError, ValueError):
        return None
    if not raw or len(raw) > _MAX_STORE_BYTES:
        return None
    try:
        document = _parse_document(raw)
    except ValueError:
        return None
    entry = document.get(_HOST)
    if entry is None:
        return None
    try:
        return _parse_record(entry)
    except ValueError:
        return None


def clear_applied_route(*, _state: Path | None = None) -> None:
    """Remove the recorded Codex route; absence is success and nothing here raises."""

    try:
        path = _store_path(_state)
    except (OSError, PathSafetyError, ValueError):
        return
    try:
        # Fast path: clearing an absent record must not create state directories.
        if not path.exists() or path.is_symlink():
            return
    except (OSError, PathSafetyError, ValueError):
        return
    try:
        with _store_lock(path):
            try:
                facts = path.lstat()
            except (FileNotFoundError, NotADirectoryError):
                return
            except OSError:
                return
            if stat.S_ISLNK(facts.st_mode) or not stat.S_ISREG(facts.st_mode):
                return
            try:
                raw = path.read_bytes()
            except OSError:
                return
            if not raw or len(raw) > _MAX_STORE_BYTES:
                with contextlib.suppress(OSError):
                    path.unlink()
                return
            try:
                document = _parse_document(raw)
            except ValueError:
                with contextlib.suppress(OSError):
                    path.unlink()
                return
            if _HOST not in document:
                return
            remaining = {key: value for key, value in document.items() if key != _HOST}
            if not remaining:
                with contextlib.suppress(OSError):
                    path.unlink()
                return
            _write_private_atomic(path, _serialize_document(remaining))
    except Exception:
        return
