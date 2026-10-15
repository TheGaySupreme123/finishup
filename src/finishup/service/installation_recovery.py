"""Owner-only managed installation-recovery sets and structural status.

The managed store is deliberately pathless at its public boundary.  A human helper may import or
export a set, but the daemon and agent-facing status identify it only by recovery generation and
digest.  Secret material never enters this module.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import stat
import urllib.parse
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final, Literal, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]
try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]

from finishup.adapters.keys.installation_recovery import (
    InstallationRecoveryArtifact,
    InstallationRecoveryMetadata,
    InstallationRecoveryMode,
    InstallationRecoverySecretKind,
)
from finishup.config.paths import ensure_owner_only_dir
from finishup.domain.values import validate_sha256_digest
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "InstallationRecoverySetStore",
    "InstallationRecoveryState",
    "InstallationRecoveryStatus",
    "OfflineInstallationRecoveryLease",
    "PreparedInstallationSnapshot",
]


class InstallationRecoveryState(str, Enum):  # noqa: UP042 - public durable spelling
    PRISTINE_SETUP = "pristine_setup"
    TEMPORARILY_LOCKED = "temporarily_locked"
    AUTO_UNLOCK_REPAIRABLE = "auto_unlock_repairable"
    RECOVERY_MATERIAL_REQUIRED = "recovery_material_required"
    RECOVERY_IN_PROGRESS = "recovery_in_progress"
    RECOVERED = "recovered"
    PERMANENTLY_UNRECOVERABLE = "permanently_unrecoverable"


_MAX_STATE_BYTES: Final = 16_384
_MAX_ARTIFACT_BYTES: Final = 16_384
_STATE_FORMAT: Final = "yoetz-installation-recovery-state/1"
_SET_FORMAT: Final = "yoetz-installation-recovery-set/1"
_DIGEST_DOMAIN: Final = b"yoetz/installation-recovery-state/v1\x00"
_SWAP_DIGEST_DOMAIN: Final = b"yoetz/installation-recovery-swap/v1\x00"
_SNAPSHOT_FORMAT: Final = "yoetz-installation-snapshot/1"
_PENDING_FORMAT: Final = "yoetz-installation-recovery-pending/1"
_ARCHIVE_FORMAT: Final = "yoetz-installation-recovery-set/1"
_MAX_ARCHIVE_MEMBERS: Final = 100_000
_MAX_ARCHIVE_MEMBER_BYTES: Final = 8 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class InstallationRecoveryStatus:
    state: InstallationRecoveryState
    reason: str
    active_generation: int | None
    available_modes: tuple[Literal["compact", "self_contained"], ...]
    continuation_id: str | None
    next_command: str | None

    def __post_init__(self) -> None:
        if type(self.state) is not InstallationRecoveryState:
            raise ValueError("installation_recovery_status_invalid")
        if (
            type(self.reason) is not str
            or not self.reason
            or len(self.reason) > 128
            or not self.reason.replace("_", "").isalnum()
        ):
            raise ValueError("installation_recovery_status_invalid")
        if self.active_generation is not None and (
            type(self.active_generation) is not int or self.active_generation <= 0
        ):
            raise ValueError("installation_recovery_status_invalid")
        if (
            type(self.available_modes) is not tuple
            or tuple(sorted(set(self.available_modes))) != self.available_modes
            or any(mode not in {"compact", "self_contained"} for mode in self.available_modes)
        ):
            raise ValueError("installation_recovery_status_invalid")
        for value in (self.continuation_id, self.next_command):
            if value is not None and (type(value) is not str or not value or len(value) > 256):
                raise ValueError("installation_recovery_status_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class PreparedInstallationSnapshot:
    recovery_generation: int
    manifest_digest: str
    item_count: int
    total_bytes: int
    _stage: Path

    def __post_init__(self) -> None:
        if type(self.recovery_generation) is not int or self.recovery_generation <= 0:
            raise ValueError("installation_snapshot_invalid")
        validate_sha256_digest(self.manifest_digest)
        if (
            type(self.item_count) is not int
            or self.item_count <= 0
            or type(self.total_bytes) is not int
            or self.total_bytes <= 0
        ):
            raise ValueError("installation_snapshot_invalid")


class OfflineInstallationRecoveryLease:
    """Cross-process exclusion for clean-profile import and directory switching."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._descriptor = -1

    def __enter__(self) -> OfflineInstallationRecoveryLease:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif msvcrt is not None:
                windows_msvcrt = cast(Any, msvcrt)
                os.lseek(descriptor, 0, os.SEEK_SET)
                os.write(descriptor, b"\x00")
                os.lseek(descriptor, 0, os.SEEK_SET)
                windows_msvcrt.locking(descriptor, windows_msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - supported platforms provide one primitive
                raise OSError("installation_recovery_lock_unavailable")
        except (BlockingIOError, OSError) as exc:
            os.close(descriptor)
            raise RuntimeError("service_must_be_stopped_for_recovery") from exc
        self._descriptor = descriptor
        return self

    def __exit__(self, *_args: object) -> None:
        descriptor, self._descriptor = self._descriptor, -1
        if descriptor < 0:
            return
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            elif msvcrt is not None:
                windows_msvcrt = cast(Any, msvcrt)
                os.lseek(descriptor, 0, os.SEEK_SET)
                windows_msvcrt.locking(descriptor, windows_msvcrt.LK_UNLCK, 1)
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _StateRecord:
    active_generation: int
    available_modes: tuple[Literal["compact", "self_contained"], ...]
    lifecycle: Literal["provisioned", "recovering", "recovered", "revoked"]
    continuation_id: str | None
    record_digest: str

    def __post_init__(self) -> None:
        if type(self.active_generation) is not int or self.active_generation <= 0:
            raise ValueError("recovery_state_invalid")
        if (
            type(self.available_modes) is not tuple
            or tuple(sorted(set(self.available_modes))) != self.available_modes
            or any(mode not in {"compact", "self_contained"} for mode in self.available_modes)
        ):
            raise ValueError("recovery_state_invalid")
        if self.lifecycle not in {"provisioned", "recovering", "recovered", "revoked"}:
            raise ValueError("recovery_state_invalid")
        if (self.lifecycle == "recovering") != (self.continuation_id is not None):
            raise ValueError("recovery_state_invalid")
        validate_sha256_digest(self.record_digest)
        if self.record_digest != _state_digest(self.body()):
            raise ValueError("recovery_state_invalid")

    def body(self) -> dict[str, JsonValue]:
        return {
            "active_generation": self.active_generation,
            "available_modes": list(self.available_modes),
            "continuation_id": self.continuation_id,
            "format": _STATE_FORMAT,
            "lifecycle": self.lifecycle,
        }

    def encode(self) -> bytes:
        body = self.body()
        body["record_digest"] = self.record_digest
        return canonical_encode(body) + b"\n"

    @classmethod
    def create(
        cls,
        active_generation: int,
        available_modes: tuple[Literal["compact", "self_contained"], ...],
        lifecycle: Literal["provisioned", "recovering", "recovered", "revoked"],
        continuation_id: str | None,
    ) -> _StateRecord:
        body: dict[str, JsonValue] = {
            "active_generation": active_generation,
            "available_modes": list(available_modes),
            "continuation_id": continuation_id,
            "format": _STATE_FORMAT,
            "lifecycle": lifecycle,
        }
        return cls(
            active_generation,
            available_modes,
            lifecycle,
            continuation_id,
            _state_digest(body),
        )

    @classmethod
    def decode(cls, encoded: bytes) -> _StateRecord:
        try:
            if (
                not encoded.endswith(b"\n")
                or encoded.endswith(b"\n\n")
                or len(encoded) > _MAX_STATE_BYTES
            ):
                raise ValueError
            value = strict_json_parse(encoded[:-1])
            if type(value) is not dict:
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            if canonical_encode(source) != encoded[:-1]:
                raise ValueError
            if (
                set(source)
                != {
                    "active_generation",
                    "available_modes",
                    "continuation_id",
                    "format",
                    "lifecycle",
                    "record_digest",
                }
                or source["format"] != _STATE_FORMAT
            ):
                raise ValueError
            modes = source["available_modes"]
            if type(modes) is not list or any(type(mode) is not str for mode in modes):
                raise ValueError
            continuation = source["continuation_id"]
            if continuation is not None and type(continuation) is not str:
                raise ValueError
            generation = source["active_generation"]
            lifecycle = source["lifecycle"]
            digest = source["record_digest"]
            if type(generation) is not int or type(lifecycle) is not str or type(digest) is not str:
                raise ValueError
            return cls(
                generation,
                cast(tuple[Literal["compact", "self_contained"], ...], tuple(modes)),
                cast(Literal["provisioned", "recovering", "recovered", "revoked"], lifecycle),
                continuation,
                digest,
            )
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ValueError("recovery_state_invalid") from exc


def _state_digest(body: dict[str, JsonValue]) -> str:
    return "sha256:" + hashlib.sha256(_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()


def _clean_restore_record(metadata: InstallationRecoveryMetadata) -> bytes:
    body: dict[str, JsonValue] = {
        "artifact_digest": metadata.artifact_digest,
        "format": "yoetz-installation-clean-restore/1",
        "mode": metadata.mode.value,
        "recovery_generation": metadata.recovery_generation,
        "secret_kind": metadata.secret_kind.value,
        "snapshot_manifest_digest": metadata.snapshot_manifest_digest,
    }
    body["record_digest"] = (
        "sha256:" + hashlib.sha256(_SWAP_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()
    )
    return canonical_encode(body) + b"\n"


def _read_clean_restore_record(path: Path) -> InstallationRecoveryMetadata:
    encoded = _read_private(path, _MAX_STATE_BYTES)
    if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
        raise ValueError("installation_clean_restore_invalid")
    value = strict_json_parse(encoded[:-1])
    if type(value) is not dict:
        raise ValueError("installation_clean_restore_invalid")
    source = cast(dict[str, JsonValue], value)
    if canonical_encode(source) != encoded[:-1] or set(source) != {
        "artifact_digest",
        "format",
        "mode",
        "record_digest",
        "recovery_generation",
        "secret_kind",
        "snapshot_manifest_digest",
    }:
        raise ValueError("installation_clean_restore_invalid")
    body = dict(source)
    record = body.pop("record_digest")
    expected = "sha256:" + hashlib.sha256(_SWAP_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()
    if source["format"] != "yoetz-installation-clean-restore/1" or record != expected:
        raise ValueError("installation_clean_restore_invalid")
    generation = source["recovery_generation"]
    mode = source["mode"]
    kind = source["secret_kind"]
    artifact_digest = source["artifact_digest"]
    snapshot = source["snapshot_manifest_digest"]
    if (
        type(generation) is not int
        or type(mode) is not str
        or type(kind) is not str
        or type(artifact_digest) is not str
        or type(snapshot) is not str
    ):
        raise ValueError("installation_clean_restore_invalid")
    return InstallationRecoveryMetadata(
        generation,
        InstallationRecoveryMode(mode),
        InstallationRecoverySecretKind(kind),
        artifact_digest,
        snapshot,
    )


@dataclass(frozen=True, slots=True)
class _PendingImport:
    """One staged-but-unauthenticated imported generation and its in-flight restore, if any.

    An imported archive header is not evidence: anyone able to write a file can offer a
    higher-numbered set.  The pending record keeps that material addressable without letting it
    become installation authority, so the previously active generation survives a wrong import.
    """

    metadata: InstallationRecoveryMetadata
    continuation_id: str | None

    def __post_init__(self) -> None:
        if type(self.metadata) is not InstallationRecoveryMetadata:
            raise TypeError("installation_recovery_pending_invalid")
        if self.continuation_id is not None and (
            type(self.continuation_id) is not str or not self.continuation_id
        ):
            raise ValueError("installation_recovery_pending_invalid")

    def body(self) -> dict[str, JsonValue]:
        return {
            "artifact_digest": self.metadata.artifact_digest,
            "continuation_id": self.continuation_id,
            "format": _PENDING_FORMAT,
            "mode": self.metadata.mode.value,
            "recovery_generation": self.metadata.recovery_generation,
            "secret_kind": self.metadata.secret_kind.value,
            "snapshot_manifest_digest": self.metadata.snapshot_manifest_digest,
        }

    def encode(self) -> bytes:
        body = self.body()
        body["record_digest"] = (
            "sha256:" + hashlib.sha256(_SWAP_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()
        )
        return canonical_encode(body) + b"\n"

    @classmethod
    def decode(cls, encoded: bytes) -> _PendingImport:
        try:
            if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
                raise ValueError
            value = strict_json_parse(encoded[:-1])
            if type(value) is not dict:
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            if canonical_encode(source) != encoded[:-1] or set(source) != {
                "artifact_digest",
                "continuation_id",
                "format",
                "mode",
                "record_digest",
                "recovery_generation",
                "secret_kind",
                "snapshot_manifest_digest",
            }:
                raise ValueError
            body = dict(source)
            record = body.pop("record_digest")
            expected = (
                "sha256:" + hashlib.sha256(_SWAP_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()
            )
            generation = source["recovery_generation"]
            mode = source["mode"]
            kind = source["secret_kind"]
            artifact_digest = source["artifact_digest"]
            snapshot = source["snapshot_manifest_digest"]
            continuation = source["continuation_id"]
            if (
                source["format"] != _PENDING_FORMAT
                or type(record) is not str
                or record != expected
                or type(generation) is not int
                or type(mode) is not str
                or type(kind) is not str
                or type(artifact_digest) is not str
                or (snapshot is not None and type(snapshot) is not str)
                or (continuation is not None and type(continuation) is not str)
            ):
                raise ValueError
            return cls(
                InstallationRecoveryMetadata(
                    generation,
                    InstallationRecoveryMode(mode),
                    InstallationRecoverySecretKind(kind),
                    artifact_digest,
                    snapshot,
                ),
                continuation,
            )
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ValueError("installation_recovery_pending_invalid") from exc


class InstallationRecoverySetStore:
    """Crash-safe owner of daemon-managed recovery artifacts and their structural marker."""

    def __init__(self, bundle_root: Path) -> None:
        self._root = bundle_root / "installation-recovery"
        self._sets = self._root / "sets"
        self._state_path = self._root / "state.json"
        self._clean_restore_path = self._root / "clean-restore.json"
        self._pending_path = self._root / "pending-import.json"

    def publish(self, artifact: InstallationRecoveryArtifact) -> InstallationRecoveryMetadata:
        """Publish one verified artifact generation without overwriting any older generation."""

        metadata = self.stage(artifact)
        self.activate(metadata)
        return metadata

    def stage(
        self,
        artifact: InstallationRecoveryArtifact,
        snapshot: PreparedInstallationSnapshot | None = None,
    ) -> InstallationRecoveryMetadata:
        """Durably stage and reopen one artifact without advertising it as provisioned."""

        if type(artifact) is not InstallationRecoveryArtifact:
            raise TypeError("installation_recovery_artifact_invalid")
        metadata = _metadata_from_artifact(artifact)
        if (metadata.mode is InstallationRecoveryMode.SELF_CONTAINED) != (snapshot is not None):
            raise ValueError("installation_recovery_snapshot_mismatch")
        if snapshot is not None and (
            snapshot.recovery_generation != metadata.recovery_generation
            or snapshot.manifest_digest != metadata.snapshot_manifest_digest
        ):
            raise ValueError("installation_recovery_snapshot_mismatch")
        ensure_owner_only_dir(self._root)
        ensure_owner_only_dir(self._sets)
        target = self._sets / str(metadata.recovery_generation)
        if target.exists():
            # A failure or crash between staging and commit leaves a directory no durable marker
            # points at.  Refusing it forever would wedge every later attempt at the same
            # generation number, because the next attempt recomputes the same number, so reclaim
            # orphaned material and refuse only a genuine collision with published authority.
            if not self._generation_is_orphaned(metadata.recovery_generation):
                raise FileExistsError("installation_recovery_generation_exists")
            _remove_stage(target)
            _fsync_dir(self._sets)
        stage = self._sets / f".{metadata.recovery_generation}.{secrets.token_hex(16)}.tmp"
        try:
            ensure_owner_only_dir(stage)
            _write_exclusive(stage / "artifact.yir", artifact.canonical_bytes)
            if snapshot is not None:
                os.rename(snapshot._stage, stage / "snapshot")  # pyright: ignore[reportPrivateUsage]
            descriptor = os.open(stage, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.rename(stage, target)
            _fsync_dir(self._sets)
            loaded = self.load(metadata.recovery_generation)
            if loaded.canonical_bytes != artifact.canonical_bytes:
                raise OSError("installation_recovery_publish_verify_failed")
            return metadata
        finally:
            # The stage holds an artifact file (and, for a self-contained set, a whole snapshot
            # tree) whenever publication failed part-way, so an empty-directory removal would
            # silently leak it.
            _remove_stage(stage)

    def _generation_is_orphaned(self, recovery_generation: int) -> bool:
        """Return whether no durable marker claims this staged generation."""

        state = self._load_state_optional()
        if state is not None and recovery_generation <= state.active_generation:
            return False
        pending = self._pending_import_optional()
        return pending is None or pending.metadata.recovery_generation != recovery_generation

    def discard_staged_generation(self, recovery_generation: int) -> None:
        """Remove one staged-but-unpublished generation after a failed provision or rotation.

        Material any durable marker still points at is never removed: only a stage nothing
        advertises is disposable.  Without this, an interrupted attempt leaves a directory that
        makes the identical retry fail with `installation_recovery_generation_exists` forever.
        """

        if type(recovery_generation) is not int or recovery_generation <= 0:
            raise ValueError("recovery_generation_invalid")
        if not self._generation_is_orphaned(recovery_generation):
            return
        target = self._sets / str(recovery_generation)
        if not target.exists():
            return
        _remove_stage(target)
        _fsync_dir(self._sets)

    def prepare_snapshot(
        self,
        recovery_generation: int,
        *,
        vault_override: Path | None = None,
    ) -> PreparedInstallationSnapshot:
        """Create a manifest-last, per-database online snapshot of installation-owned state."""

        if type(recovery_generation) is not int or recovery_generation <= 0:
            raise ValueError("recovery_generation_invalid")
        ensure_owner_only_dir(self._root)
        stage = self._root / f".snapshot.{recovery_generation}.{secrets.token_hex(16)}.tmp"
        payload = stage / "members"
        ensure_owner_only_dir(stage)
        ensure_owner_only_dir(payload)
        entries: list[dict[str, JsonValue]] = []
        try:
            for source in sorted(
                self._bundle_files(vault_override=vault_override), key=lambda item: item[0]
            ):
                logical_name, path = source
                destination = payload / logical_name
                ensure_owner_only_dir(destination.parent)
                if path.name.endswith((".sqlite3-wal", ".sqlite3-shm")):
                    continue
                if path.suffix == ".sqlite3":
                    _backup_sqlite(path, destination)
                    member_kind = "sqlite_backup"
                else:
                    _copy_private_file(path, destination)
                    member_kind = "ciphertext_or_structural"
                encoded_digest, size = _file_digest(destination)
                entries.append(
                    {
                        "kind": member_kind,
                        "logical_name": logical_name,
                        "sha256_digest": encoded_digest,
                        "size_bytes": size,
                    }
                )
            if not entries:
                raise ValueError("installation_snapshot_empty")
            manifest: dict[str, JsonValue] = {
                "format": _SNAPSHOT_FORMAT,
                "members": cast(list[JsonValue], entries),
                "recovery_generation": recovery_generation,
                "total_bytes": sum(cast(int, entry["size_bytes"]) for entry in entries),
            }
            manifest_bytes = canonical_encode(manifest)
            digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            _write_exclusive(stage / "manifest.json", manifest_bytes)
            _fsync_tree(payload)
            _fsync_dir(stage)
            prepared = PreparedInstallationSnapshot(
                recovery_generation,
                digest,
                len(entries),
                cast(int, manifest["total_bytes"]),
                stage,
            )
            self._verify_prepared_snapshot(prepared)
            return prepared
        except BaseException:
            _remove_stage(stage)
            raise

    def discard_snapshot(self, snapshot: PreparedInstallationSnapshot) -> None:
        """Remove a not-yet-published quarantine after cancellation or stale preview."""

        if type(snapshot) is not PreparedInstallationSnapshot:
            raise TypeError("installation_snapshot_invalid")
        _remove_stage(snapshot._stage)  # pyright: ignore[reportPrivateUsage]

    def _bundle_files(self, *, vault_override: Path | None = None) -> tuple[tuple[str, Path], ...]:
        members: list[tuple[str, Path]] = []
        allowed_top_level = {
            "catalog.sqlite3",
            "catalog.sqlite3-shm",
            "catalog.sqlite3-wal",
            "installation-recovery",
            "installation-state.json",
            "tasks",
            "vault",
        }
        if vault_override is not None:
            if (
                vault_override.parent != self._root.parent
                or not vault_override.name.startswith(".vault.root-")
                or not vault_override.name.endswith(".tmp")
            ):
                raise ValueError("installation_snapshot_vault_override_invalid")
            allowed_top_level.add(vault_override.name)
        for child in self._root.parent.iterdir():
            if child.name not in allowed_top_level:
                raise ValueError("installation_snapshot_unknown_member")
        for path in self._root.parent.rglob("*"):
            try:
                path.relative_to(self._root)
            except ValueError:
                pass
            else:
                continue
            if vault_override is not None:
                try:
                    path.relative_to(self._root.parent / "vault")
                except ValueError:
                    pass
                else:
                    continue
                try:
                    path.relative_to(vault_override)
                except ValueError:
                    pass
                else:
                    continue
            facts = path.lstat()
            if stat.S_ISLNK(facts.st_mode):
                raise PermissionError("installation_snapshot_symlink_forbidden")
            if stat.S_ISDIR(facts.st_mode):
                continue
            if not stat.S_ISREG(facts.st_mode):
                continue
            _verify_private_facts(facts)
            logical_name = path.relative_to(self._root.parent).as_posix()
            if logical_name.startswith("../") or logical_name.startswith("/"):
                raise ValueError("installation_snapshot_path_invalid")
            members.append((logical_name, path))
        if vault_override is not None:
            if not vault_override.is_dir():
                raise ValueError("installation_snapshot_vault_override_invalid")
            for path in vault_override.rglob("*"):
                facts = path.lstat()
                if stat.S_ISLNK(facts.st_mode):
                    raise PermissionError("installation_snapshot_symlink_forbidden")
                if stat.S_ISDIR(facts.st_mode):
                    continue
                if not stat.S_ISREG(facts.st_mode):
                    raise PermissionError("installation_snapshot_member_unsafe")
                _verify_private_facts(facts)
                logical_name = "vault/" + path.relative_to(vault_override).as_posix()
                members.append((logical_name, path))
        return tuple(members)

    @staticmethod
    def _verify_prepared_snapshot(snapshot: PreparedInstallationSnapshot) -> None:
        manifest_path = snapshot._stage / "manifest.json"  # pyright: ignore[reportPrivateUsage]
        manifest = _read_private(manifest_path, 4_194_304)
        if "sha256:" + hashlib.sha256(manifest).hexdigest() != snapshot.manifest_digest:
            raise ValueError("installation_snapshot_manifest_invalid")
        value = strict_json_parse(manifest)
        if type(value) is not dict:
            raise ValueError("installation_snapshot_manifest_invalid")
        source = cast(dict[str, JsonValue], value)
        if canonical_encode(source) != manifest:
            raise ValueError("installation_snapshot_manifest_invalid")
        members = source.get("members")
        if source.get("format") != _SNAPSHOT_FORMAT or type(members) is not list:
            raise ValueError("installation_snapshot_manifest_invalid")
        for value_member in members:
            if type(value_member) is not dict:
                raise ValueError("installation_snapshot_manifest_invalid")
            member = cast(dict[str, JsonValue], value_member)
            logical_name = member.get("logical_name")
            expected_digest = member.get("sha256_digest")
            expected_size = member.get("size_bytes")
            if (
                type(logical_name) is not str
                or type(expected_digest) is not str
                or type(expected_size) is not int
            ):
                raise ValueError("installation_snapshot_manifest_invalid")
            observed_digest, observed_size = _file_digest(
                snapshot._stage / "members" / logical_name  # pyright: ignore[reportPrivateUsage]
            )
            if observed_digest != expected_digest or observed_size != expected_size:
                raise ValueError("installation_snapshot_member_invalid")

    def activate(self, metadata: InstallationRecoveryMetadata) -> None:
        """Advertise a stage only after the vault committed matching encrypted metadata."""

        if type(metadata) is not InstallationRecoveryMetadata:
            raise TypeError("installation_recovery_metadata_invalid")
        artifact = self.load(metadata.recovery_generation)
        observed = _metadata_from_artifact(artifact)
        if observed != metadata:
            raise RuntimeError("installation_recovery_metadata_mismatch")
        previous = self._load_state_optional()
        if (
            previous is not None
            and previous.active_generation == metadata.recovery_generation
            and previous.lifecycle in {"provisioned", "recovered"}
            and metadata.mode.value in previous.available_modes
        ):
            return
        if previous is not None and metadata.recovery_generation <= previous.active_generation:
            raise RuntimeError("installation_recovery_generation_stale")
        modes = (metadata.mode.value,)
        record = _StateRecord.create(
            metadata.recovery_generation,
            cast(tuple[Literal["compact", "self_contained"], ...], modes),
            "provisioned",
            None,
        )
        _write_atomic(self._state_path, record.encode())

    def revoke(self, recovery_generation: int) -> None:
        """Withdraw the active managed generation while retaining ciphertext for audit/rollback."""

        state = self._load_state()
        if state.active_generation != recovery_generation or state.lifecycle not in {
            "provisioned",
            "recovered",
            "revoked",
        }:
            raise RuntimeError("installation_recovery_state_conflict")
        if state.lifecycle == "revoked":
            return
        _write_atomic(
            self._state_path,
            _StateRecord.create(
                state.active_generation,
                state.available_modes,
                "revoked",
                None,
            ).encode(),
        )

    def load(self, recovery_generation: int) -> InstallationRecoveryArtifact:
        if type(recovery_generation) is not int or recovery_generation <= 0:
            raise ValueError("recovery_generation_invalid")
        path = self._sets / str(recovery_generation) / "artifact.yir"
        return InstallationRecoveryArtifact(_read_private(path, _MAX_ARTIFACT_BYTES))

    def metadata(self, recovery_generation: int) -> InstallationRecoveryMetadata:
        """Return only the canonical artifact's nonsecret public binding."""

        return _metadata_from_artifact(self.load(recovery_generation))

    def export_generation(self, recovery_generation: int, destination: Path) -> str:
        """Export one encrypted set to a create-only archive and return only its digest."""

        metadata = self.metadata(recovery_generation)
        source = self._sets / str(recovery_generation)
        if destination.exists():
            raise FileExistsError("installation_recovery_export_exists")
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "w+b", closefd=False) as stream:
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
                    archive.comment = _ARCHIVE_FORMAT.encode("ascii")
                    _zip_add_private(archive, source / "artifact.yir", "artifact.yir")
                    if metadata.mode is InstallationRecoveryMode.SELF_CONTAINED:
                        snapshot = source / "snapshot"
                        _zip_add_private(
                            archive, snapshot / "manifest.json", "snapshot/manifest.json"
                        )
                        for member in sorted((snapshot / "members").rglob("*")):
                            if member.is_file():
                                logical = member.relative_to(snapshot / "members").as_posix()
                                _zip_add_private(
                                    archive,
                                    member,
                                    f"snapshot/members/{logical}",
                                )
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            digest, _size = _file_digest(destination)
            return digest
        except Exception:
            try:
                destination.unlink()
            except OSError:
                pass
            raise

    def import_archive(self, source: Path) -> InstallationRecoveryMetadata:
        """Validate and stage one external archive without trusting member paths or modes."""

        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        incoming = self._root / f".import.{secrets.token_hex(16)}.tmp"
        snapshot_stage = incoming / "snapshot"
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode):
                raise ValueError("installation_recovery_import_invalid")
            ensure_owner_only_dir(self._root)
            ensure_owner_only_dir(incoming)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                with zipfile.ZipFile(stream, "r") as archive:
                    if archive.comment != _ARCHIVE_FORMAT.encode("ascii"):
                        raise ValueError("installation_recovery_import_invalid")
                    infos = archive.infolist()
                    if not 1 <= len(infos) <= _MAX_ARCHIVE_MEMBERS:
                        raise ValueError("installation_recovery_import_invalid")
                    names = [info.filename for info in infos]
                    if len(set(names)) != len(names) or "artifact.yir" not in names:
                        raise ValueError("installation_recovery_import_invalid")
                    for info in infos:
                        _validate_archive_member(info)
                        destination = incoming / info.filename
                        ensure_owner_only_dir(destination.parent)
                        _extract_archive_member(archive, info, destination)
            artifact = InstallationRecoveryArtifact(
                _read_private(incoming / "artifact.yir", _MAX_ARTIFACT_BYTES)
            )
            metadata = _metadata_from_artifact(artifact)
            prepared: PreparedInstallationSnapshot | None = None
            snapshot_names = {name for name in names if name.startswith("snapshot/")}
            if metadata.mode is InstallationRecoveryMode.SELF_CONTAINED:
                if "snapshot/manifest.json" not in snapshot_names:
                    raise ValueError("installation_recovery_import_invalid")
                item_count, total_bytes, digest = _snapshot_facts(snapshot_stage)
                if digest != metadata.snapshot_manifest_digest:
                    raise ValueError("installation_recovery_import_invalid")
                prepared = PreparedInstallationSnapshot(
                    metadata.recovery_generation,
                    digest,
                    item_count,
                    total_bytes,
                    snapshot_stage,
                )
                self._verify_prepared_snapshot(prepared)
            elif snapshot_names:
                raise ValueError("installation_recovery_import_invalid")
            # Only file contents were fsynced during extraction.  The snapshot tree is renamed
            # into the published set by `stage`, so its directories must be durable first.
            _fsync_tree(incoming)
            staged_metadata = self.stage(artifact, prepared)
            # Deliberately not activated: the archive header is unauthenticated, so an imported
            # set stays pending until the restore ceremony proves it with a real secret.
            self._write_pending(_PendingImport(staged_metadata, None))
            return staged_metadata
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            raise ValueError("installation_recovery_import_invalid") from exc
        finally:
            os.close(descriptor)
            _remove_stage(incoming)

    def install_snapshot_into_pristine(self, recovery_generation: int) -> str:
        """Atomically install one imported snapshot into a marker-free profile.

        The original profile directory is renamed, never overwritten.  A private sibling journal
        makes the two directory renames roll-forward recoverable after process or machine failure.
        """

        bundle = self._root.parent
        _reconcile_snapshot_install(bundle)
        if (bundle / "installation-state.json").exists():
            artifact = self.load(recovery_generation)
            metadata = self.metadata(recovery_generation)
            if (
                self.admits_clean_restore(artifact)
                and metadata.snapshot_manifest_digest is not None
            ):
                return metadata.snapshot_manifest_digest
            raise RuntimeError("installation_recovery_target_not_pristine")
        metadata = self.metadata(recovery_generation)
        if metadata.mode is not InstallationRecoveryMode.SELF_CONTAINED:
            raise RuntimeError("installation_recovery_snapshot_required")
        source_set = self._sets / str(recovery_generation)
        snapshot = source_set / "snapshot"
        item_count, _total_bytes, manifest_digest = _snapshot_facts(snapshot)
        if item_count <= 0 or manifest_digest != metadata.snapshot_manifest_digest:
            raise ValueError("installation_snapshot_manifest_invalid")
        unexpected = [path for path in bundle.iterdir() if path.name != "installation-recovery"]
        if unexpected:
            raise RuntimeError("installation_recovery_target_ambiguous")
        token = secrets.token_hex(16)
        stage = bundle.parent / f".{bundle.name}.recovery-target.{token}"
        backup = bundle.parent / f".{bundle.name}.pristine-before-recovery.{token}"
        journal = bundle.parent / f".{bundle.name}.recovery-journal.json"
        if stage.exists() or backup.exists() or journal.exists():
            raise RuntimeError("installation_recovery_target_ambiguous")
        ensure_owner_only_dir(stage)
        try:
            for member in (snapshot / "members").rglob("*"):
                if not member.is_file():
                    continue
                logical = member.relative_to(snapshot / "members")
                destination = stage / logical
                ensure_owner_only_dir(destination.parent)
                _copy_private_file(member, destination)
            recovery_target = stage / "installation-recovery"
            ensure_owner_only_dir(recovery_target)
            ensure_owner_only_dir(recovery_target / "sets")
            _copy_private_tree(source_set, recovery_target / "sets" / str(recovery_generation))
            if self._state_path.exists():
                _copy_private_file(self._state_path, recovery_target / "state.json")
            pending = self._pending_import_optional()
            if pending is not None:
                _write_exclusive(recovery_target / "pending-import.json", pending.encode())
            _write_exclusive(
                recovery_target / "clean-restore.json",
                _clean_restore_record(metadata),
            )
            if not (stage / "installation-state.json").exists():
                raise ValueError("installation_snapshot_marker_missing")
            _fsync_tree(stage)
            _write_swap_journal(
                journal,
                bundle_name=bundle.name,
                stage_name=stage.name,
                backup_name=backup.name,
                phase="prepared",
            )
            os.rename(bundle, backup)
            _fsync_dir(bundle.parent)
            _write_swap_journal(
                journal,
                bundle_name=bundle.name,
                stage_name=stage.name,
                backup_name=backup.name,
                phase="old_moved",
            )
            os.rename(stage, bundle)
            _fsync_dir(bundle.parent)
            _write_swap_journal(
                journal,
                bundle_name=bundle.name,
                stage_name=stage.name,
                backup_name=backup.name,
                phase="installed",
            )
            if not (bundle / "installation-state.json").exists():
                raise ValueError("installation_snapshot_marker_missing")
            journal.unlink()
            _fsync_dir(bundle.parent)
            return manifest_digest
        except BaseException:
            # Leave the journal/stage/backup intact once publication began.  The next explicit
            # recovery invocation rolls it forward; before that point a local stage is disposable.
            if not journal.exists():
                _remove_stage(stage)
            raise

    def begin_recovery(self, recovery_generation: int) -> str:
        pending = self._pending_import_optional()
        if pending is not None and pending.metadata.recovery_generation == recovery_generation:
            # An imported set is not installation authority yet, so its ceremony is tracked on
            # the pending record alone.  Nothing in `state.json` moves, which is what keeps a
            # failed or abandoned attempt from disturbing the generation already in force.
            continuation = secrets.token_hex(32)
            self._write_pending(_PendingImport(pending.metadata, continuation))
            return continuation
        state = self._load_state()
        if state.active_generation != recovery_generation or state.lifecycle not in {
            "provisioned",
            "recovered",
        }:
            raise RuntimeError("installation_recovery_state_conflict")
        continuation = secrets.token_hex(32)
        _write_atomic(
            self._state_path,
            _StateRecord.create(
                state.active_generation,
                state.available_modes,
                "recovering",
                continuation,
            ).encode(),
        )
        return continuation

    def finish_recovery(self, continuation_id: str, *, success: bool) -> None:
        pending = self._pending_import_optional()
        if pending is not None and pending.continuation_id == continuation_id:
            # A successful restore already published the set at its marker-commit point, which
            # clears the pending record; reaching here means the attempt did not commit, so the
            # set simply returns to pending and stays retryable.
            self._write_pending(_PendingImport(pending.metadata, None))
            return
        state = self._load_state()
        if success and state.lifecycle == "recovered":
            return
        if state.lifecycle != "recovering" or state.continuation_id != continuation_id:
            raise RuntimeError("installation_recovery_state_conflict")
        if success:
            self.finalize_committed_recovery(state.active_generation)
            return
        _write_atomic(
            self._state_path,
            _StateRecord.create(
                state.active_generation,
                state.available_modes,
                "provisioned",
                None,
            ).encode(),
        )

    def finalize_committed_recovery(self, recovery_generation: int) -> None:
        """Idempotently finish state after the installation marker selected recovery.

        This runs at the marker-commit point, which is downstream of artifact authentication, so
        it is the first moment an imported set has proven it belongs to this installation and the
        only place an import is allowed to become the active generation.
        """

        published = False
        pending = self._pending_import_optional()
        if pending is not None and pending.metadata.recovery_generation == recovery_generation:
            self.activate(pending.metadata)
            self._clear_pending()
            published = True
        state = self._load_state()
        if state.active_generation != recovery_generation:
            raise RuntimeError("installation_recovery_state_conflict")
        if state.lifecycle == "recovered":
            return
        if state.lifecycle != "recovering" and not (published and state.lifecycle == "provisioned"):
            raise RuntimeError("installation_recovery_state_conflict")
        self._mark_recovered(state)

    def rollback_interrupted_recovery(self, recovery_generation: int) -> None:
        """Return an uncommitted restart-interrupted ceremony to provisioned state."""

        pending = self._pending_import_optional()
        if pending is not None and pending.metadata.recovery_generation == recovery_generation:
            # Nothing was published, so the generation already in force is intact by
            # construction; the import only stops claiming an attempt is under way.
            if pending.continuation_id is not None:
                self._write_pending(_PendingImport(pending.metadata, None))
            return
        state = self._load_state()
        if state.active_generation != recovery_generation:
            raise RuntimeError("installation_recovery_state_conflict")
        if state.lifecycle == "provisioned":
            return
        if state.lifecycle != "recovering":
            raise RuntimeError("installation_recovery_state_conflict")
        _write_atomic(
            self._state_path,
            _StateRecord.create(
                state.active_generation,
                state.available_modes,
                "provisioned",
                None,
            ).encode(),
        )

    def admits_clean_restore(self, artifact: InstallationRecoveryArtifact) -> bool:
        """Return whether the active bundle is a manifest-verified imported quarantine."""

        try:
            observed = _read_clean_restore_record(self._clean_restore_path)
            metadata = _metadata_from_artifact(artifact)
            state = self._load_state_optional()
            pending = self._pending_import_optional()
            # A quarantine installed from a still-pending import has no published state yet, so
            # either durable marker may name the generation this artifact belongs to.
            selected = (
                state is not None and state.active_generation == metadata.recovery_generation
            ) or (
                pending is not None
                and pending.metadata.recovery_generation == metadata.recovery_generation
            )
            return (
                observed == metadata
                and selected
                and metadata.mode is InstallationRecoveryMode.SELF_CONTAINED
            )
        except FileNotFoundError, OSError, TypeError, ValueError:
            return False

    def status(
        self,
        *,
        installation_exists: bool,
        vault_ready: bool,
        ordinary_unlock_available: bool,
        auto_unlock_repairable: bool,
        proven_unrecoverable: bool = False,
    ) -> InstallationRecoveryStatus:
        state = self._load_state_optional()
        pending = self._pending_import_optional()
        if (
            pending is not None
            and not vault_ready
            and (state is None or pending.metadata.recovery_generation > state.active_generation)
        ):
            # A pending import is the exact material the next restore consumes, so it must be
            # visible; it is deliberately not reported as an active generation.
            return InstallationRecoveryStatus(
                InstallationRecoveryState.RECOVERY_MATERIAL_REQUIRED,
                "imported_set_pending_restore",
                pending.metadata.recovery_generation,
                (pending.metadata.mode.value,),
                pending.continuation_id,
                "finishup service recovery restore",
            )
        if not installation_exists:
            if state is not None:
                if state.lifecycle == "revoked":
                    return InstallationRecoveryStatus(
                        InstallationRecoveryState.PRISTINE_SETUP,
                        "recovery_material_revoked",
                        state.active_generation,
                        (),
                        None,
                        "finishup service initialize-passphrase",
                    )
                has_snapshot = "self_contained" in state.available_modes
                return InstallationRecoveryStatus(
                    InstallationRecoveryState.RECOVERY_MATERIAL_REQUIRED,
                    "imported_snapshot_ready" if has_snapshot else "encrypted_state_copy_required",
                    state.active_generation,
                    state.available_modes,
                    None,
                    "finishup service recovery restore" if has_snapshot else None,
                )
            return InstallationRecoveryStatus(
                InstallationRecoveryState.PRISTINE_SETUP,
                "installation_absent",
                None,
                (),
                None,
                "finishup service initialize-passphrase",
            )
        if vault_ready:
            recovered = state is not None and state.lifecycle == "recovered"
            revoked = state is not None and state.lifecycle == "revoked"
            return InstallationRecoveryStatus(
                InstallationRecoveryState.RECOVERED
                if recovered
                else InstallationRecoveryState.TEMPORARILY_LOCKED,
                "recovery_completed"
                if recovered
                else "recovery_material_revoked"
                if revoked
                else "vault_ready",
                None if state is None else state.active_generation,
                () if state is None or revoked else state.available_modes,
                None,
                None,
            )
        if state is not None and state.lifecycle == "recovering":
            return InstallationRecoveryStatus(
                InstallationRecoveryState.RECOVERY_IN_PROGRESS,
                "recovery_owned",
                state.active_generation,
                state.available_modes,
                state.continuation_id,
                "finishup service recovery status",
            )
        if auto_unlock_repairable:
            return InstallationRecoveryStatus(
                InstallationRecoveryState.AUTO_UNLOCK_REPAIRABLE,
                "auto_unlock_repairable",
                None if state is None else state.active_generation,
                () if state is None else state.available_modes,
                None,
                "finishup service auto-unlock repair",
            )
        if ordinary_unlock_available:
            return InstallationRecoveryStatus(
                InstallationRecoveryState.TEMPORARILY_LOCKED,
                "ordinary_unlock_available",
                None if state is None else state.active_generation,
                () if state is None else state.available_modes,
                None,
                "finishup service unlock",
            )
        if state is not None and state.lifecycle == "revoked":
            return InstallationRecoveryStatus(
                InstallationRecoveryState.TEMPORARILY_LOCKED,
                "recovery_material_revoked",
                state.active_generation,
                (),
                None,
                "finishup service unlock",
            )
        if state is not None:
            return InstallationRecoveryStatus(
                InstallationRecoveryState.RECOVERY_MATERIAL_REQUIRED,
                "provisioned_recovery_available",
                state.active_generation,
                state.available_modes,
                None,
                "finishup service recovery restore",
            )
        if proven_unrecoverable:
            return InstallationRecoveryStatus(
                InstallationRecoveryState.PERMANENTLY_UNRECOVERABLE,
                "all_unlock_authority_proven_absent",
                None,
                (),
                None,
                None,
            )
        return InstallationRecoveryStatus(
            InstallationRecoveryState.TEMPORARILY_LOCKED,
            "recovery_state_unknown",
            None,
            (),
            None,
            "finishup service recovery status",
        )

    def pending_import(self) -> InstallationRecoveryMetadata | None:
        """Return the staged-but-unauthenticated imported generation, when one exists."""

        pending = self._pending_import_optional()
        return None if pending is None else pending.metadata

    def _pending_import_optional(self) -> _PendingImport | None:
        try:
            return _PendingImport.decode(_read_private(self._pending_path, _MAX_STATE_BYTES))
        except FileNotFoundError:
            return None

    def _write_pending(self, pending: _PendingImport) -> None:
        _write_atomic(self._pending_path, pending.encode())

    def _clear_pending(self) -> None:
        try:
            self._pending_path.unlink()
            _fsync_dir(self._root)
        except FileNotFoundError:
            pass

    def _mark_recovered(self, state: _StateRecord) -> None:
        _write_atomic(
            self._state_path,
            _StateRecord.create(
                state.active_generation,
                state.available_modes,
                "recovered",
                None,
            ).encode(),
        )
        try:
            self._clean_restore_path.unlink()
            _fsync_dir(self._root)
        except FileNotFoundError:
            pass

    def _load_state(self) -> _StateRecord:
        state = self._load_state_optional()
        if state is None:
            raise FileNotFoundError("installation_recovery_not_provisioned")
        return state

    def _load_state_optional(self) -> _StateRecord | None:
        try:
            return _StateRecord.decode(_read_private(self._state_path, _MAX_STATE_BYTES))
        except FileNotFoundError:
            return None


def _metadata_from_artifact(artifact: InstallationRecoveryArtifact) -> InstallationRecoveryMetadata:
    # Authentication is deliberately not attempted here: the service already created the artifact
    # from a live vault root.  Exact public binding is recovered from the canonical header.
    value = strict_json_parse(artifact.canonical_bytes)
    if type(value) is not dict:
        raise ValueError("installation_recovery_artifact_invalid")
    source = cast(dict[str, JsonValue], value)
    binding = source.get("binding")
    if type(binding) is not dict:
        raise ValueError("installation_recovery_artifact_invalid")
    public = cast(dict[str, JsonValue], binding)
    generation = public.get("recovery_generation")
    mode = public.get("mode")
    kind = public.get("secret_kind")
    snapshot = public.get("snapshot_manifest_digest")
    if (
        type(generation) is not int
        or type(mode) is not str
        or type(kind) is not str
        or (snapshot is not None and type(snapshot) is not str)
    ):
        raise ValueError("installation_recovery_artifact_invalid")
    return InstallationRecoveryMetadata(
        generation,
        InstallationRecoveryMode(mode),
        InstallationRecoverySecretKind(kind),
        artifact.artifact_digest,
        snapshot,
    )


def _read_private(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        facts = os.fstat(descriptor)
        _verify_private_facts(facts)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("installation_recovery_file_too_large")
        return data
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
        _verify_private_facts(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _write_atomic(path: Path, data: bytes) -> None:
    ensure_owner_only_dir(path.parent)
    temp = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        _write_exclusive(temp, data)
        os.replace(temp, path)
        _fsync_dir(path.parent)
        if _read_private(path, max(len(data), 1)) != data:
            raise OSError("installation_recovery_atomic_verify_failed")
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _copy_private_file(source: Path, destination: Path) -> None:
    source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    destination_descriptor = -1
    try:
        _verify_private_facts(os.fstat(source_descriptor))
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        while True:
            chunk = os.read(source_descriptor, 1_048_576)
            if not chunk:
                break
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_descriptor, remaining)
                if written <= 0:
                    raise OSError("installation_snapshot_write_incomplete")
                remaining = remaining[written:]
        os.fsync(destination_descriptor)
        _verify_private_facts(os.fstat(destination_descriptor))
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)


def _copy_private_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError("installation_recovery_target_exists")
    ensure_owner_only_dir(destination)
    for member in source.rglob("*"):
        relative = member.relative_to(source)
        target = destination / relative
        facts = member.lstat()
        if stat.S_ISLNK(facts.st_mode):
            raise PermissionError("installation_recovery_symlink_forbidden")
        if stat.S_ISDIR(facts.st_mode):
            ensure_owner_only_dir(target)
        elif stat.S_ISREG(facts.st_mode):
            ensure_owner_only_dir(target.parent)
            _copy_private_file(member, target)
        else:
            raise PermissionError("installation_recovery_member_unsafe")


def _write_swap_journal(
    path: Path,
    *,
    bundle_name: str,
    stage_name: str,
    backup_name: str,
    phase: Literal["prepared", "old_moved", "installed"],
) -> None:
    body: dict[str, JsonValue] = {
        "backup_name": backup_name,
        "bundle_name": bundle_name,
        "format": "yoetz-installation-recovery-swap/1",
        "phase": phase,
        "stage_name": stage_name,
    }
    body["record_digest"] = (
        "sha256:" + hashlib.sha256(_SWAP_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()
    )
    data = canonical_encode(body) + b"\n"
    temp = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        _write_exclusive(temp, data)
        os.replace(temp, path)
        _fsync_dir(path.parent)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _read_swap_journal(path: Path) -> tuple[str, str, str, str]:
    encoded = _read_private(path, _MAX_STATE_BYTES)
    if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
        raise ValueError("installation_recovery_swap_invalid")
    value = strict_json_parse(encoded[:-1])
    if type(value) is not dict:
        raise ValueError("installation_recovery_swap_invalid")
    source = cast(dict[str, JsonValue], value)
    if canonical_encode(source) != encoded[:-1] or set(source) != {
        "backup_name",
        "bundle_name",
        "format",
        "phase",
        "record_digest",
        "stage_name",
    }:
        raise ValueError("installation_recovery_swap_invalid")
    record = source["record_digest"]
    body = dict(source)
    del body["record_digest"]
    expected = "sha256:" + hashlib.sha256(_SWAP_DIGEST_DOMAIN + canonical_encode(body)).hexdigest()
    values = (
        source["bundle_name"],
        source["stage_name"],
        source["backup_name"],
        source["phase"],
    )
    if (
        source["format"] != "yoetz-installation-recovery-swap/1"
        or type(record) is not str
        or record != expected
        or any(type(item) is not str for item in values)
    ):
        raise ValueError("installation_recovery_swap_invalid")
    return cast(tuple[str, str, str, str], values)


def _reconcile_snapshot_install(bundle: Path) -> None:
    journal = bundle.parent / f".{bundle.name}.recovery-journal.json"
    if not journal.exists():
        return
    bundle_name, stage_name, backup_name, phase = _read_swap_journal(journal)
    if (
        bundle_name != bundle.name
        or "/" in stage_name
        or "/" in backup_name
        or not stage_name.startswith(f".{bundle.name}.recovery-target.")
        or not backup_name.startswith(f".{bundle.name}.pristine-before-recovery.")
        or phase not in {"prepared", "old_moved", "installed"}
    ):
        raise ValueError("installation_recovery_swap_invalid")
    stage = bundle.parent / stage_name
    backup = bundle.parent / backup_name
    if phase == "prepared":
        if bundle.exists() and stage.exists() and not backup.exists():
            os.rename(bundle, backup)
            _fsync_dir(bundle.parent)
        if bundle.exists() or not stage.exists() or not backup.exists():
            raise RuntimeError("installation_recovery_swap_ambiguous")
        _write_swap_journal(
            journal,
            bundle_name=bundle.name,
            stage_name=stage_name,
            backup_name=backup_name,
            phase="old_moved",
        )
        phase = "old_moved"
    if phase == "old_moved":
        if not bundle.exists() and stage.exists() and backup.exists():
            os.rename(stage, bundle)
            _fsync_dir(bundle.parent)
        if not bundle.exists() or stage.exists() or not backup.exists():
            raise RuntimeError("installation_recovery_swap_ambiguous")
        _write_swap_journal(
            journal,
            bundle_name=bundle.name,
            stage_name=stage_name,
            backup_name=backup_name,
            phase="installed",
        )
    if not bundle.exists() or stage.exists() or not backup.exists():
        raise RuntimeError("installation_recovery_swap_ambiguous")
    journal.unlink()
    _fsync_dir(bundle.parent)


def _zip_add_private(archive: zipfile.ZipFile, source: Path, logical_name: str) -> None:
    _validate_logical_name(logical_name)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _verify_private_facts(os.fstat(descriptor))
        info = zipfile.ZipInfo(logical_name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_STORED
        info.create_system = 3
        info.external_attr = 0o100600 << 16
        with archive.open(info, "w", force_zip64=True) as target:
            while True:
                chunk = os.read(descriptor, 1_048_576)
                if not chunk:
                    break
                target.write(chunk)
    finally:
        os.close(descriptor)


def _validate_archive_member(info: zipfile.ZipInfo) -> None:
    _validate_logical_name(info.filename)
    if (
        info.is_dir()
        or info.compress_type != zipfile.ZIP_STORED
        or info.file_size < 0
        or info.file_size > _MAX_ARCHIVE_MEMBER_BYTES
        or info.compress_size != info.file_size
    ):
        raise ValueError("installation_recovery_import_invalid")


def _validate_logical_name(value: str) -> None:
    path = Path(value)
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or value.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
        or value not in {"artifact.yir", "snapshot/manifest.json"}
        and not value.startswith("snapshot/members/")
    ):
        raise ValueError("installation_recovery_import_invalid")


def _extract_archive_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, destination: Path
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    observed = 0
    try:
        with archive.open(info, "r") as source:
            while True:
                chunk = source.read(1_048_576)
                if not chunk:
                    break
                observed += len(chunk)
                if observed > info.file_size:
                    raise ValueError("installation_recovery_import_invalid")
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("installation_recovery_import_write_incomplete")
                    remaining = remaining[written:]
        if observed != info.file_size:
            raise ValueError("installation_recovery_import_invalid")
        os.fsync(descriptor)
        _verify_private_facts(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _snapshot_facts(snapshot: Path) -> tuple[int, int, str]:
    manifest = _read_private(snapshot / "manifest.json", 4_194_304)
    value = strict_json_parse(manifest)
    if type(value) is not dict:
        raise ValueError("installation_snapshot_manifest_invalid")
    source = cast(dict[str, JsonValue], value)
    if canonical_encode(source) != manifest:
        raise ValueError("installation_snapshot_manifest_invalid")
    members = source.get("members")
    recovery_generation = source.get("recovery_generation")
    total_bytes = source.get("total_bytes")
    if (
        source.get("format") != _SNAPSHOT_FORMAT
        or type(members) is not list
        or type(recovery_generation) is not int
        or type(total_bytes) is not int
    ):
        raise ValueError("installation_snapshot_manifest_invalid")
    expected_names: set[str] = set()
    observed_total = 0
    for value_member in members:
        if type(value_member) is not dict:
            raise ValueError("installation_snapshot_manifest_invalid")
        member = cast(dict[str, JsonValue], value_member)
        name = member.get("logical_name")
        size = member.get("size_bytes")
        if type(name) is not str or type(size) is not int:
            raise ValueError("installation_snapshot_manifest_invalid")
        _validate_logical_name(f"snapshot/members/{name}")
        if name in expected_names:
            raise ValueError("installation_snapshot_manifest_invalid")
        expected_names.add(name)
        observed_total += size
    observed_names = {
        path.relative_to(snapshot / "members").as_posix()
        for path in (snapshot / "members").rglob("*")
        if path.is_file()
    }
    if observed_names != expected_names or observed_total != total_bytes:
        raise ValueError("installation_snapshot_manifest_invalid")
    return len(members), total_bytes, "sha256:" + hashlib.sha256(manifest).hexdigest()


def _backup_sqlite(source: Path, destination: Path) -> None:
    source_uri = "file:" + urllib.parse.quote(source.as_posix(), safe="/:") + "?mode=ro"
    source_connection = sqlite3.connect(source_uri, uri=True, timeout=30.0)
    destination_connection = sqlite3.connect(destination, timeout=30.0)
    try:
        source_connection.backup(destination_connection)
        row = destination_connection.execute("PRAGMA integrity_check").fetchone()
        if row != ("ok",):
            raise ValueError("installation_snapshot_sqlite_invalid")
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()
    destination.chmod(0o600)
    descriptor = os.open(destination, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _verify_private_facts(os.fstat(descriptor))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_digest(path: Path) -> tuple[str, int]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    size = 0
    try:
        _verify_private_facts(os.fstat(descriptor))
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest(), size


def _fsync_tree(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for directory in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        _fsync_dir(directory)
    _fsync_dir(root)


def _remove_stage(stage: Path) -> None:
    if not stage.exists():
        return
    for path in sorted(stage.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        try:
            if path.is_dir():
                path.rmdir()
            else:
                path.unlink()
        except OSError:
            pass
    try:
        stage.rmdir()
    except OSError:
        pass


def _verify_private_facts(facts: os.stat_result) -> None:
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else facts.st_uid
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_nlink != 1
        or facts.st_uid != expected_uid
        or stat.S_IMODE(facts.st_mode) != 0o600
    ):
        raise PermissionError("installation_recovery_file_unsafe")


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
