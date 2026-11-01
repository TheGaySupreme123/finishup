"""Immutable encrypted-object storage boundary values and protocol."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast

from finishup.domain.values import (
    format_rfc3339_millis,
    object_id,
    task_id,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES

__all__ = [
    "MAX_OBJECT_HEADER_BYTES",
    "OBJECT_COMMITMENT_DOMAINS",
    "ObjectKind",
    "ObjectMetadata",
    "ObjectRef",
    "ObjectRootSnapshot",
    "ObjectSource",
    "ObjectStorePort",
    "StagedObject",
]


class ObjectKind(str, Enum):  # noqa: UP042 - exact durable enum base
    EVENT_PAYLOAD = "event_payload"
    CAPTURED_CONTENT = "captured_content"
    SEMANTIC_CASE = "semantic_case"
    SEMANTIC_RESPONSE = "semantic_response"
    OPERATION_RESULT = "operation_result"
    START_RESULT = "start_result"
    CHECK_RESUME = "check_resume"
    DETERMINISTIC_RESULT = "deterministic_result"
    RECEIPT = "receipt"
    IMPORT_SOURCE = "import_source"
    IMPORT_SOURCE_MANIFEST = "import_source_manifest"
    IMPORT_PLAN = "import_plan"
    IMPORT_REPORT = "import_report"
    IMPORT_STDERR = "import_stderr"
    IMPORT_QUARANTINE = "import_quarantine"
    CAPABILITY_EVIDENCE = "capability_evidence"
    PRIVACY_AUDIT = "privacy_audit"
    PROJECT_TEXT = "project_text"
    # Service-captured repository change material (ADR-031): the task-start base record and the
    # one check-time change object a check's AI-powered review reads.
    CHANGE_CAPTURE = "change_capture"


MAX_OBJECT_HEADER_BYTES: Final = 16 * 1024
OBJECT_COMMITMENT_DOMAINS: Final[Mapping[ObjectKind, bytes]] = MappingProxyType(
    {
        ObjectKind.EVENT_PAYLOAD: b"yoetz/object/event_payload/v1\x00",
        ObjectKind.CAPTURED_CONTENT: b"yoetz/object/captured_content/v1\x00",
        ObjectKind.SEMANTIC_CASE: b"yoetz/object/semantic_case/v1\x00",
        ObjectKind.SEMANTIC_RESPONSE: b"yoetz/object/semantic_response/v1\x00",
        ObjectKind.OPERATION_RESULT: b"yoetz/object/operation_result/v1\x00",
        ObjectKind.START_RESULT: b"yoetz/object/start_result/v1\x00",
        ObjectKind.CHECK_RESUME: b"yoetz/object/check_resume/v1\x00",
        ObjectKind.DETERMINISTIC_RESULT: b"yoetz/object/deterministic_result/v1\x00",
        ObjectKind.RECEIPT: b"yoetz/object/receipt/v1\x00",
        ObjectKind.IMPORT_SOURCE: b"yoetz/object/import_source/v1\x00",
        ObjectKind.IMPORT_SOURCE_MANIFEST: b"yoetz/object/import_source_manifest/v1\x00",
        ObjectKind.IMPORT_PLAN: b"yoetz/object/import_plan/v1\x00",
        ObjectKind.IMPORT_REPORT: b"yoetz/object/import_report/v1\x00",
        ObjectKind.IMPORT_STDERR: b"yoetz/object/import_stderr/v1\x00",
        ObjectKind.IMPORT_QUARANTINE: b"yoetz/object/import_quarantine/v1\x00",
        ObjectKind.CAPABILITY_EVIDENCE: b"yoetz/object/capability_evidence/v1\x00",
        ObjectKind.PRIVACY_AUDIT: b"yoetz/object/privacy_audit/v1\x00",
        ObjectKind.PROJECT_TEXT: b"yoetz/object/project_text/v1\x00",
        ObjectKind.CHANGE_CAPTURE: b"yoetz/object/change_capture/v1\x00",
    }
)

_MEDIA_TYPE_PATTERN: Final = re.compile(
    r"^[a-z][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$",
    re.ASCII,
)
_KEY_SLOT_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_MAX_SQLITE_SIGNED_INTEGER: Final = 2**63 - 1


def _invalid() -> ValueError:
    return ValueError("invalid_object_port_value")


def _nonnegative_int(value: object, *, maximum: int = _MAX_SQLITE_SIGNED_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _invalid()
    return value


def _positive_int(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise _invalid()
    return value


def _sorted_unique_ascii(values: object) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise _invalid()
    raw = cast(tuple[object, ...], values)
    if any(type(value) is not str for value in raw):
        raise _invalid()
    candidate = cast(tuple[str, ...], raw)
    try:
        expected = tuple(sorted(set(candidate), key=str.encode))
    except UnicodeEncodeError as exc:
        raise _invalid() from exc
    if candidate != expected:
        raise _invalid()
    return candidate


@dataclass(frozen=True, slots=True)
class ObjectSource:
    data: bytes | None = None
    stream: AsyncIterator[bytes] | None = None
    declared_size: int | None = None

    def __post_init__(self) -> None:
        if (self.data is None) == (self.stream is None):
            raise _invalid()
        if self.data is not None:
            if type(self.data) is not bytes:
                raise _invalid()
            if len(self.data) > MAX_OBJECT_PLAINTEXT_BYTES:
                raise _invalid()
            if self.declared_size is not None:
                _nonnegative_int(self.declared_size, maximum=MAX_OBJECT_PLAINTEXT_BYTES)
                if self.declared_size != len(self.data):
                    raise _invalid()
            return
        if not hasattr(self.stream, "__aiter__") or self.declared_size is None:
            raise _invalid()
        _nonnegative_int(self.declared_size, maximum=MAX_OBJECT_PLAINTEXT_BYTES)


@dataclass(frozen=True, slots=True)
class ObjectMetadata:
    kind: ObjectKind
    media_type: str
    task_id: str
    created_at: datetime

    def __post_init__(self) -> None:
        if type(self.kind) is not ObjectKind:
            raise _invalid()
        if (
            type(self.media_type) is not str
            or len(self.media_type) > 128
            or _MEDIA_TYPE_PATTERN.fullmatch(self.media_type) is None
        ):
            raise _invalid()
        try:
            task_id(self.task_id)
            format_rfc3339_millis(self.created_at)
        except ValueError as exc:
            raise _invalid() from exc


@dataclass(frozen=True, slots=True)
class StagedObject:
    object_id: str
    plaintext_size: int
    commitment: str
    envelope_digest: str
    encryption_format: Literal["yoetz-object/1"]
    key_slot: str
    metadata: ObjectMetadata
    staging_handle: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _validate_object_descriptor(self)
        if self.metadata.kind is ObjectKind.IMPORT_STDERR:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ObjectRef:
    object_id: str
    plaintext_size: int
    commitment: str
    envelope_digest: str
    encryption_format: Literal["yoetz-object/1"]
    key_slot: str
    metadata: ObjectMetadata

    def __post_init__(self) -> None:
        _validate_object_descriptor(self)
        if self.metadata.kind is ObjectKind.IMPORT_STDERR:
            raise _invalid()


def _validate_object_descriptor(value: StagedObject | ObjectRef) -> None:
    try:
        object_id(value.object_id)
        _nonnegative_int(value.plaintext_size, maximum=MAX_OBJECT_PLAINTEXT_BYTES)
        validate_commitment(value.commitment)
        validate_sha256_digest(value.envelope_digest)
    except ValueError as exc:
        raise _invalid() from exc
    if value.encryption_format != "yoetz-object/1":
        raise _invalid()
    if (
        type(value.key_slot) is not str
        or _KEY_SLOT_PATTERN.fullmatch(value.key_slot) is None
        or type(value.metadata) is not ObjectMetadata
    ):
        raise _invalid()


@dataclass(frozen=True, slots=True)
class ObjectRootSnapshot:
    task_id: str
    route_identity_digest: str
    route_generation: int
    bundle_generation: int
    privacy_root_generation: int
    ledger_roots_digest: str
    importer_roots_digest: str
    privacy_roots_digest: str
    maintenance_pin_digest: str
    captured_at: datetime
    live_object_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            task_id(self.task_id)
            validate_sha256_digest(self.route_identity_digest)
            _positive_int(self.route_generation)
            _positive_int(self.bundle_generation)
            _nonnegative_int(self.privacy_root_generation)
            validate_sha256_digest(self.ledger_roots_digest)
            validate_sha256_digest(self.importer_roots_digest)
            validate_sha256_digest(self.privacy_roots_digest)
            validate_sha256_digest(self.maintenance_pin_digest)
            format_rfc3339_millis(self.captured_at)
        except ValueError as exc:
            raise _invalid() from exc
        values = _sorted_unique_ascii(self.live_object_ids)
        try:
            for value in values:
                object_id(value)
        except ValueError as exc:
            raise _invalid() from exc


class ObjectStorePort(Protocol):
    async def commitment_for(self, data: bytes, kind: ObjectKind) -> str: ...

    async def stage(
        self,
        source: ObjectSource,
        metadata: ObjectMetadata,
        *,
        object_id: str | None = None,
    ) -> StagedObject: ...

    async def finalize(self, staged: StagedObject) -> ObjectRef: ...

    async def abandon(self, staged: StagedObject) -> None: ...

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef: ...

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]: ...

    async def sweep_orphans(self, root_snapshot: ObjectRootSnapshot, now: datetime) -> int: ...
