"""Lossless, authenticated paging for internal frozen check checkpoints (#1159).

The encrypted object port retains its 4 MiB limit. Only CHECK_RESUME checkpoints may
use this manifest; captured artifacts and external review payloads gain no authority.
"""

from __future__ import annotations

import hashlib
from typing import Final, cast

from finishup.ports.objects import (
    ObjectKind,
    ObjectMetadata,
    ObjectRef,
    ObjectSource,
    ObjectStorePort,
)
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES

MAX_CHECK_RESUME_PAGES: Final = 64
MAX_CHECK_RESUME_BYTES: Final = MAX_CHECK_RESUME_PAGES * MAX_OBJECT_PLAINTEXT_BYTES
CHECK_RESUME_PAGE_MEDIA_TYPE: Final = "application/vnd.yoetz.check-resume-page"
_SCHEMA: Final = "yoetz.check-resume-pages/1"


async def _stage(objects: ObjectStorePort, data: bytes, metadata: ObjectMetadata) -> ObjectRef:
    return await objects.finalize(
        await objects.stage(ObjectSource(data=data, declared_size=len(data)), metadata)
    )


async def stage_check_resume(
    objects: ObjectStorePort, data: bytes, metadata: ObjectMetadata
) -> tuple[ObjectRef, tuple[ObjectRef, ...]]:
    """Finalize children first; the ledger inventories them with the admitted root."""

    if metadata.kind is not ObjectKind.CHECK_RESUME:
        raise ValueError("check_resume_kind_invalid")
    if len(data) > MAX_CHECK_RESUME_BYTES:
        raise PublicOperationError(
            PublicErrorCode.LIMIT_EXCEEDED,
            "The local frozen check checkpoint exceeds its capacity. Retain this task and "
            "report the limitation; unchanged check retries cannot reduce it.",
            False,
            safe_details={
                "reason_code": "check_resume_capacity_exceeded",
                "count": len(data),
                "limit": MAX_CHECK_RESUME_BYTES,
            },
        )
    if len(data) <= MAX_OBJECT_PLAINTEXT_BYTES:
        return await _stage(objects, data, metadata), ()
    page_metadata = ObjectMetadata(
        ObjectKind.CHECK_RESUME, CHECK_RESUME_PAGE_MEDIA_TYPE, metadata.task_id, metadata.created_at
    )
    pages: list[ObjectRef] = []
    for offset in range(0, len(data), MAX_OBJECT_PLAINTEXT_BYTES):
        pages.append(
            await _stage(objects, data[offset : offset + MAX_OBJECT_PLAINTEXT_BYTES], page_metadata)
        )
    manifest = canonical_encode(
        {
            "schema": _SCHEMA,
            "size": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "pages": [
                {
                    "object_id": ref.object_id,
                    "envelope_digest": ref.envelope_digest,
                    "commitment": ref.commitment,
                    "size": ref.plaintext_size,
                }
                for ref in pages
            ],
        }
    )
    return await _stage(objects, manifest, metadata), tuple(pages)


async def open_check_resume(objects: ObjectStorePort, root: ObjectRef, raw: bytes) -> bytes:
    """Read old inline checkpoints or a bounded manifest; never follow nested manifests."""

    source = strict_json_parse(raw)
    if not isinstance(source, dict) or source.get("schema") != _SCHEMA:
        return raw
    invalid = "check_resume_pages_invalid"
    if canonical_encode(source) != raw or set(source) != {"schema", "size", "digest", "pages"}:
        raise ValueError(invalid)
    size = source["size"]
    pages = source["pages"]
    if (
        type(size) is not int
        or not MAX_OBJECT_PLAINTEXT_BYTES < size <= MAX_CHECK_RESUME_BYTES
        or not isinstance(pages, list)
        or not 2 <= len(pages) <= MAX_CHECK_RESUME_PAGES
        or len(pages) != (size + MAX_OBJECT_PLAINTEXT_BYTES - 1) // MAX_OBJECT_PLAINTEXT_BYTES
        or type(source["digest"]) is not str
        or root.metadata.kind is not ObjectKind.CHECK_RESUME
    ):
        raise ValueError(invalid)
    # Validate the entire manifest's shape and byte accounting before reading any page.
    seen: set[str] = {root.object_id}
    for index, pointer in enumerate(pages):
        if (
            not isinstance(pointer, dict)
            or set(pointer) != {"object_id", "envelope_digest", "commitment", "size"}
            or any(
                type(pointer[key]) is not str
                for key in ("object_id", "envelope_digest", "commitment")
            )
            or type(pointer["size"]) is not int
            or pointer["size"]
            != min(MAX_OBJECT_PLAINTEXT_BYTES, size - index * MAX_OBJECT_PLAINTEXT_BYTES)
            or pointer["object_id"] in seen
        ):
            raise ValueError(invalid)
        seen.add(cast(str, pointer["object_id"]))
    parts: list[bytes] = []
    for pointer in pages:
        assert isinstance(pointer, dict)
        ref = await objects.resolve_verified(
            cast(str, pointer["object_id"]), cast(str, pointer["envelope_digest"])
        )
        if (
            ref.metadata.kind is not ObjectKind.CHECK_RESUME
            or ref.metadata.task_id != root.metadata.task_id
            or ref.metadata.media_type != CHECK_RESUME_PAGE_MEDIA_TYPE
            or ref.metadata.created_at != root.metadata.created_at
            or ref.commitment != pointer["commitment"]
            or ref.plaintext_size != pointer["size"]
        ):
            raise ValueError(invalid)
        part = bytearray()
        async for chunk in objects.open_verified(ref):
            if len(part) + len(chunk) > ref.plaintext_size:
                raise ValueError(invalid)
            part.extend(chunk)
        if len(part) != ref.plaintext_size:
            raise ValueError(invalid)
        parts.append(bytes(part))
    data = b"".join(parts)
    if len(data) != size or "sha256:" + hashlib.sha256(data).hexdigest() != source["digest"]:
        raise ValueError(invalid)
    return data
