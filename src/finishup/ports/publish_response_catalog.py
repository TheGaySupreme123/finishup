"""Durable projected publish-response identity boundary."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

from finishup.domain.privacy import LocalDisclosureSink
from finishup.domain.values import validate_sha256_digest
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "PublishResponseCatalogPort",
    "PublishResponseKey",
    "StoredPublishResponse",
]


def _invalid() -> ValueError:
    return ValueError("invalid_publish_response_catalog_value")


@dataclass(frozen=True, slots=True)
class PublishResponseKey:
    task_id: str
    session_id: str
    writer_id: str
    request_id: str
    request_digest: str
    sink: LocalDisclosureSink

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.TASK, self.task_id)
            validate_id(IdKind.SESSION, self.session_id)
            validate_id(IdKind.WRITER, self.writer_id)
            validate_id(IdKind.REQUEST, self.request_id)
            validate_sha256_digest(self.request_digest)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        if self.sink not in {
            LocalDisclosureSink.AGENT_CONTEXT,
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        }:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class StoredPublishResponse:
    key: PublishResponseKey
    result_canonical: bytes = field(repr=False)
    result_digest: str

    def __post_init__(self) -> None:
        if type(self.key) is not PublishResponseKey or type(self.result_canonical) is not bytes:
            raise _invalid()
        try:
            canonical = canonical_encode(strict_json_parse(self.result_canonical))
            validate_sha256_digest(self.result_digest)
        except (TypeError, ValueError) as exc:
            raise _invalid() from exc
        expected = f"sha256:{hashlib.sha256(self.result_canonical).hexdigest()}"
        if canonical != self.result_canonical or self.result_digest != expected:
            raise _invalid()


class PublishResponseCatalogPort(Protocol):
    async def lookup(self, key: PublishResponseKey) -> StoredPublishResponse | None: ...

    async def put_if_absent(self, value: StoredPublishResponse) -> StoredPublishResponse: ...
