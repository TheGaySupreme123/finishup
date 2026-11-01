"""Strict ``yoetz-object/1`` envelope framing."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, cast

from finishup.domain.values import object_id, task_id
from finishup.ports.objects import MAX_OBJECT_HEADER_BYTES, ObjectKind, ObjectMetadata
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES

__all__ = [
    "ObjectEnvelope",
    "ObjectEnvelopeHeader",
    "decode_object_envelope",
    "encode_object_envelope",
    "validate_object_envelope",
]

_MAGIC: Final = b"YZO1"
_VERSION: Final = 1
_NONCE_BYTES: Final = 12
_TAG_BYTES: Final = 16
_HEADER_KEYS: Final = frozenset(
    {
        "created_at",
        "encryption_format",
        "key_slot",
        "media_type",
        "object_id",
        "object_kind",
        "payload_algorithm",
        "plaintext_size",
        "task_id",
        "wrap_algorithm",
        "wrapped_dek",
    }
)
_CREATED_AT_PATTERN: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$",
    re.ASCII,
)
_KEY_SLOT_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_BASE64URL_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)


def _invalid() -> ValueError:
    return ValueError("invalid_object_envelope")


def _created_at_from_wire(value: object) -> datetime:
    if type(value) is not str or _CREATED_AT_PATTERN.fullmatch(value) is None:
        raise _invalid()
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise _invalid() from exc
    if parsed.microsecond % 1000 != 0:
        raise _invalid()
    return parsed


def _decode_wrapped_dek(value: object) -> bytes:
    if type(value) is not str or len(value) != 54 or _BASE64URL_PATTERN.fullmatch(value) is None:
        raise _invalid()
    try:
        decoded = base64.urlsafe_b64decode(value + "==")
    except (ValueError, TypeError) as exc:
        raise _invalid() from exc
    if len(decoded) != 40 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise _invalid()
    return decoded


@dataclass(frozen=True, slots=True)
class ObjectEnvelopeHeader:
    created_at: str
    encryption_format: Literal["yoetz-object/1"]
    key_slot: str
    media_type: str
    object_id: str
    object_kind: ObjectKind
    payload_algorithm: Literal["aes-256-gcm"]
    plaintext_size: int
    task_id: str
    wrap_algorithm: Literal["aes-256-kw-rfc3394"]
    wrapped_dek: bytes

    def __post_init__(self) -> None:
        created_at = _created_at_from_wire(self.created_at)
        try:
            object_id(self.object_id)
            task_id(self.task_id)
            ObjectMetadata(
                kind=self.object_kind,
                media_type=self.media_type,
                task_id=self.task_id,
                created_at=created_at,
            )
        except ValueError as exc:
            raise _invalid() from exc
        if self.encryption_format != "yoetz-object/1":
            raise _invalid()
        if (
            type(self.key_slot) is not str
            or _KEY_SLOT_PATTERN.fullmatch(self.key_slot) is None
            or self.payload_algorithm != "aes-256-gcm"
            or type(self.plaintext_size) is not int
            or not 0 <= self.plaintext_size <= MAX_OBJECT_PLAINTEXT_BYTES
            or self.wrap_algorithm != "aes-256-kw-rfc3394"
            or type(self.wrapped_dek) is not bytes
            or len(self.wrapped_dek) != 40
        ):
            raise _invalid()

    @property
    def created_at_datetime(self) -> datetime:
        return _created_at_from_wire(self.created_at)

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "created_at": self.created_at,
            "encryption_format": self.encryption_format,
            "key_slot": self.key_slot,
            "media_type": self.media_type,
            "object_id": self.object_id,
            "object_kind": self.object_kind.value,
            "payload_algorithm": self.payload_algorithm,
            "plaintext_size": self.plaintext_size,
            "task_id": self.task_id,
            "wrap_algorithm": self.wrap_algorithm,
            "wrapped_dek": base64.urlsafe_b64encode(self.wrapped_dek).rstrip(b"=").decode("ascii"),
        }


@dataclass(frozen=True, slots=True)
class ObjectEnvelope:
    header: ObjectEnvelopeHeader
    header_bytes: bytes
    payload_nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        validate_object_envelope(self)


def _header_from_json(value: JsonValue) -> ObjectEnvelopeHeader:
    if not isinstance(value, Mapping):
        raise _invalid()
    source = cast(Mapping[str, JsonValue], value)
    if frozenset(source) != _HEADER_KEYS:
        raise _invalid()
    try:
        kind_value = source["object_kind"]
        if type(kind_value) is not str:
            raise _invalid()
        kind = ObjectKind(kind_value)
        return ObjectEnvelopeHeader(
            created_at=cast(str, source["created_at"]),
            encryption_format=cast(Literal["yoetz-object/1"], source["encryption_format"]),
            key_slot=cast(str, source["key_slot"]),
            media_type=cast(str, source["media_type"]),
            object_id=cast(str, source["object_id"]),
            object_kind=kind,
            payload_algorithm=cast(Literal["aes-256-gcm"], source["payload_algorithm"]),
            plaintext_size=cast(int, source["plaintext_size"]),
            task_id=cast(str, source["task_id"]),
            wrap_algorithm=cast(Literal["aes-256-kw-rfc3394"], source["wrap_algorithm"]),
            wrapped_dek=_decode_wrapped_dek(source["wrapped_dek"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc) == "invalid_object_envelope":
            raise
        raise _invalid() from exc


def validate_object_envelope(envelope: ObjectEnvelope | bytes) -> None:
    if isinstance(envelope, bytes):
        decode_object_envelope(envelope)
        return
    if type(envelope.header) is not ObjectEnvelopeHeader:
        raise _invalid()
    if type(envelope.header_bytes) is not bytes:
        raise _invalid()
    expected_header = canonical_encode(cast(JsonValue, envelope.header.to_json()))
    if (
        not 1 <= len(envelope.header_bytes) <= MAX_OBJECT_HEADER_BYTES
        or envelope.header_bytes != expected_header
        or type(envelope.payload_nonce) is not bytes
        or len(envelope.payload_nonce) != _NONCE_BYTES
        or type(envelope.ciphertext) is not bytes
        or len(envelope.ciphertext) != envelope.header.plaintext_size
        or type(envelope.tag) is not bytes
        or len(envelope.tag) != _TAG_BYTES
    ):
        raise _invalid()


def encode_object_envelope(
    header: ObjectEnvelopeHeader,
    payload_nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    header_bytes = canonical_encode(cast(JsonValue, header.to_json()))
    envelope = ObjectEnvelope(header, header_bytes, payload_nonce, ciphertext, tag)
    return b"".join(
        (
            _MAGIC,
            bytes((_VERSION,)),
            len(envelope.header_bytes).to_bytes(4, "big"),
            envelope.header_bytes,
            envelope.payload_nonce,
            envelope.ciphertext,
            envelope.tag,
        )
    )


def decode_object_envelope(data: bytes) -> ObjectEnvelope:
    if type(data) is not bytes or len(data) < 4 + 1 + 4 + 1 + _NONCE_BYTES + _TAG_BYTES:
        raise _invalid()
    if data[:4] != _MAGIC or data[4] != _VERSION:
        raise _invalid()
    header_length = int.from_bytes(data[5:9], "big")
    if not 1 <= header_length <= MAX_OBJECT_HEADER_BYTES:
        raise _invalid()
    header_end = 9 + header_length
    if header_end > len(data):
        raise _invalid()
    header_bytes = data[9:header_end]
    try:
        parsed = strict_json_parse(header_bytes)
        if canonical_encode(parsed) != header_bytes:
            raise _invalid()
        header = _header_from_json(parsed)
    except ValueError as exc:
        if str(exc) == "invalid_object_envelope":
            raise
        raise _invalid() from exc
    expected_length = header_end + _NONCE_BYTES + header.plaintext_size + _TAG_BYTES
    if len(data) != expected_length:
        raise _invalid()
    nonce_end = header_end + _NONCE_BYTES
    ciphertext_end = nonce_end + header.plaintext_size
    return ObjectEnvelope(
        header=header,
        header_bytes=header_bytes,
        payload_nonce=data[header_end:nonce_end],
        ciphertext=data[nonce_end:ciphertext_end],
        tag=data[ciphertext_end:],
    )
