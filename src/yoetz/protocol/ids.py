"""Typed public identifier generation and strict validation."""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Final, cast

from yoetz.protocol.errors import ProtocolValueError

__all__ = [
    "ACTOR_ID_PATTERN",
    "OPAQUE_ITEM_ID_PATTERN",
    "ID_TOTAL_LENGTH",
    "PREFIX_BY_KIND",
    "IdKind",
    "is_valid_id",
    "new_id",
    "safe_request_id_from",
    "validate_actor_id",
    "validate_opaque_item_id",
    "validate_id",
]


class IdKind(str, Enum):  # noqa: UP042 - v0.1 requires a str-valued Enum
    REQUEST = "request"
    INSTALLATION = "installation"
    TASK = "task"
    SESSION = "session"
    WRITER = "writer"
    EVENT = "event"
    OBLIGATION = "obligation"
    CLAIM = "claim"
    ACTION = "action"
    RESULT = "result"
    EVIDENCE = "evidence"
    FINDING = "finding"
    OBJECT = "object"
    RECEIPT = "receipt"
    CORRELATION = "correlation"
    SEMANTIC_JOB = "semantic_job"
    SEMANTIC_ATTEMPT = "semantic_attempt"
    MAINTENANCE_PIN = "maintenance_pin"
    SERVICE_INSTANCE = "service_instance"
    CONTROL_RPC = "control_rpc"
    PRIVACY_POLICY = "privacy_policy"
    PRIVACY_SETUP_SESSION = "privacy_setup_session"
    PRIVACY_PROPOSAL = "privacy_proposal"
    OUTBOUND_CASE = "outbound_case"
    EGRESS_AUTHORIZATION = "egress_authorization"
    EGRESS_DISPATCH = "egress_dispatch"
    EGRESS_RECEIPT = "egress_receipt"
    ACTOR = "actor"
    PROJECT = "project"


ID_TOTAL_LENGTH: Final = 40
ACTOR_ID_PATTERN: Final = r"^[A-Za-z0-9._:-]{1,128}$"
OPAQUE_ITEM_ID_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"

PREFIX_BY_KIND: Final[Mapping[IdKind, str]] = MappingProxyType(
    {
        IdKind.REQUEST: "req_",
        IdKind.INSTALLATION: "ins_",
        IdKind.TASK: "tsk_",
        IdKind.SESSION: "ses_",
        IdKind.WRITER: "wri_",
        IdKind.EVENT: "evt_",
        IdKind.OBLIGATION: "obl_",
        IdKind.CLAIM: "clm_",
        IdKind.ACTION: "act_",
        IdKind.RESULT: "res_",
        IdKind.EVIDENCE: "evd_",
        IdKind.FINDING: "fnd_",
        IdKind.OBJECT: "obj_",
        IdKind.RECEIPT: "rcp_",
        IdKind.CORRELATION: "err_",
        IdKind.SEMANTIC_JOB: "job_",
        IdKind.SEMANTIC_ATTEMPT: "att_",
        IdKind.MAINTENANCE_PIN: "pin_",
        IdKind.SERVICE_INSTANCE: "svc_",
        IdKind.CONTROL_RPC: "rpc_",
        IdKind.PRIVACY_POLICY: "pvy_",
        IdKind.PRIVACY_SETUP_SESSION: "psw_",
        IdKind.PRIVACY_PROPOSAL: "ppr_",
        IdKind.OUTBOUND_CASE: "cas_",
        IdKind.EGRESS_AUTHORIZATION: "aut_",
        IdKind.EGRESS_DISPATCH: "dsp_",
        IdKind.EGRESS_RECEIPT: "egr_",
        IdKind.ACTOR: "agt_",
        IdKind.PROJECT: "prj_",
    }
)

_UUID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.ASCII,
)
_ACTOR_PATTERN: Final[re.Pattern[str]] = re.compile(ACTOR_ID_PATTERN, re.ASCII)
_OPAQUE_ITEM_PATTERN: Final[re.Pattern[str]] = re.compile(OPAQUE_ITEM_ID_PATTERN, re.ASCII)


def _validate_kind(kind: object) -> IdKind:
    if type(kind) is not IdKind:
        raise TypeError("id_kind_wrong_type")
    return kind


def _is_actual_str_instance(value: object) -> bool:
    try:
        return issubclass(type(value), str)
    except BaseException:
        return False


def _string_length(value: str) -> int:
    return str.__len__(value)


def _string_slice(value: str, start: int, stop: int | None = None) -> str:
    return str.__getitem__(value, slice(start, stop))


def new_id(kind: IdKind) -> str:
    """Generate a canonical UUIDv4-shaped ID from the OS CSPRNG."""

    validated_kind = _validate_kind(kind)
    if validated_kind is IdKind.ACTOR:
        raise ProtocolValueError("actor_id_not_generated")
    random_bytes = bytearray(os.urandom(16))
    random_bytes[6] = (random_bytes[6] & 0x0F) | 0x40
    random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[validated_kind] + str(uuid.UUID(bytes=bytes(random_bytes)))


def validate_id(kind: IdKind, value: object) -> str:
    """Validate one ID against an expected kind and return the same string object."""

    validated_kind = _validate_kind(kind)
    if validated_kind is IdKind.ACTOR:
        return validate_actor_id(value)
    if not _is_actual_str_instance(value):
        raise ProtocolValueError("id_wrong_type")
    candidate = cast(str, value)
    if _string_length(candidate) != ID_TOTAL_LENGTH:
        raise ProtocolValueError("id_wrong_length")
    try:
        encoded = str.encode(candidate, "ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("id_not_ascii") from exc
    if any(byte < 0x21 or byte > 0x7E for byte in encoded):
        raise ProtocolValueError("id_not_ascii")
    if _string_slice(candidate, 0, 4) != PREFIX_BY_KIND[validated_kind]:
        raise ProtocolValueError("id_wrong_prefix")
    uuid_text = _string_slice(candidate, 4)
    if _UUID_PATTERN.fullmatch(uuid_text) is None:
        raise ProtocolValueError("id_malformed_uuid")
    if uuid_text[14] != "4":
        raise ProtocolValueError("id_uuid_not_version_4")
    if uuid_text[19] not in {"8", "9", "a", "b"}:
        raise ProtocolValueError("id_uuid_wrong_variant")
    return candidate


def validate_opaque_item_id(value: object) -> str:
    """Validate an opaque case-item identity used in privacy omission projections."""

    if type(value) is not str or _OPAQUE_ITEM_PATTERN.fullmatch(value) is None:
        raise ProtocolValueError("opaque_item_id_invalid")
    return value


def is_valid_id(kind: IdKind, value: object) -> bool:
    """Return whether a value validates for a kind; programmer defects propagate."""

    try:
        validate_id(kind, value)
    except ProtocolValueError:
        return False
    return True


def validate_actor_id(value: object) -> str:
    """Validate a caller-asserted actor identifier without minting assurance."""

    if not _is_actual_str_instance(value):
        raise ProtocolValueError("id_wrong_type")
    candidate = cast(str, value)
    if _string_length(candidate) > 128:
        raise ProtocolValueError("id_wrong_length")
    bounded = _string_slice(candidate, 0)
    if _ACTOR_PATTERN.fullmatch(bounded) is None:
        raise ProtocolValueError("actor_id_malformed")
    return candidate


def safe_request_id_from(arguments: object) -> str | None:
    """Extract a validated request ID from an arbitrary hostile mapping boundary."""

    try:
        if not issubclass(type(arguments), Mapping):
            return None
        source = cast(Mapping[object, object], arguments)
        candidate: object = source.get("request_id")
    except BaseException:
        return None
    if type(candidate) is not str:
        return None
    if str.__len__(candidate) != ID_TOTAL_LENGTH:
        return None
    if is_valid_id(IdKind.REQUEST, candidate):
        return candidate
    return None
