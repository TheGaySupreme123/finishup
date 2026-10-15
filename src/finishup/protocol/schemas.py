"""Frozen packaged JSON Schema catalog with closed local reference resolution."""

from __future__ import annotations

import hashlib
import re
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import lru_cache
from importlib import resources
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import Any, Final, Never, Protocol, cast
from urllib.parse import urldefrag, urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema import validators as jsonschema_validators
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry
from referencing.exceptions import NoSuchResource
from referencing.jsonschema import DRAFT202012, Schema, SchemaRegistry

from finishup.protocol.canonical import (
    CanonicalFragment,
    JsonValue,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "EVENT_FAMILY_NAME_PATTERN",
    "MAX_UNKNOWN_PROPERTY_COUNT",
    "SCHEMA_MANIFEST_SCHEMA",
    "SCHEMA_MANIFEST_VERSION",
    "SCHEMA_MEMBER_COUNT",
    "SCHEMA_NAMESPACE",
    "SCHEMA_VERSION_PATTERN",
    "SchemaArtifactRole",
    "SchemaCatalog",
    "SchemaDocument",
    "SchemaInstanceInvalid",
    "SchemaKind",
    "event_schema_versions",
    "load_schema_catalog",
    "request_result_schema_versions",
    "schema_document_for",
    "schema_manifest_digest",
    "schema_path_for",
    "schema_uri",
    "validate_schema_document",
    "validate_schema_instance",
]

# Frozen legacy identifier (ADR-048): every released schema ``$id`` and the hosted manifest
# format tag; released schema bytes never change.
SCHEMA_NAMESPACE: Final = "https://schemas.yoetz.dev/0.1/"
SCHEMA_MANIFEST_SCHEMA: Final = "yoetz.schema-manifest/1.0.0"
SCHEMA_MANIFEST_VERSION: Final = "1.0.0"
SCHEMA_MEMBER_COUNT: Final = 230

_DRAFT_2020_12: Final = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_MEDIA_TYPE: Final = "application/schema+json"
_MANIFEST_FIELDS: Final = frozenset({"manifest_schema", "manifest_version", "members"})
_MEMBER_FIELDS: Final = frozenset(
    {
        "$id",
        "artifact_role",
        "byte_length",
        "media_type",
        "owning_model",
        "path",
        "schema_kind",
        "schema_version",
        "sha256",
    }
)
_SCHEMA_NAME_PATTERN: Final = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$", re.ASCII)
# Public because the MCP bridge admits the same shapes when it projects a validator failure to a
# caller-facing hint. One definition, imported there, so the two surfaces cannot drift apart.
SCHEMA_VERSION_PATTERN: Final = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$", re.ASCII
)
_SHA256_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_RFC3339_DATE_TIME_PATTERN: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$",
    re.ASCII,
)


class SchemaKind(str, Enum):  # noqa: UP042 - the wire contract fixes these bases
    REQUEST_RESULT = "request_result"
    EVENT = "event"
    CONFIG = "config"
    VERSION_MANIFEST = "version_manifest"


class SchemaArtifactRole(str, Enum):  # noqa: UP042 - the wire contract fixes these bases
    COMMON_VALUE = "common-value"
    MCP_INPUT = "MCP input"
    MCP_OUTPUT = "MCP output"
    PERSISTED_ENVELOPE = "persisted-envelope"
    EVENT_ENVELOPE = "event-envelope"
    EVENT_PAYLOAD = "event-payload"
    CONFIGURATION = "configuration"
    FINDING = "finding"
    PROVIDER_JUDGMENT = "provider-judgment"
    SEMANTIC_PROVENANCE = "semantic-provenance"
    RECEIPT_DOCUMENT = "receipt-document"
    PRIVACY_POLICY = "privacy-policy"
    OUTBOUND_CASE = "outbound-case"
    PRIVACY_AUDIT = "privacy-audit"
    SETUP_CONTRACT = "setup-contract"
    LOCAL_CONTROL = "local-control"
    SERVICE_STATUS = "service-status"
    VERSION_REPORT = "version-report"


@dataclass(frozen=True, slots=True)
class SchemaDocument:
    schema_kind: SchemaKind
    artifact_role: SchemaArtifactRole
    schema_name: str
    schema_version: str
    schema_id: str
    relative_path: str
    canonical_digest: str
    schema_bytes: bytes
    json_schema: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class SchemaCatalog:
    documents: tuple[SchemaDocument, ...]
    by_path: Mapping[str, SchemaDocument]
    by_id: Mapping[str, SchemaDocument]
    by_name_version: Mapping[tuple[str, str], SchemaDocument]
    request_result_versions: Mapping[str, str]
    event_schema_versions: Mapping[str, str]
    manifest_version: str
    manifest_digest: str


@dataclass(frozen=True, slots=True)
class _ManifestMember:
    path: str
    schema_id: str
    schema_version: str
    schema_kind: SchemaKind
    artifact_role: SchemaArtifactRole
    byte_length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _CatalogState:
    catalog: SchemaCatalog
    plain_by_id: Mapping[str, dict[str, JsonValue]]
    registry: SchemaRegistry


class _ValidatorProtocol(Protocol):
    def validate(self, instance: object) -> None: ...


_FORMAT_CHECKER: Final = FormatChecker(formats=())


def _is_rfc3339_date_time(value: object) -> bool:
    if type(value) is not str:
        return True
    if _RFC3339_DATE_TIME_PATTERN.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return True


_FORMAT_CHECKER.checks("date-time")(_is_rfc3339_date_time)


type _KeywordErrors = Iterator[ValidationError]


def _any_of_first_error(
    validator: Any, any_of: Sequence[object], instance: object, schema: object
) -> _KeywordErrors:
    """``anyOf`` that stops each failing branch at its first error.

    The stock keyword runs every failing branch to exhaustion so it can report the best error.
    Validity only depends on whether a branch has *an* error, and a status page's ``page`` is an
    ``anyOf`` over thirteen page shapes, each failing one of which otherwise walked every row
    (issue #916). This accepts and rejects exactly what the stock keyword does.
    """

    del schema
    for index, subschema in enumerate(any_of):
        if next(validator.descend(instance, subschema, schema_path=index), None) is None:
            return
    yield ValidationError("instance is not valid under any of the given schemas")


def _one_of_first_error(
    validator: Any, one_of: Sequence[object], instance: object, schema: object
) -> _KeywordErrors:
    """``oneOf`` with the stock keyword's decision, stopping each failing branch at one error."""

    del schema
    branches = enumerate(one_of)
    for index, subschema in branches:
        if next(validator.descend(instance, subschema, schema_path=index), None) is None:
            break
    else:
        yield ValidationError("instance is not valid under any of the given schemas")
        return
    if any(validator.evolve(schema=each).is_valid(instance) for _, each in branches):
        yield ValidationError("instance is valid under more than one of the given schemas")


def _ref_resolved_once(
    resolved_references: dict[tuple[str, str], Any],
    document_roots: Mapping[int, str],
    verdicts: _ValidInstanceVerdicts | None,
) -> Any:
    """``$ref`` exactly as the stock keyword applies it, resolving each reference once.

    The catalog is immutable for the life of its checker and uses no dynamic references
    (``_ValidityChecker.build`` refuses any), so a reference resolves to the same target from the
    same base URI every time. Re-walking its JSON pointer through ``referencing`` on every row was
    about a third of the remaining validation cost.

    A reference to a whole catalog document asks exactly what validating the sub-instance against
    that document asks, so it shares the checker's verdict memory when *verdicts* is given: the
    control envelope's ``body`` is the status result the service or client already validated.
    """

    def keyword(validator: Any, ref: str, instance: object, schema: object) -> _KeywordErrors:
        del schema
        resolver = validator._resolver
        key = (cast(str, resolver._base_uri), ref)
        resolved = resolved_references.get(key)
        if resolved is None:
            resolved = resolver.lookup(ref)
            resolved_references[key] = resolved
        document_id = document_roots.get(id(resolved.contents))
        if verdicts is None or document_id is None:
            yield from validator.descend(instance, resolved.contents, resolver=resolved.resolver)
            return
        verdict = (
            document_id,
            hashlib.sha256(canonical_encode(cast(JsonValue, instance))).digest(),
        )
        if verdicts.seen(verdict):
            return
        errors = validator.descend(instance, resolved.contents, resolver=resolved.resolver)
        first = next(errors, None)
        if first is None:
            verdicts.remember(verdict)
            return
        yield first
        yield from errors

    return keyword


def _deny_retrieve(uri: str) -> Never:
    raise NoSuchResource(uri)


def _protocol_error(reason: str) -> Never:
    raise ProtocolValueError(reason)


def _actual_mapping(value: object) -> bool:
    try:
        return issubclass(type(value), Mapping)
    except BaseException:
        return False


def _as_plain_object(value: JsonValue, reason: str) -> dict[str, JsonValue]:
    if type(value) is not dict:
        _protocol_error(reason)
    return cast(dict[str, JsonValue], value)


def _read_resource(resource: Traversable, reason: str) -> bytes:
    try:
        if not resource.is_file():
            _protocol_error(reason)
        return resource.read_bytes()
    except ProtocolValueError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise ProtocolValueError(reason) from exc


def _schema_root() -> Traversable:
    return resources.files("finishup").joinpath("resources", "schemas")


def _resource_at(root: Traversable, relative_path: str) -> Traversable:
    resource = root
    for part in relative_path.split("/"):
        resource = resource.joinpath(part)
    return resource


def _validate_relative_schema_path(value: object) -> str:
    if type(value) is not str:
        _protocol_error("schema_path_unsafe")
    path = value
    try:
        encoded = path.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("schema_path_unsafe") from exc
    if (
        not encoded
        or path.startswith("/")
        or "\\" in path
        or "%" in path
        or "//" in path
        or not path.endswith(".schema.json")
    ):
        _protocol_error("schema_path_unsafe")
    parts = path.split("/")
    if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts):
        _protocol_error("schema_path_unsafe")
    return path


def _collect_files(root: Traversable) -> frozenset[str]:
    collected: set[str] = set()

    def _walk(node: Traversable, prefix: str) -> None:
        try:
            children = tuple(node.iterdir())
        except (OSError, ValueError, TypeError) as exc:
            raise ProtocolValueError("schema_manifest_member_mismatch") from exc
        for child in children:
            name = child.name
            relative = f"{prefix}{name}"
            try:
                if child.is_file():
                    collected.add(relative)
                elif child.is_dir():
                    _walk(child, f"{relative}/")
            except (OSError, ValueError, TypeError) as exc:
                raise ProtocolValueError("schema_manifest_member_mismatch") from exc

    _walk(root, "")
    return frozenset(collected)


def _parse_manifest(data: bytes) -> tuple[_ManifestMember, ...]:
    try:
        parsed = strict_json_parse(data)
        if canonical_encode(parsed) != data:
            _protocol_error("schema_manifest_invalid")
        manifest = _as_plain_object(parsed, "schema_manifest_invalid")
    except ProtocolValueError as exc:
        if exc.reason_code == "schema_manifest_invalid":
            raise
        raise ProtocolValueError("schema_manifest_invalid") from None

    if frozenset(manifest) != _MANIFEST_FIELDS:
        _protocol_error("schema_manifest_invalid")
    if (
        manifest["manifest_schema"] != SCHEMA_MANIFEST_SCHEMA
        or manifest["manifest_version"] != SCHEMA_MANIFEST_VERSION
    ):
        _protocol_error("schema_manifest_invalid")
    raw_members = manifest["members"]
    if type(raw_members) is not list or len(raw_members) != SCHEMA_MEMBER_COUNT:
        _protocol_error("schema_manifest_member_mismatch")

    members: list[_ManifestMember] = []
    seen_paths: set[str] = set()
    declared_paths: list[str] = []
    for raw_member in raw_members:
        if type(raw_member) is not dict:
            _protocol_error("schema_manifest_member_mismatch")
        member = cast(dict[str, JsonValue], raw_member)
        if frozenset(member) != _MEMBER_FIELDS:
            _protocol_error("schema_manifest_member_mismatch")

        path = _validate_relative_schema_path(member["path"])
        if path in seen_paths:
            _protocol_error("schema_manifest_duplicate_path")
        seen_paths.add(path)
        declared_paths.append(path)

        schema_id = member["$id"]
        schema_version = member["schema_version"]
        media_type = member["media_type"]
        owning_model = member["owning_model"]
        byte_length = member["byte_length"]
        digest = member["sha256"]
        if (
            type(schema_id) is not str
            or type(schema_version) is not str
            or type(media_type) is not str
            or media_type != _SCHEMA_MEDIA_TYPE
            or type(owning_model) is not str
            or not owning_model
            or type(byte_length) is not int
            or byte_length < 0
            or type(digest) is not str
            or _SHA256_PATTERN.fullmatch(digest) is None
        ):
            _protocol_error("schema_manifest_member_mismatch")

        raw_kind = member["schema_kind"]
        if type(raw_kind) is not str:
            _protocol_error("schema_kind_mismatch")
        try:
            kind = SchemaKind(raw_kind)
        except ValueError:
            _protocol_error("schema_kind_mismatch")

        raw_role = member["artifact_role"]
        if type(raw_role) is not str:
            _protocol_error("schema_artifact_role_invalid")
        try:
            role = SchemaArtifactRole(raw_role)
        except ValueError:
            _protocol_error("schema_artifact_role_invalid")

        members.append(
            _ManifestMember(
                path=path,
                schema_id=schema_id,
                schema_version=schema_version,
                schema_kind=kind,
                artifact_role=role,
                byte_length=byte_length,
                sha256=digest,
            )
        )

    if declared_paths != sorted(declared_paths, key=str.encode):
        _protocol_error("schema_manifest_invalid")
    return tuple(members)


def _derive_identity(path: str, version: str) -> tuple[str, str]:
    if SCHEMA_VERSION_PATTERN.fullmatch(version) is None:
        _protocol_error("schema_version_mismatch")
    filename = path.rsplit("/", 1)[1]
    suffix = f"-{version}.schema.json"
    if not filename.endswith(suffix):
        _protocol_error("schema_version_mismatch")
    name = filename[: -len(suffix)]
    if _SCHEMA_NAME_PATTERN.fullmatch(name) is None:
        _protocol_error("schema_version_mismatch")
    return name, version


def _derive_kind(path: str) -> SchemaKind:
    prefix = path.split("/", 1)[0]
    if prefix == "events":
        return SchemaKind.EVENT
    if prefix == "config":
        return SchemaKind.CONFIG
    if prefix == "version":
        return SchemaKind.VERSION_MANIFEST
    if prefix in {
        "common",
        "consent",
        "operations",
        "observations",
        "findings",
        "receipts",
        "privacy",
        "service",
        "integrations",
    }:
        return SchemaKind.REQUEST_RESULT
    _protocol_error("schema_kind_mismatch")


def _derive_role(path: str) -> SchemaArtifactRole:
    directory, filename = path.split("/", 1)
    if directory == "integrations" and filename.startswith("mcp-removal-"):
        return SchemaArtifactRole.SETUP_CONTRACT
    if directory == "integrations" and filename.startswith("host-connection-"):
        return SchemaArtifactRole.SETUP_CONTRACT
    if directory == "integrations" and filename.startswith("setup-status-"):
        return SchemaArtifactRole.SETUP_CONTRACT
    if directory == "integrations" and filename.startswith("setup-readiness-"):
        return SchemaArtifactRole.SETUP_CONTRACT
    if directory == "common":
        if filename.startswith("operation-result-"):
            return SchemaArtifactRole.MCP_OUTPUT
        return SchemaArtifactRole.COMMON_VALUE
    if directory == "consent":
        return SchemaArtifactRole.LOCAL_CONTROL
    if directory == "observations" and filename.startswith("routine-read-summary-"):
        return SchemaArtifactRole.LOCAL_CONTROL
    if directory == "operations":
        if "-request-" in filename:
            return SchemaArtifactRole.MCP_INPUT
        if "-result-" in filename:
            return SchemaArtifactRole.MCP_OUTPUT
        _protocol_error("schema_artifact_role_mismatch")
    if directory == "events":
        if filename.startswith("accepted-event-"):
            return SchemaArtifactRole.PERSISTED_ENVELOPE
        if filename.startswith(("event-draft-", "opaque-unknown-event-draft-")):
            return SchemaArtifactRole.EVENT_ENVELOPE
        return SchemaArtifactRole.EVENT_PAYLOAD
    if directory == "findings":
        if filename.startswith("finding-"):
            return SchemaArtifactRole.FINDING
        if filename.startswith("provider-judgment-"):
            return SchemaArtifactRole.PROVIDER_JUDGMENT
        if filename.startswith(("semantic-provenance-", "runtime-attempt-evidence-")):
            return SchemaArtifactRole.SEMANTIC_PROVENANCE
        _protocol_error("schema_artifact_role_mismatch")
    if directory == "config":
        return SchemaArtifactRole.CONFIGURATION
    if directory == "receipts":
        return SchemaArtifactRole.RECEIPT_DOCUMENT
    if directory == "version":
        return SchemaArtifactRole.VERSION_REPORT
    if directory == "privacy":
        if filename.startswith("privacy-policy-"):
            return SchemaArtifactRole.PRIVACY_POLICY
        if filename.startswith(("outbound-case-", "review-packet-row-")):
            return SchemaArtifactRole.OUTBOUND_CASE
        if filename.startswith("egress-receipt-"):
            return SchemaArtifactRole.PRIVACY_AUDIT
        if filename.startswith("setup-wizard-contract-"):
            return SchemaArtifactRole.SETUP_CONTRACT
        _protocol_error("schema_artifact_role_mismatch")
    if directory == "service":
        if filename.startswith(("service-status-", "isolation-report-")):
            return SchemaArtifactRole.SERVICE_STATUS
        if filename.startswith(
            ("control-hello-", "control-hello-result-", "control-request-", "control-result-")
        ):
            return SchemaArtifactRole.LOCAL_CONTROL
        _protocol_error("schema_artifact_role_mismatch")
    _protocol_error("schema_artifact_role_mismatch")


def _freeze_json(value: JsonValue) -> JsonValue:
    if type(value) is dict:
        source = cast(dict[str, JsonValue], value)
        frozen = {
            key: _freeze_json(source[key])
            for key in sorted(source, key=lambda item: item.encode("utf-16-be"))
        }
        return MappingProxyType(frozen)
    if type(value) is list:
        return tuple(_freeze_json(item) for item in cast(list[JsonValue], value))
    return value


def _plain_validation_instance(value: JsonValue) -> tuple[JsonValue, bool]:
    """The plain dict/list instance the validator reads, and whether it holds a spliced fragment.

    A :class:`CanonicalFragment` has the canonical text of the value it stands for but is not that
    value to the validator, so its verdict must never be shared with that value.
    """

    spliced = False

    def plain(item: JsonValue) -> JsonValue:
        nonlocal spliced
        if _actual_mapping(item):
            source = cast(Mapping[str, JsonValue], item)
            return {key: plain(member) for key, member in source.items()}
        if type(item) is list or type(item) is tuple:
            return [plain(member) for member in item]
        if type(cast(object, item)) is CanonicalFragment:
            spliced = True
        return item

    return plain(value), spliced


class _ValidInstanceVerdicts:
    """A bounded, thread-safe memory of (schema id, canonical instance digest) pairs found valid.

    Validity is a pure function of the immutable packaged schema and the instance, and canonical
    bytes identify a JSON value exactly, so a repeated validation of the same bytes against the
    same schema has the same answer. One status page is validated about ten times on its way from
    the service to the host (result model, control envelope, client parse, bridge rendering); only
    the first of each needs the validator (issue #916). Invalid instances are never remembered.
    """

    __slots__ = ("_entries", "_limit", "_lock")

    def __init__(self, limit: int) -> None:
        self._entries: OrderedDict[tuple[str, bytes], None] = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def seen(self, key: tuple[str, bytes]) -> bool:
        with self._lock:
            if key not in self._entries:
                return False
            self._entries.move_to_end(key)
            return True

    def remember(self, key: tuple[str, bytes]) -> None:
        with self._lock:
            self._entries[key] = None
            self._entries.move_to_end(key)
            while len(self._entries) > self._limit:
                self._entries.popitem(last=False)


def _walk_refs(value: JsonValue) -> Iterator[str]:
    if type(value) is dict:
        source = cast(dict[str, JsonValue], value)
        for key, item in source.items():
            if key == "$ref":
                if type(item) is not str:
                    _protocol_error("schema_reference_unresolved")
                yield item
            yield from _walk_refs(item)
    elif type(value) is list:
        for item in cast(list[JsonValue], value):
            yield from _walk_refs(item)


def _build_registry(plain_by_id: Mapping[str, dict[str, JsonValue]]) -> SchemaRegistry:
    registry: Registry[Schema] = Registry(retrieve=_deny_retrieve)
    for schema_id in sorted(plain_by_id, key=str.encode):
        registry = registry.with_resource(
            schema_id, DRAFT202012.create_resource(plain_by_id[schema_id])
        )
    return registry


def _validate_references(
    plain_by_id: Mapping[str, dict[str, JsonValue]], registry: SchemaRegistry
) -> None:
    known_ids = frozenset(plain_by_id)
    for schema_id in sorted(plain_by_id, key=str.encode):
        schema = plain_by_id[schema_id]
        resolver = registry.resolver(schema_id)
        for ref in _walk_refs(schema):
            split = urlsplit(ref)
            if split.query:
                _protocol_error("schema_reference_unresolved")
            if ref.startswith("#"):
                admissible = split.scheme == split.netloc == split.path == ""
            else:
                base, _ = urldefrag(ref)
                admissible = (
                    bool(split.scheme)
                    and bool(split.netloc)
                    and base in known_ids
                    and split.scheme == "https"
                )
            if not admissible:
                _protocol_error("schema_reference_unresolved")
            try:
                resolver.lookup(ref)
            except BaseException:
                raise ProtocolValueError("schema_reference_unresolved") from None


def _plain_schema(data: bytes, *, digest_verified: bool = False) -> dict[str, JsonValue]:
    try:
        parsed = strict_json_parse(data)
        if canonical_encode(parsed) != data:
            _protocol_error("schema_bytes_invalid")
        schema = _as_plain_object(parsed, "schema_bytes_invalid")
    except ProtocolValueError as exc:
        if exc.reason_code == "schema_bytes_invalid":
            raise
        raise ProtocolValueError("schema_bytes_invalid") from None
    dialect = schema.get("$schema")
    if dialect != _DRAFT_2020_12:
        _protocol_error("schema_draft_unsupported")
    if not digest_verified:
        # Draft meta-validation dominates catalog load cost (~81% measured, #210).
        # Members whose bytes already matched the packaged manifest digest carry
        # the same trust as the code itself; their meta-validity is a build-time
        # invariant enforced by tests/conformance over the packaged catalog.
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError:
            raise ProtocolValueError("schema_bytes_invalid") from None
    return schema


@lru_cache(maxsize=1)
def _load_catalog_state() -> _CatalogState:
    root = _schema_root()
    manifest_resource = root.joinpath("manifest.json")
    manifest_bytes = _read_resource(manifest_resource, "schema_manifest_missing")
    members = _parse_manifest(manifest_bytes)
    expected_files = frozenset({"manifest.json", *(member.path for member in members)})
    if _collect_files(root) != expected_files:
        _protocol_error("schema_manifest_member_mismatch")

    documents: list[SchemaDocument] = []
    plain_by_id: dict[str, dict[str, JsonValue]] = {}
    seen_identities: set[tuple[str, str]] = set()

    for member in members:
        resource = _resource_at(root, member.path)
        data = _read_resource(resource, "schema_manifest_member_mismatch")
        if len(data) != member.byte_length:
            _protocol_error("schema_manifest_member_mismatch")
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if digest != member.sha256:
            _protocol_error("schema_digest_mismatch")
        plain = _plain_schema(data, digest_verified=True)
        name, version = _derive_identity(member.path, member.schema_version)
        expected_id = SCHEMA_NAMESPACE + member.path
        document_id = plain.get("$id")
        if member.schema_id != expected_id or document_id != expected_id:
            _protocol_error("schema_id_mismatch")
        if member.schema_kind is not _derive_kind(member.path):
            _protocol_error("schema_kind_mismatch")
        if member.artifact_role is not _derive_role(member.path):
            _protocol_error("schema_artifact_role_mismatch")
        identity = (name, version)
        if expected_id in plain_by_id or identity in seen_identities:
            _protocol_error("schema_duplicate_identity")
        plain_by_id[expected_id] = plain
        seen_identities.add(identity)
        frozen = _freeze_json(plain)
        if not _actual_mapping(frozen):
            _protocol_error("schema_bytes_invalid")
        documents.append(
            SchemaDocument(
                schema_kind=member.schema_kind,
                artifact_role=member.artifact_role,
                schema_name=name,
                schema_version=version,
                schema_id=expected_id,
                relative_path=member.path,
                canonical_digest=digest,
                schema_bytes=data,
                json_schema=cast(Mapping[str, JsonValue], frozen),
            )
        )

    registry = _build_registry(plain_by_id)
    _validate_references(plain_by_id, registry)

    ordered_documents = tuple(documents)
    by_path_dict = {document.relative_path: document for document in ordered_documents}
    by_id_dict = {
        document.schema_id: document
        for document in sorted(ordered_documents, key=lambda item: item.schema_id.encode("ascii"))
    }
    by_name_version_dict = {
        (document.schema_name, document.schema_version): document
        for document in sorted(
            ordered_documents,
            key=lambda item: (
                item.schema_name.encode("ascii"),
                item.schema_version.encode("ascii"),
            ),
        )
    }
    request_versions_dict = {
        document.schema_name: document.schema_version
        for document in sorted(
            (item for item in ordered_documents if item.schema_kind is SchemaKind.REQUEST_RESULT),
            key=lambda item: (
                item.schema_name.encode("ascii"),
                tuple(int(part) for part in item.schema_version.split(".")),
            ),
        )
    }
    event_versions_dict = {
        document.schema_name.replace("-", "_"): document.schema_version
        for document in sorted(
            (
                item
                for item in ordered_documents
                if item.artifact_role is SchemaArtifactRole.EVENT_PAYLOAD
            ),
            key=lambda item: item.schema_name.replace("-", "_").encode("ascii"),
        )
    }
    if len(request_versions_dict) != 54 or len(event_versions_dict) != 29:
        _protocol_error("schema_catalog_incomplete")

    catalog = SchemaCatalog(
        documents=ordered_documents,
        by_path=MappingProxyType(by_path_dict),
        by_id=MappingProxyType(by_id_dict),
        by_name_version=MappingProxyType(by_name_version_dict),
        request_result_versions=MappingProxyType(request_versions_dict),
        event_schema_versions=MappingProxyType(event_versions_dict),
        manifest_version=SCHEMA_MANIFEST_VERSION,
        manifest_digest=f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}",
    )
    return _CatalogState(
        catalog=catalog,
        plain_by_id=MappingProxyType(plain_by_id),
        registry=registry,
    )


def load_schema_catalog() -> SchemaCatalog:
    """Load and validate the immutable packaged schema catalog."""

    return _load_catalog_state().catalog


def _uses_dynamic_reference(value: JsonValue) -> bool:
    if type(value) is dict:
        source = cast(dict[str, JsonValue], value)
        return any(
            key in {"$dynamicRef", "$recursiveRef"} or _uses_dynamic_reference(item)
            for key, item in source.items()
        )
    if type(value) is list:
        return any(_uses_dynamic_reference(item) for item in cast(list[JsonValue], value))
    return False


@dataclass(frozen=True, slots=True)
class _ValidityChecker:
    """Decides schema validity for one loaded catalog without building diagnostics (issue #916).

    It accepts and rejects exactly what the stock ``Draft202012Validator`` does; its keywords
    differ only in how much they evaluate. ``anyOf`` and ``oneOf`` stop each failing branch at its
    first error, and ``$ref`` resolves each reference once. Documents drop their root ``$schema``
    marker because ``jsonschema`` picks the class for a referenced document from it, which would
    hand every cross-document reference back to the stock class; every member is draft 2020-12
    (``_plain_schema`` refuses anything else) and is registered with that specification
    explicitly, so the marker changes no keyword and no reference. An instance it rejects goes to
    the stock validator, which builds the exact diagnostic the caller always received.
    """

    state: _CatalogState
    plain_by_id: Mapping[str, dict[str, JsonValue]]
    registry: SchemaRegistry
    verdicts: _ValidInstanceVerdicts
    # Remembers and reuses verdicts; the other one never does, for an instance holding a fragment.
    remembering_class: Any
    forgetful_class: Any

    @classmethod
    def build(cls, state: _CatalogState) -> _ValidityChecker | None:
        if any(_uses_dynamic_reference(plain) for plain in state.plain_by_id.values()):
            # Dynamic scope would make a resolved reference depend on the path taken to it.
            return None
        stripped = {
            schema_id: {key: value for key, value in plain.items() if key != "$schema"}
            for schema_id, plain in state.plain_by_id.items()
        }
        document_roots = MappingProxyType(
            {id(plain): schema_id for schema_id, plain in stripped.items()}
        )
        verdicts = _ValidInstanceVerdicts(_VALID_INSTANCE_MEMORY)
        extend = cast(Callable[..., Any], getattr(jsonschema_validators, "extend"))

        def validator_class(memory: _ValidInstanceVerdicts | None) -> Any:
            return extend(
                Draft202012Validator,
                {
                    "$ref": _ref_resolved_once({}, document_roots, memory),
                    "anyOf": _any_of_first_error,
                    "oneOf": _one_of_first_error,
                },
            )

        return cls(
            state,
            MappingProxyType(stripped),
            _build_registry(stripped),
            verdicts,
            validator_class(verdicts),
            validator_class(None),
        )

    def is_valid(self, schema_id: str, instance: JsonValue, digest: bytes | None) -> bool:
        """Whether the stock validator accepts *instance*; ``False`` whenever it cannot tell.

        *digest* is the SHA-256 of the instance's canonical bytes, or ``None`` when the instance
        holds a spliced fragment and must not share verdicts.
        """

        try:
            if digest is not None and self.verdicts.seen((schema_id, digest)):
                return True
            validator_class = self.forgetful_class if digest is None else self.remembering_class
            validator = validator_class(
                self.plain_by_id[schema_id],
                registry=self.registry,
                format_checker=_FORMAT_CHECKER,
            )
            valid = next(validator.iter_errors(instance), None) is None
        except Exception:
            return False
        if valid and digest is not None:
            self.verdicts.remember((schema_id, digest))
        return valid


_VALID_INSTANCE_MEMORY: Final = 256
_VALIDITY_CHECKER_LOCK: Final = threading.Lock()
# (catalog state, its checker or None when the catalog cannot use one); rebuilt with the catalog.
_validity_checker_slot: list[tuple[_CatalogState, _ValidityChecker | None]] = []


def _validity_checker() -> _ValidityChecker | None:
    """The validity checker for the currently loaded catalog."""

    state = _load_catalog_state()
    with _VALIDITY_CHECKER_LOCK:
        if _validity_checker_slot and _validity_checker_slot[0][0] is state:
            return _validity_checker_slot[0][1]
        try:
            checker = _ValidityChecker.build(state)
        except Exception:
            checker = None
        _validity_checker_slot[:] = [(state, checker)]
        return checker


@lru_cache(maxsize=1)
def schema_manifest_digest() -> str:
    """Digest of the packaged schema manifest, without building the catalog.

    Byte-identical to ``load_schema_catalog().manifest_digest`` — the digest
    depends only on ``manifest.json`` — but skips reading and meta-validating
    every catalog member. Handshake-style compatibility checks that only
    compare digests must use this; catalog construction stays lazy for
    callers that actually validate instances (#210).
    """

    manifest_bytes = _read_resource(
        _schema_root().joinpath("manifest.json"), "schema_manifest_missing"
    )
    return f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"


def _validate_lookup_identity(name: object, version: object) -> tuple[str, str]:
    if (
        type(name) is not str
        or type(version) is not str
        or _SCHEMA_NAME_PATTERN.fullmatch(name) is None
        or SCHEMA_VERSION_PATTERN.fullmatch(version) is None
    ):
        _protocol_error("schema_name_invalid")
    return name, version


def schema_path_for(name: str, version: str) -> str:
    """Return the exact packaged path for one canonical schema identity."""

    identity = _validate_lookup_identity(name, version)
    document = load_schema_catalog().by_name_version.get(identity)
    if document is None:
        _protocol_error("schema_not_found")
    return document.relative_path


def schema_uri(name: str, version: str) -> str:
    """Return the static-host URI for one canonical schema identity."""

    return SCHEMA_NAMESPACE + schema_path_for(name, version)


def schema_document_for(name: str, version: str) -> SchemaDocument:
    """Return one validated packaged schema document."""

    identity = _validate_lookup_identity(name, version)
    document = load_schema_catalog().by_name_version.get(identity)
    if document is None:
        _protocol_error("schema_not_found")
    return document


def validate_schema_document(document: SchemaDocument) -> None:
    """Recheck the bounded public invariants of one schema document."""

    if type(document) is not SchemaDocument:
        _protocol_error("schema_bytes_invalid")
    if hashlib.sha256(document.schema_bytes).hexdigest() != document.canonical_digest.removeprefix(
        "sha256:"
    ):
        _protocol_error("schema_digest_mismatch")
    plain = _plain_schema(document.schema_bytes)
    expected_id = SCHEMA_NAMESPACE + document.relative_path
    if plain.get("$id") != expected_id or document.schema_id != expected_id:
        _protocol_error("schema_id_mismatch")
    name, version = _derive_identity(document.relative_path, document.schema_version)
    if name != document.schema_name or version != document.schema_version:
        _protocol_error("schema_version_mismatch")
    if document.schema_kind is not _derive_kind(document.relative_path):
        _protocol_error("schema_kind_mismatch")
    if document.artifact_role is not _derive_role(document.relative_path):
        _protocol_error("schema_artifact_role_mismatch")
    try:
        if canonical_encode(document.json_schema) != document.schema_bytes:
            _protocol_error("schema_bytes_invalid")
    except ProtocolValueError:
        raise ProtocolValueError("schema_bytes_invalid") from None


def request_result_schema_versions(catalog: SchemaCatalog) -> Mapping[str, str]:
    """Return the catalog's immutable request/result version map."""

    if type(catalog) is not SchemaCatalog:
        raise TypeError("schema_catalog_wrong_type")
    return catalog.request_result_versions


def event_schema_versions(catalog: SchemaCatalog) -> Mapping[str, str]:
    """Return the catalog's immutable event-payload version map."""

    if type(catalog) is not SchemaCatalog:
        raise TypeError("schema_catalog_wrong_type")
    return catalog.event_schema_versions


# Closed reason tokens for root-level object rules (dependentRequired, if/then required).
# These travel through Pydantic value_error ctx and MCP safe_details; never invent free-form text.
_OBJECT_RULE_PAIRED: Final = "paired_field_required"
_OBJECT_RULE_CONDITIONAL: Final = "conditional_field_required"
_OBJECT_RULE_REASONS: Final = frozenset({_OBJECT_RULE_PAIRED, _OBJECT_RULE_CONDITIONAL})
_MAX_PROJECTED_OBJECT_LOCATIONS: Final = 8
# Closed reason token for a nested instance failure. Only the class of the mistake travels; the
# rejected key names are caller-controlled and never leave the validator (issue #240).
_INSTANCE_REASON_EXTRA_FORBIDDEN: Final = "extra_forbidden"
_INSTANCE_REASON_CONDITIONAL_FIELD_REQUIRED: Final = "conditional_field_required"
_INSTANCE_REASONS: Final = frozenset(
    {_INSTANCE_REASON_EXTRA_FORBIDDEN, _INSTANCE_REASON_CONDITIONAL_FIELD_REQUIRED}
)
MAX_UNKNOWN_PROPERTY_COUNT: Final = 32
_UNKNOWN_PROPERTY_COUNT_OVERFLOW: Final = MAX_UNKNOWN_PROPERTY_COUNT + 1
EVENT_FAMILY_NAME_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)


class SchemaInstanceInvalid(ProtocolValueError):
    """Schema admission failure with optional path(s) for caller recovery.

    ``absolute_path`` names one nested field when jsonschema already points there.
    ``location_reasons`` carries root-level object-rule projections (pairing / conditional
    required) when the instance path is empty but the schema names safe corrective fields.
    ``reason``, ``family``, ``family_version``, and ``unknown_count`` describe a named nested
    failure: a closed token, a frozen schema-derived family name, that family's frozen schema
    version, and a bounded cardinality. ``condition_field`` and ``condition_value`` are populated
    only for a selected const-discriminated ``oneOf`` branch. No caller-supplied key or value is
    admitted through any of them — ``family_version`` is read from the catalogue entry the
    failing schema's own ``$id`` names, or, for a value nested inside a draft payload, from the
    catalogue entry whose name and version the draft's admitted ``schema`` byte-equals; an
    uncatalogued pair travels as nothing.
    ``misplaced_field`` names one rejected key only when it byte-equals a payload property name
    some catalogued event family declares, so the token that travels is frozen schema vocabulary
    and never a caller-invented key (issue #266). ``missing_fields`` names the members of a
    failing ``required`` list the instance lacks; every name is read from that schema list.
    """

    __slots__ = (
        "absolute_path",
        "condition_field",
        "condition_value",
        "family",
        "family_version",
        "location_reasons",
        "misplaced_field",
        "missing_fields",
        "reason",
        "unknown_count",
    )

    absolute_path: tuple[str | int, ...]
    condition_field: str | None
    condition_value: str | None
    location_reasons: tuple[tuple[tuple[str | int, ...], str], ...]
    reason: str | None
    family: str | None
    family_version: str | None
    unknown_count: int
    misplaced_field: str | None
    missing_fields: tuple[str, ...]

    def __init__(
        self,
        absolute_path: tuple[str | int, ...] = (),
        location_reasons: tuple[tuple[tuple[str | int, ...], str], ...] = (),
        *,
        reason: str | None = None,
        family: str | None = None,
        family_version: str | None = None,
        unknown_count: int = 0,
        misplaced_field: str | None = None,
        missing_fields: tuple[str, ...] = (),
        condition_field: str | None = None,
        condition_value: str | None = None,
    ) -> None:
        if type(absolute_path) is not tuple:
            raise TypeError("schema_instance_path_invalid")
        if any(type(item) is not str and type(item) is not int for item in absolute_path):
            raise TypeError("schema_instance_path_invalid")
        if type(location_reasons) is not tuple:
            raise TypeError("schema_instance_locations_invalid")
        for item in location_reasons:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("schema_instance_locations_invalid")
            path, item_reason = item
            if type(path) is not tuple:
                raise TypeError("schema_instance_locations_invalid")
            if any(type(segment) is not str and type(segment) is not int for segment in path):
                raise TypeError("schema_instance_locations_invalid")
            if type(item_reason) is not str or item_reason not in _OBJECT_RULE_REASONS:
                raise TypeError("schema_instance_locations_invalid")
        if reason is not None and reason not in _INSTANCE_REASONS:
            raise TypeError("schema_instance_reason_invalid")
        if family is not None and (
            type(family) is not str or EVENT_FAMILY_NAME_PATTERN.fullmatch(family) is None
        ):
            raise TypeError("schema_instance_family_invalid")
        if family_version is not None and (
            type(family_version) is not str
            or SCHEMA_VERSION_PATTERN.fullmatch(family_version) is None
        ):
            raise TypeError("schema_instance_family_version_invalid")
        if (
            type(unknown_count) is not int
            or not 0 <= unknown_count <= _UNKNOWN_PROPERTY_COUNT_OVERFLOW
        ):
            raise TypeError("schema_instance_unknown_count_invalid")
        if misplaced_field is not None and (
            type(misplaced_field) is not str
            or EVENT_FAMILY_NAME_PATTERN.fullmatch(misplaced_field) is None
        ):
            raise TypeError("schema_instance_misplaced_field_invalid")
        if (
            type(missing_fields) is not tuple
            or len(missing_fields) > _MAX_PROJECTED_OBJECT_LOCATIONS
            or any(
                type(name) is not str or EVENT_FAMILY_NAME_PATTERN.fullmatch(name) is None
                for name in missing_fields
            )
        ):
            raise TypeError("schema_instance_missing_fields_invalid")
        if (condition_field is None) != (condition_value is None):
            raise TypeError("schema_instance_condition_invalid")
        if condition_field is not None and (
            EVENT_FAMILY_NAME_PATTERN.fullmatch(condition_field) is None
            or type(condition_value) is not str
            or not condition_value.isascii()
            or not 1 <= len(condition_value) <= 64
        ):
            raise TypeError("schema_instance_condition_invalid")
        self.absolute_path = absolute_path
        self.condition_field = condition_field
        self.condition_value = condition_value
        self.location_reasons = location_reasons
        self.reason = reason
        self.family = family
        self.family_version = family_version
        self.unknown_count = unknown_count
        self.misplaced_field = misplaced_field
        self.missing_fields = missing_fields
        super().__init__("schema_instance_invalid")


def validate_schema_instance(name: str, version: str, value: JsonValue) -> None:
    """Validate a canonical JSON value against one exact local schema."""

    document = schema_document_for(name, version)
    # Encoding enforces the canonical profile exactly as ``ensure_canonical_value`` does, and its
    # bytes identify the instance for the checker's verdict memory.
    digest = hashlib.sha256(canonical_encode(value)).digest()
    instance, spliced = _plain_validation_instance(value)
    checker = _validity_checker()
    if checker is not None and checker.is_valid(
        document.schema_id, instance, None if spliced else digest
    ):
        return
    state = _load_catalog_state()
    plain = state.plain_by_id[document.schema_id]
    validator = Draft202012Validator(
        plain,
        registry=state.registry,
        format_checker=_FORMAT_CHECKER,
    )
    try:
        validator_api = cast(_ValidatorProtocol, cast(object, validator))
        validator_api.validate(instance)
    except ValidationError as exc:
        best = _best_schema_instance_error(exc)
        # A selected nested oneOf can expose a missing peer even though the parent request path is
        # nonempty. Project it before the generic best-path rule, which otherwise points at the
        # satisfied discriminator selected only to score the union.
        selected = _project_selected_one_of_required_locations(exc)
        if selected is not None:
            projected, condition_field, condition_value, identity = selected
            raise SchemaInstanceInvalid(
                (),
                projected,
                reason=_INSTANCE_REASON_CONDITIONAL_FIELD_REQUIRED,
                family=identity[0] if identity is not None else None,
                family_version=identity[1] if identity is not None else None,
                condition_field=condition_field,
                condition_value=condition_value,
            ) from None
        path = _path_items_from(best) or ()
        if path:
            reason = _instance_reason_for(best)
            # A missing required payload key also names its frozen family, so the MCP hint can
            # state that family's required and admitted keys instead of the generic envelope
            # recital (benchmark full3: plan_revised drafts written with plan_published keys).
            identity = (
                _selected_family_for(best)
                if reason is not None or best.validator == "required"
                else None
            )
            if identity is None and reason is None:
                # A nested value failure (an id pattern inside ``limitation_refs``) carries no
                # ``$id`` of its own. The draft's admitted schema identity selected the branch
                # that rejected it, so name that family and version: several families share a
                # field name with different admitted shapes (tb4n1: result ``evidence_refs``).
                identity = _draft_family_for_payload_path(instance, path)
            # tb4n5 (#1049): a payload value a sibling's const narrows (``digest_binding.subject``
            # by ``evidence_kind``) names the frozen branch the draft selected, so the hint states
            # that branch's subset instead of the property's whole union.
            condition = (
                _payload_condition_for(instance, path, identity)
                if identity is not None and reason is None
                else None
            )
            raise SchemaInstanceInvalid(
                path,
                reason=reason,
                family=identity[0] if identity is not None else None,
                family_version=identity[1] if identity is not None else None,
                unknown_count=_unknown_property_count(best) if reason is not None else 0,
                misplaced_field=_misplaced_known_field(best) if reason is not None else None,
                missing_fields=_missing_required_fields(best),
                condition_field=condition[0] if condition is not None else None,
                condition_value=condition[1] if condition is not None else None,
            ) from None
        # Root-level object rules (dependentRequired, if/then anyOf required) report an empty
        # instance path. Project only schema-named fields so MCP can name the corrective pair.
        projected = _project_root_object_rule_locations(exc)
        if projected:
            raise SchemaInstanceInvalid((), projected) from None
        # A conditional ``not required`` (status ``filter`` beside a view that admits none) also
        # reports an empty path. Name the forbidden schema-declared field so the caller learns
        # which key to drop instead of a bare template pointer (tb4n1: 3 status rejections).
        forbidden = _root_conditionally_forbidden_field(exc)
        if forbidden is not None:
            raise SchemaInstanceInvalid(
                (forbidden,), reason=_INSTANCE_REASON_EXTRA_FORBIDDEN
            ) from None
        raise SchemaInstanceInvalid() from None
    except BaseException:
        raise SchemaInstanceInvalid() from None


def _missing_required_fields(error: ValidationError) -> tuple[str, ...]:
    """Name the schema-listed ``required`` members the instance lacks, in schema order.

    Each name is read from the failing schema's own ``required`` list, so it is frozen schema
    vocabulary: tb4n1 agents were told a family's whole required list when one key was absent.
    """

    if error.validator != "required":
        return ()
    names = error.validator_value
    instance = error.instance
    if not isinstance(names, list) or not isinstance(instance, Mapping):
        return ()
    missing: list[str] = []
    for name in cast(list[object], names):
        if (
            type(name) is str
            and EVENT_FAMILY_NAME_PATTERN.fullmatch(name) is not None
            and name not in cast(Mapping[object, object], instance)
            and name not in missing
        ):
            missing.append(name)
        if len(missing) == _MAX_PROJECTED_OBJECT_LOCATIONS:
            break
    return tuple(missing)


def _draft_family_for_payload_path(
    instance: object, path: tuple[str | int, ...]
) -> tuple[str, str] | None:
    """Return the catalogued family and version of the draft whose payload holds ``path``.

    Only a path strictly inside ``/event_drafts/<n>/payload`` qualifies. The draft's
    ``schema.name`` and ``schema.version`` must byte-equal a catalogued event schema; the returned
    pair is read from that catalogue entry, so nothing outside the frozen vocabulary travels.
    """

    try:
        if (
            len(path) < 4
            or path[0] != "event_drafts"
            or type(path[1]) is not int
            or path[2] != "payload"
            or not isinstance(instance, Mapping)
        ):
            return None
        drafts = cast(Mapping[str, object], instance).get("event_drafts")
        if not isinstance(drafts, list) or not 0 <= path[1] < len(cast(list[object], drafts)):
            return None
        draft = cast(list[object], drafts)[path[1]]
        if not isinstance(draft, Mapping):
            return None
        identity = cast(Mapping[str, object], draft).get("schema")
        if not isinstance(identity, Mapping):
            return None
        name = cast(Mapping[str, object], identity).get("name")
        version = cast(Mapping[str, object], identity).get("version")
        if type(name) is not str or type(version) is not str:
            return None
        catalog = _load_catalog_state().catalog
        if name not in catalog.event_schema_versions:
            return None
        for document in catalog.by_id.values():
            family = document.schema_name.replace("-", "_")
            if family == name and document.schema_version == version:
                if SCHEMA_VERSION_PATTERN.fullmatch(document.schema_version) is None:
                    return None
                return (family, document.schema_version)
    except Exception:
        return None
    return None


def _payload_condition_for(
    instance: object, path: tuple[str | int, ...], identity: tuple[str, str]
) -> tuple[str, str] | None:
    """The ``(field, const)`` of the family branch that narrows the value at ``path``, or None.

    Only a top-level ``allOf`` rule of the catalogued family schema qualifies: its ``if`` holds
    exactly one ``const`` on a required sibling field, and its ``then`` narrows the payload path
    below ``/event_drafts/<n>/payload`` to an ``enum``. The draft's sibling value selects the rule
    only when it byte-equals that const, and the pair returned is read from the schema, so nothing
    outside the frozen vocabulary travels (``evidence_kind`` ``test_result`` for
    ``digest_binding/subject``).
    """

    try:
        tail = path[3:]
        if (
            len(tail) < 2
            or any(type(segment) is not str for segment in tail)
            or not isinstance(instance, Mapping)
        ):
            return None
        drafts = cast(Mapping[str, object], instance).get("event_drafts")
        index = path[1]
        if not isinstance(drafts, list) or type(index) is not int:
            return None
        draft = cast(list[object], drafts)[index]
        if not isinstance(draft, Mapping):
            return None
        payload = cast(Mapping[str, object], draft).get("payload")
        if not isinstance(payload, Mapping):
            return None
        family, version = identity
        state = _load_catalog_state()
        document = schema_document_for(family.replace("_", "-"), version)
        rules = state.plain_by_id[document.schema_id].get("allOf")
        if not isinstance(rules, list):
            return None
        for rule in cast(list[JsonValue], rules):
            if not isinstance(rule, Mapping):
                continue
            condition = cast(Mapping[str, JsonValue], rule).get("if")
            narrowed: JsonValue = cast(Mapping[str, JsonValue], rule).get("then")
            if not isinstance(condition, Mapping):
                continue
            properties = cast(Mapping[str, JsonValue], condition).get("properties")
            required = cast(Mapping[str, JsonValue], condition).get("required")
            if not isinstance(properties, Mapping) or not isinstance(required, list):
                continue
            consts = [
                (name, cast(Mapping[str, JsonValue], spec).get("const"))
                for name, spec in cast(Mapping[str, JsonValue], properties).items()
                if isinstance(spec, Mapping)
            ]
            if len(consts) != 1:
                continue
            field, value = consts[0]
            if (
                type(value) is not str
                or field == tail[0]
                or field not in cast(list[JsonValue], required)
                or EVENT_FAMILY_NAME_PATTERN.fullmatch(field) is None
            ):
                continue
            for segment in tail:
                nested = (
                    cast(Mapping[str, JsonValue], narrowed).get("properties")
                    if isinstance(narrowed, Mapping)
                    else None
                )
                narrowed = (
                    cast(Mapping[str, JsonValue], nested).get(cast(str, segment))
                    if isinstance(nested, Mapping)
                    else None
                )
            if not isinstance(narrowed, Mapping) or "enum" not in narrowed:
                continue
            submitted = cast(Mapping[str, object], payload).get(field)
            if type(submitted) is str and submitted == value:
                return (field, value)
    except Exception:
        return None
    return None


def _root_conditionally_forbidden_field(exc: ValidationError) -> str | None:
    """Return the one field a root ``if``/``then`` ``not required`` rule forbids, or None.

    The name is read from the schema's own ``not.required`` list (checked-in content), and is
    returned only when the instance actually carries it, so the projection names the key to drop
    and never a caller-invented one.
    """

    try:
        candidates = [exc]
        if exc.validator == "allOf":
            candidates.extend(exc.context or ())
        for error in candidates:
            if error.validator != "not" or tuple(error.absolute_path) != ():
                continue
            if "then" not in tuple(error.absolute_schema_path):
                continue
            rule = error.validator_value
            instance = error.instance
            if not isinstance(rule, Mapping) or not isinstance(instance, Mapping):
                continue
            names = cast(Mapping[str, JsonValue], rule).get("required")
            if not isinstance(names, list) or len(cast(list[object], names)) != 1:
                continue
            name = cast(list[object], names)[0]
            if (
                type(name) is str
                and EVENT_FAMILY_NAME_PATTERN.fullmatch(name) is not None
                and name in cast(Mapping[object, object], instance)
            ):
                return name
    except Exception:
        return None
    return None


def _path_items_from(error: ValidationError) -> tuple[str | int, ...] | None:
    """Return a typed absolute path, or None when any segment is unusable."""

    path_items: list[str | int] = []
    for item in error.absolute_path:
        if type(item) is str or type(item) is int:
            path_items.append(item)
        else:
            return None
    return tuple(path_items)


def _schema_property_names(schema: object) -> frozenset[str] | None:
    """Return checked-in property names from a schema object, or None when unusable."""

    if not isinstance(schema, Mapping):
        return None
    properties = cast(Mapping[str, JsonValue], schema).get("properties")
    if not isinstance(properties, Mapping):
        return None
    names = frozenset(key for key in cast(Mapping[object, object], properties) if type(key) is str)
    return names or None


def _safe_schema_field(name: object, property_names: frozenset[str] | None) -> str | None:
    """Admit a field name only when it is a checked-in schema property."""

    if type(name) is not str or property_names is None or name not in property_names:
        return None
    return name


def _project_root_object_rule_locations(
    exc: ValidationError,
) -> tuple[tuple[tuple[str | int, ...], str], ...]:
    """Project known root-level object rules into fixed safe (path, reason) pairs.

    Inspects only validator kind and checked-in schema metadata. Never names a key that is not
    declared on the schema. Failure to derive a safe projection returns empty so the caller
    falls back to a generic invalid request.
    """

    try:
        return _project_root_object_rule_locations_impl(exc)
    except Exception:
        return ()


def _project_selected_one_of_required_locations(
    exc: ValidationError,
) -> (
    tuple[
        tuple[tuple[tuple[str | int, ...], str], ...],
        str | None,
        str | None,
        tuple[str, str] | None,
    ]
    | None
):
    """Project required peers from exactly one const-discriminated ``oneOf`` branch.

    A failed ``oneOf`` normally has an empty instance path.  Flattening all of its branches would
    name fields from alternatives the caller did not choose, while selecting the parent error
    loses the actual missing peer.  This picks a branch only when sibling const rejections prove
    that every other branch was ruled out by the same schema-authored property.  The selected
    branch's own ``required`` list, ``anyOf``-of-``required`` alternatives, and sibling ``allOf``
    ``if``/``then`` required peers are all eligible once the branch is uniquely selected.
    Projection is best-effort: an unexpected error-tree shape degrades to the generic best-path
    rule.
    """

    try:
        return _project_selected_one_of_required_locations_impl(exc)
    except Exception:
        return None


def _project_selected_one_of_required_locations_impl(
    exc: ValidationError,
) -> (
    tuple[
        tuple[tuple[tuple[str | int, ...], str], ...],
        str | None,
        str | None,
        tuple[str, str] | None,
    ]
    | None
):
    if exc.validator != "oneOf" or not isinstance(exc.schema, Mapping):
        return None
    branches: dict[int, list[ValidationError]] = {}
    parent_schema_path = tuple(exc.absolute_schema_path)
    for nested in exc.context or ():
        schema_path = tuple(nested.absolute_schema_path)
        if (
            len(schema_path) <= len(parent_schema_path)
            or schema_path[: len(parent_schema_path)] != parent_schema_path
            or type(schema_path[len(parent_schema_path)]) is not int
        ):
            return None
        branches.setdefault(cast(int, schema_path[len(parent_schema_path)]), []).append(nested)
    if len(branches) < _MIN_DISCRIMINATED_BRANCHES:
        return None
    options = exc.validator_value
    if not isinstance(options, list):
        return None
    option_values = cast(list[object], options)
    root_properties = _schema_property_names(exc.schema)
    if root_properties is None:
        return None
    base_path = _path_items_from(exc)
    if base_path is None:
        return None
    for field in sorted(root_properties):
        selected = _const_discriminator_selected_branch(exc, branches, field=field)
        if selected is None:
            continue
        selected_index, selected_errors, selected_value = selected
        if selected_value is None:
            # A const-free branch can be the sole survivor, but it supplies no safe condition text
            # for a selected-branch repair. The recursive path below may still project an inner
            # schema-authored conditional rule from that branch.
            continue
        ordered = _missing_required_locations(selected_errors, base_path, root_properties)
        if ordered:
            return (tuple(ordered), field, selected_value, _selected_family_for(exc))
    # Descend only into a branch the discriminator proved selected. Recursing into
    # unselected branches would project a sibling contract the caller did not choose
    # (for example the 1.0.0 family for a 1.1.0 draft) whenever selection fails.
    selected = _discriminator_selected_branch(exc)
    if selected is None:
        return None
    for nested in selected:
        projected = _project_selected_one_of_required_locations_impl(nested)
        if projected is not None:
            return projected
    selected_index = _shared_branch_index(parent_schema_path, selected)
    if selected_index is None or not 0 <= selected_index < len(option_values):
        return None
    payload_properties = _payload_property_names_from_option(option_values[selected_index])
    if payload_properties is None:
        return None
    # No discriminator picked this branch's contract, so only rules the schema itself marks
    # conditional (``anyOf``/``allOf`` of ``required``) may be reported as conditional. A plain
    # top-level ``required`` failure here is an unconditional payload field: projecting it would
    # both mislabel the reason and strand the caller with a repair sentence no rule can render.
    ordered = _missing_required_locations(
        selected,
        base_path,
        payload_properties,
        wrappers_only=True,
        branch_schema_path=parent_schema_path + (selected_index,),
    )
    if not ordered:
        return None
    identity = _selected_family_for(exc) or _family_from_option(option_values[selected_index])
    return (tuple(ordered), None, None, identity)


def _shared_branch_index(
    parent_schema_path: tuple[object, ...], errors: Sequence[ValidationError]
) -> int | None:
    """Return the one child index shared by every selected error, or None if mixed."""

    indices: set[int] = set()
    for error in errors:
        schema_path = tuple(error.absolute_schema_path)
        if len(schema_path) <= len(parent_schema_path):
            return None
        index = schema_path[len(parent_schema_path)]
        if type(index) is not int:
            return None
        indices.add(index)
    return next(iter(indices)) if len(indices) == 1 else None


def _payload_property_names_from_option(option: object) -> frozenset[str] | None:
    """Return payload property names from one event-draft union option, resolving ``$ref``."""

    if not isinstance(option, Mapping):
        return None
    properties = cast(Mapping[str, JsonValue], option).get("properties")
    if not isinstance(properties, Mapping):
        return None
    return _schema_property_names(
        _resolve_schema_mapping(cast(Mapping[str, JsonValue], properties).get("payload"))
    )


def _family_from_option(option: object) -> tuple[str, str] | None:
    """Name the family whose payload ``$ref`` this event-draft option carries."""

    payload = _resolve_schema_mapping(_option_payload_node(option))
    if payload is None:
        return None
    schema_id = payload.get("$id")
    if type(schema_id) is not str:
        return None
    document = _load_catalog_state().catalog.by_id.get(schema_id)
    if document is None:
        return None
    family = document.schema_name.replace("-", "_")
    version = document.schema_version
    if family not in _load_catalog_state().catalog.event_schema_versions:
        return None
    return (family, version) if SCHEMA_VERSION_PATTERN.fullmatch(version) is not None else None


def _option_payload_node(option: object) -> object:
    if not isinstance(option, Mapping):
        return None
    properties = cast(Mapping[str, JsonValue], option).get("properties")
    if not isinstance(properties, Mapping):
        return None
    return cast(Mapping[str, JsonValue], properties).get("payload")


def _resolve_schema_mapping(node: object) -> Mapping[str, JsonValue] | None:
    """Return a schema object, following a same-catalog ``$ref`` when that is the node."""

    if not isinstance(node, Mapping):
        return None
    source = cast(Mapping[str, JsonValue], node)
    ref = source.get("$ref")
    if type(ref) is not str:
        return source
    target = _load_catalog_state().plain_by_id.get(ref)
    return target if isinstance(target, dict) else None


def _missing_required_locations(
    errors: Sequence[ValidationError],
    base_path: tuple[str | int, ...],
    admitted: frozenset[str],
    *,
    wrappers_only: bool = False,
    branch_schema_path: tuple[object, ...] = (),
) -> list[tuple[tuple[str | int, ...], str]]:
    """Collect missing schema-named required fields from one already-selected branch.

    Direct ``required`` errors and ``anyOf``/``allOf`` wrappers of ``required`` are in scope.
    Nested ``oneOf`` is left to the discriminator-selecting caller so sibling contracts stay
    unprojected.

    ``wrappers_only`` narrows the collection to ``required`` rules that sit under an
    ``anyOf``/``allOf`` inside ``branch_schema_path``. Every location this collection yields is
    reported as ``conditional_field_required``, so a caller that has not proved the whole branch
    conditional on a matched discriminator must pass it: an unconditional payload ``required``
    would otherwise be labelled conditional and carry no repair sentence at all.
    """

    ordered: list[tuple[tuple[str | int, ...], str]] = []

    def consider(error: ValidationError) -> None:
        if len(ordered) >= _MAX_PROJECTED_OBJECT_LOCATIONS:
            return
        validator = error.validator
        if validator == "required":
            if wrappers_only and not _is_wrapped_required(error, branch_schema_path):
                return
            _append_missing_required(error, base_path, admitted, ordered)
            return
        if validator == "anyOf":
            for nested in error.context or ():
                consider(nested)
            return
        if validator == "allOf":
            for nested in error.context or ():
                consider(nested)

    for error in errors:
        consider(error)
        if len(ordered) >= _MAX_PROJECTED_OBJECT_LOCATIONS:
            break
    return ordered


_CONDITIONAL_SCHEMA_WRAPPERS: Final = frozenset({"anyOf", "allOf"})


def _is_wrapped_required(error: ValidationError, branch_schema_path: tuple[object, ...]) -> bool:
    """True when a ``required`` rule sits under an ``anyOf``/``allOf`` inside the given branch.

    ``$ref``-resolved payload rules arrive flat rather than nested under a wrapper error, so the
    schema location is what distinguishes ``allOf/0/then/required`` from the payload's own
    unconditional ``required``.
    """

    schema_path = tuple(error.absolute_schema_path)
    if schema_path[: len(branch_schema_path)] != branch_schema_path:
        return False
    return any(
        segment in _CONDITIONAL_SCHEMA_WRAPPERS
        for segment in schema_path[len(branch_schema_path) :]
    )


def _append_missing_required(
    error: ValidationError,
    base_path: tuple[str | int, ...],
    admitted: frozenset[str],
    ordered: list[tuple[tuple[str | int, ...], str]],
) -> None:
    validator_value = cast(object, error.validator_value)
    instance = error.instance
    if not isinstance(validator_value, list) or not isinstance(instance, Mapping):
        return
    object_path = _path_items_from(error)
    if object_path is None:
        object_path = base_path
    for item in cast(list[object], validator_value):
        required = _safe_schema_field(item, admitted)
        if required is None or required in instance:
            continue
        location = (object_path + (required,), _OBJECT_RULE_CONDITIONAL)
        if location not in ordered:
            ordered.append(location)
        if len(ordered) >= _MAX_PROJECTED_OBJECT_LOCATIONS:
            return


def _project_root_object_rule_locations_impl(
    exc: ValidationError,
) -> tuple[tuple[tuple[str | int, ...], str], ...]:
    path = _path_items_from(exc)
    if path is None or path != ():
        return ()
    validator = exc.validator
    if validator == "dependentRequired":
        return _project_dependent_required(exc)
    if validator in {"anyOf", "oneOf"}:
        return _project_conditional_required_alternatives(exc)
    # allOf itself rarely fails at root; nested context may hold the object rule.
    if validator == "allOf":
        for nested in exc.context or ():
            projected = _project_root_object_rule_locations_impl(nested)
            if projected:
                return projected
    return ()


def _project_dependent_required(
    error: ValidationError,
) -> tuple[tuple[tuple[str | int, ...], str], ...]:
    """Name the present field and its required peer from schema ``dependentRequired`` only."""

    deps = error.validator_value
    instance = error.instance
    if not isinstance(deps, Mapping) or not isinstance(instance, Mapping):
        return ()
    property_names = _schema_property_names(error.schema)
    if property_names is None:
        return ()
    ordered: list[tuple[tuple[str | int, ...], str]] = []
    seen: set[str] = set()
    for prop, peers in cast(Mapping[object, object], deps).items():
        present = _safe_schema_field(prop, property_names)
        if present is None or present not in cast(Mapping[object, object], instance):
            continue
        if not isinstance(peers, list):
            continue
        for peer in cast(list[object], peers):
            missing = _safe_schema_field(peer, property_names)
            if missing is None or missing in cast(Mapping[object, object], instance):
                continue
            for name in (present, missing):
                if name in seen:
                    continue
                seen.add(name)
                ordered.append(((name,), _OBJECT_RULE_PAIRED))
                if len(ordered) >= _MAX_PROJECTED_OBJECT_LOCATIONS:
                    return tuple(ordered)
    return tuple(ordered)


def _project_conditional_required_alternatives(
    error: ValidationError,
) -> tuple[tuple[tuple[str | int, ...], str], ...]:
    """Name safe required fields under a selected ``if/then`` anyOf|oneOf branch.

    Only when the schema path includes ``then`` (conditional branch) and context errors are
    ``required`` failures whose field names are checked-in properties.
    """

    schema_path = tuple(error.absolute_schema_path)
    if "then" not in schema_path and "if" not in schema_path:
        # Closed discriminated unions without if/then still admit required-field projection when
        # every context error is a schema-named required property.
        if error.validator not in {"anyOf", "oneOf"}:
            return ()
    property_names = _schema_property_names(error.schema)
    # Error.schema for anyOf is often the anyOf node (list of branches), not the root object.
    # Fall back to walking context validator_value lists and the parent schema when needed.
    ordered: list[tuple[tuple[str | int, ...], str]] = []
    seen: set[str] = set()
    for nested in error.context or ():
        if nested.validator != "required":
            continue
        required_list = nested.validator_value
        instance = nested.instance
        if not isinstance(required_list, list) or not isinstance(instance, Mapping):
            continue
        # Prefer property names from the enclosing object schema when available.
        nested_props = _schema_property_names(nested.schema)
        admitted = property_names if property_names is not None else nested_props
        # When the branch schema is only {"required": [...]}, admit names from the required list
        # only if each is a plain string — still never use instance keys as the source of names.
        for item in cast(list[object], required_list):
            if type(item) is not str:
                continue
            if admitted is not None and item not in admitted:
                # Branch-only required list: allow schema-authored required names even when the
                # branch node has no properties map (common for anyOf required alternatives).
                if nested_props is not None:
                    continue
            if item in cast(Mapping[object, object], instance):
                continue
            if item in seen:
                continue
            # Final gate: only emit names that look like schema identifiers already used as
            # locations elsewhere — still never take them from the instance.
            if not item or not item.isascii() or not item.replace("_", "").isalnum():
                continue
            seen.add(item)
            ordered.append(((item,), _OBJECT_RULE_CONDITIONAL))
            if len(ordered) >= _MAX_PROJECTED_OBJECT_LOCATIONS:
                return tuple(ordered)
    return tuple(ordered)


def _best_schema_instance_error(exc: ValidationError) -> ValidationError:
    """Prefer the deepest actionable nested failure under a ``oneOf``.

    Jsonschema reports a failed event-draft union at ``event_drafts/N``. The nested context
    already names the matching branch's payload field (for example ``action_kind``); surfacing
    that failure is what makes nested authoring hints possible without reading caller values.

    When the caller's own discriminator selects exactly one branch, only that branch is scored:
    every other branch failed on a const the caller never chose, so naming it hands back the value
    already sent (issue #240). Otherwise the whole tree is scored exactly as before.
    """

    selected = _discriminator_selected_branch(exc)
    best_error = exc
    best_path = _path_items_from(exc) or ()
    best_score = -1

    def score(error: ValidationError, path: tuple[str | int, ...]) -> int:
        points = len(path) * 10
        validator = error.validator
        if validator in {"enum", "const", "pattern"}:
            points += 100
        elif validator in {"type", "minLength", "maxLength", "minItems", "maxItems"}:
            points += 50
        elif validator == "required":
            points += 30
        elif validator == "additionalProperties":
            # An unknown key is noise across branches the caller never selected, and the most
            # specific fact known once the walk is confined to the branch it did select.
            points += 0 if selected is not None else -40
        elif validator == "oneOf":
            points -= 10
        if "payload" in path:
            points += 20
        return points

    def visit(error: ValidationError) -> None:
        nonlocal best_error, best_path, best_score
        path = _path_items_from(error)
        if path is not None:
            points = score(error, path)
            if points > best_score or (points == best_score and len(path) > len(best_path)):
                best_error = error
                best_score = points
                best_path = path
        selected_nested = _discriminator_selected_branch(error)
        for nested in selected_nested if selected_nested is not None else error.context or ():
            visit(nested)

    for root in selected if selected is not None else (exc,):
        visit(root)
    return best_error


_DISCRIMINATOR_TAILS: Final = (("schema", "name"), ("schema", "version"))
_MIN_DISCRIMINATED_BRANCHES: Final = 2


def _is_discriminator_rejection(error: ValidationError) -> bool:
    """True when a branch was ruled out by the family discriminator alone."""

    path = _path_items_from(error)
    if path is None:
        return False
    if error.validator == "const" and tuple(path[-2:]) in _DISCRIMINATOR_TAILS:
        return True
    # The catch-all branch admits only families the catalogue does not name, so it rejects a named
    # one through ``not`` on the same discriminator object rather than through a const.
    return error.validator == "not" and tuple(path[-1:]) == ("schema",)


def _discriminator_selected_branch(exc: ValidationError) -> tuple[ValidationError, ...] | None:
    """Return the failures of the one ``oneOf`` branch the caller's discriminator selected.

    Returns None when the union carries no per-branch const discriminator, or when zero or several
    branches survive it: the family itself is then wrong or ambiguous, and whole-tree scoring is
    the right answer.

    Known limitation, deliberate and unchanged from before issue #240: an extra key on the draft's
    ``schema`` object itself (rather than in the payload) leaves two symmetric survivors — the
    named family's branch and the catch-all — because neither is ruled out by a const the caller
    chose. Selection then returns None, whole-tree scoring picks the `schema/name` failure, and the
    caller is pointed at ``/event_drafts/N/schema/name`` for a defect that is really on the object
    beside it. The hint that answer carries still names every admitted family, so the report is
    imprecise rather than actively wrong, and no minimal fix exists that does not make branch
    selection guess between two equally live survivors.
    """

    if exc.validator != "oneOf":
        return None
    branches: dict[int, list[ValidationError]] = {}
    parent_schema_path = tuple(exc.absolute_schema_path)
    for nested in exc.context or ():
        schema_path = tuple(nested.absolute_schema_path)
        if (
            len(schema_path) <= len(parent_schema_path)
            or schema_path[: len(parent_schema_path)] != parent_schema_path
            or type(schema_path[len(parent_schema_path)]) is not int
        ):
            return None
        branches.setdefault(cast(int, schema_path[len(parent_schema_path)]), []).append(nested)
    if len(branches) < _MIN_DISCRIMINATED_BRANCHES:
        return None
    discriminated = 0
    survivors: list[list[ValidationError]] = []
    for errors in branches.values():
        rejections = [error for error in errors if _is_discriminator_rejection(error)]
        if not rejections:
            survivors.append(errors)
            continue
        if any(error.validator == "const" for error in rejections):
            discriminated += 1
    if discriminated >= _MIN_DISCRIMINATED_BRANCHES and len(survivors) == 1:
        return tuple(survivors[0])
    # Event-draft unions discriminate under schema.name, but payload contracts also use ordinary
    # top-level const properties such as evidence strength. Select those only when const failures
    # rule out every sibling but one; the selected branch then exposes its real required peer.
    for field in _const_discriminator_fields(exc, branches):
        selected = _const_discriminator_selected_branch(exc, branches, field=field)
        if selected is not None:
            return tuple(selected[1])
    return None


def _const_discriminator_selected_branch(
    exc: ValidationError,
    branches: Mapping[int, Sequence[ValidationError]],
    *,
    field: str,
) -> tuple[int, Sequence[ValidationError], str | None] | None:
    """Select one branch only when every other branch has a proven const rejection.

    Branches without a const for ``field`` are always survivors. Returning the selected const
    value separately lets required-peer projection name a condition only when the sole survivor
    actually declares one, while ordinary branch scoring can still select a const-free fallback.
    """

    validator_value = cast(object, exc.validator_value)
    if not isinstance(validator_value, list):
        return None
    options = cast(list[object], validator_value)
    const_values: dict[int, str] = {}
    rejected: set[int] = set()
    for index, errors in branches.items():
        if not 0 <= index < len(options):
            return None
        branch = options[index]
        if not isinstance(branch, Mapping):
            return None
        properties = cast(Mapping[str, JsonValue], branch).get("properties")
        condition = (
            cast(Mapping[str, JsonValue], properties).get(field)
            if isinstance(properties, Mapping)
            else None
        )
        value = (
            cast(Mapping[str, JsonValue], condition).get("const")
            if isinstance(condition, Mapping)
            else None
        )
        if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 64:
            continue
        const_values[index] = value
        if any(
            error.validator == "const" and tuple((_path_items_from(error) or ())[-1:]) == (field,)
            for error in errors
        ):
            rejected.add(index)
    survivors = [index for index in branches if index not in rejected]
    if (
        len(const_values) < _MIN_DISCRIMINATED_BRANCHES
        or len(rejected) < _MIN_DISCRIMINATED_BRANCHES
        or len(survivors) != 1
    ):
        return None
    selected_index = survivors[0]
    return selected_index, branches[selected_index], const_values.get(selected_index)


def _const_discriminator_fields(
    exc: ValidationError, branches: Mapping[int, Sequence[ValidationError]]
) -> tuple[str, ...]:
    """Return schema-authored root const fields shared by at least two ``oneOf`` branches."""

    validator_value = cast(object, exc.validator_value)
    if not isinstance(validator_value, list):
        return ()
    options = cast(list[object], validator_value)
    fields: set[str] = set()
    for index in branches:
        if not 0 <= index < len(options):
            return ()
        branch = options[index]
        if not isinstance(branch, Mapping):
            return ()
        properties = cast(Mapping[str, JsonValue], branch).get("properties")
        if not isinstance(properties, Mapping):
            continue
        for field, node in cast(Mapping[object, object], properties).items():
            if type(field) is not str or not isinstance(node, Mapping):
                continue
            value = cast(Mapping[str, JsonValue], node).get("const")
            if type(value) is str and value.isascii() and 1 <= len(value) <= 64:
                fields.add(field)
    return tuple(sorted(fields))


def _instance_reason_for(error: ValidationError) -> str | None:
    """Return the closed reason token for one instance failure, or None when it has no name."""

    if error.validator == "additionalProperties":
        return _INSTANCE_REASON_EXTRA_FORBIDDEN
    return None


def _unknown_property_count(error: ValidationError) -> int:
    """Count the instance keys the schema does not declare, bounded and without retaining one."""

    instance = error.instance
    schema = error.schema
    if not isinstance(instance, Mapping) or not isinstance(schema, Mapping):
        return 0
    properties = cast(Mapping[str, JsonValue], schema).get("properties")
    declared: set[object] = (
        set(cast(Mapping[object, object], properties)) if isinstance(properties, Mapping) else set()
    )
    unknown = {key for key in cast(Mapping[object, object], instance) if key not in declared}
    count = len(unknown)
    return count if count <= MAX_UNKNOWN_PROPERTY_COUNT else _UNKNOWN_PROPERTY_COUNT_OVERFLOW


def _event_payload_field_vocabulary() -> frozenset[str]:
    """Return every payload property name any catalogued event family declares.

    The vocabulary is frozen schema content read from the catalogue documents themselves, so
    membership in it is what makes naming a rejected key safe: a key outside it never travels.
    """

    state = _load_catalog_state()
    catalog = state.catalog
    names: set[str] = set()
    for schema_id, document in catalog.by_id.items():
        if document.schema_name.replace("-", "_") not in catalog.event_schema_versions:
            continue
        plain = state.plain_by_id.get(schema_id)
        if not isinstance(plain, Mapping):
            continue
        properties = cast(Mapping[str, JsonValue], plain).get("properties")
        if isinstance(properties, Mapping):
            names.update(
                key for key in cast(Mapping[object, object], properties) if type(key) is str
            )
    return frozenset(names)


def _event_draft_structural_property_names() -> frozenset[str]:
    """Return every property name the event-draft documents declare outside family payloads.

    A rejected payload key that the draft envelope itself admits (``evidence_refs``,
    ``artifact_refs``) is misplaced across levels, not across families, so naming another
    family's payload as its owner would send the caller the wrong way (issue #266).
    """

    state = _load_catalog_state()
    names: set[str] = set()

    def collect(node: JsonValue) -> None:
        if isinstance(node, Mapping):
            source = cast(Mapping[str, JsonValue], node)
            properties = source.get("properties")
            if isinstance(properties, Mapping):
                names.update(
                    key for key in cast(Mapping[object, object], properties) if type(key) is str
                )
            for value in source.values():
                collect(value)
        elif isinstance(node, list):
            for value in cast(list[JsonValue], node):
                collect(value)

    for schema_id, document in state.catalog.by_id.items():
        if not document.schema_name.endswith("event-draft"):
            continue
        plain = state.plain_by_id.get(schema_id)
        if plain is not None:
            # Family payloads are external ``$ref`` targets, so this walk only ever sees the
            # envelope and schema-identity properties the draft documents declare themselves.
            collect(plain)
    return frozenset(names)


def _misplaced_known_field(error: ValidationError) -> str | None:
    """Name the ASCII-first rejected key that some other catalogued family declares, or None.

    The rejected key names are caller-controlled and normally never leave the validator (issue
    #240). A key is admitted through this projection only when it byte-equals a payload property
    name declared by a catalogued event schema, so the token that travels is drawn from the frozen
    schema vocabulary — a caller-invented key can never match it. Keys the draft envelope itself
    declares are skipped: they are misplaced across levels, not families. Selection is
    deterministic: string keys are considered in ascending ASCII order (issue #266).
    """

    instance = error.instance
    schema = error.schema
    if not isinstance(instance, Mapping) or not isinstance(schema, Mapping):
        return None
    properties = cast(Mapping[str, JsonValue], schema).get("properties")
    declared: set[object] = (
        set(cast(Mapping[object, object], properties)) if isinstance(properties, Mapping) else set()
    )
    vocabulary = _event_payload_field_vocabulary() - _event_draft_structural_property_names()
    for key in sorted(key for key in cast(Mapping[object, object], instance) if type(key) is str):
        if key in declared or key not in vocabulary:
            continue
        if EVENT_FAMILY_NAME_PATTERN.fullmatch(key) is not None:
            return key
    return None


def _selected_family_for(error: ValidationError) -> tuple[str, str] | None:
    """Name the event family and version whose frozen payload schema rejected the instance.

    Both halves are read from the catalogue entry the failing schema's own ``$id`` identifies,
    never from the instance, so nothing caller-controlled can travel under either.

    The version travels with the name because a family may have several admitted versions
    (``evidence_recorded`` has 1.0.0, 1.1.0, and 1.2.0). A consumer that keys a per-family
    presentation
    branch on the name alone would answer a 1.1.0 failure with the 1.0.0 contract (issue #239).
    """

    schema = error.schema
    if not isinstance(schema, Mapping):
        return None
    schema_id = cast(Mapping[str, JsonValue], schema).get("$id")
    if type(schema_id) is not str:
        return None
    catalog = _load_catalog_state().catalog
    document = catalog.by_id.get(schema_id)
    if document is None:
        return None
    family = document.schema_name.replace("-", "_")
    if family not in catalog.event_schema_versions:
        return None
    version = document.schema_version
    return (family, version) if SCHEMA_VERSION_PATTERN.fullmatch(version) is not None else None
