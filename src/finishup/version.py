"""Installed resource integrity and version identity reporting."""

from __future__ import annotations

import hashlib
import importlib.metadata
import platform
import re
import sys
import sysconfig
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from types import MappingProxyType
from typing import Final, cast

from finishup.ports.diagnostics import (
    StartupCheckArea,
    StartupCheckOutcome,
    StartupCheckResult,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.policy_packs import (
    COORDINATION_POLICY_ID,
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    current_policy_pack,
)

__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "CATALOG_SCHEMA_VERSION",
    "CONTROL_PROTOCOL_VERSION",
    "CapabilitySet",
    "EGRESS_RECEIPT_SCHEMA_VERSION",
    "ENGINE_VERSION",
    "OBJECT_FORMAT_VERSION",
    "PRIVACY_CLASSIFIER_RULESET_VERSION",
    "PLATFORM_CELL_UNTESTED",
    "PRIVACY_POLICY_SCHEMA_VERSION",
    "PROJECTION_VERSION",
    "PROTOCOL_VERSION",
    "PlatformCell",
    "REVIEWED_RESOURCE_COUNT",
    "RESEARCH_EVIDENCE_POLICY_VERSION",
    "ResourceIdentity",
    "ResourceIntegrityError",
    "SQLITE_APPLICATION_ID",
    "STATUS_VERSION_STORAGE_SCHEMA",
    "StatusVersionSliceFacts",
    "UNAVAILABLE_RUNTIME_FACT",
    "VersionManifest",
    "WORK_INTEGRITY_POLICY_VERSION",
    "build_status_version_slice_facts",
    "build_version_manifest",
    "platform_cell",
    "read_verified_resource",
    "verify_resource_manifest",
    "version_manifest_json",
]

PROTOCOL_VERSION: Final = "0.1"
CONTROL_PROTOCOL_VERSION: Final = "1.0"
PRIVACY_POLICY_SCHEMA_VERSION: Final = "1.2.0"
EGRESS_RECEIPT_SCHEMA_VERSION: Final = "1.1.0"
PRIVACY_CLASSIFIER_RULESET_VERSION: Final = "privacy-classifier/0.1.0"
ENGINE_VERSION: Final = "0.1.0"
# Frozen legacy identifier (ADR-048): projection version stored in SQL CHECKs and events.
PROJECTION_VERSION: Final = "yoetz/0.1.0"
WORK_INTEGRITY_POLICY_VERSION: Final = current_policy_pack(WORK_INTEGRITY_POLICY_ID)
RESEARCH_EVIDENCE_POLICY_VERSION: Final = current_policy_pack(RESEARCH_EVIDENCE_POLICY_ID)
COORDINATION_POLICY_VERSION: Final = current_policy_pack(COORDINATION_POLICY_ID)
# Frozen legacy identifier (ADR-048): encryption format of every stored object.
OBJECT_FORMAT_VERSION: Final = "yoetz-object/1"
# Static identity on the status versions slice. Distinct from catalog/bundle schema counters
# and from live SQLite user_version. Not a probed runtime fact.
STATUS_VERSION_STORAGE_SCHEMA: Final = "1"
UNAVAILABLE_RUNTIME_FACT: Final = "unavailable"
# ADR-007's advertised platform matrix, as (platform.system(), platform.machine()) pairs. Any
# other cell the package happens to install on — Linux aarch64 (WSL 2 on Windows-on-ARM,
# Graviton, Raspberry Pi, Asahi), macOS x86-64, musl — is untested, not presumed compatible, and
# says so through the ``platform_cell_untested`` limitation (issue #724).
_CERTIFIED_PLATFORM_CELLS: Final[Mapping[tuple[str, str], str]] = MappingProxyType(
    {
        ("Darwin", "arm64"): "macosx_11_0_arm64",
        ("Linux", "x86_64"): "manylinux_2_28_x86_64",
        ("Linux", "amd64"): "manylinux_2_28_x86_64",
    }
)
# The release cell's exact interpreter, matching the CPython 3.14.6 claim in public-claims.json.
# ``requires-python`` admits 3.12 and 3.13, and uv may pick another 3.14 patch (issue #1119);
# CI runs the unit suites on several, but release evidence covers only this one.
_CERTIFIED_PYTHON: Final = ("CPython", (3, 14, 6))
PLATFORM_CELL_UNTESTED: Final = "platform_cell_untested"
_VERSION_WIRE_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,63}$")
_PROFILE_ID_WIRE_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
_ASCII_PRINTABLE_PATTERN: Final = re.compile(r"^[ -~]+$")
CATALOG_SCHEMA_VERSION: Final = "5"
BUNDLE_SCHEMA_VERSION: Final = "13"
# Frozen legacy identifier (ADR-048): SQLite application_id ("YOET") every open compares.
SQLITE_APPLICATION_ID: Final = "0x594F4554"

# Frozen legacy identifier (ADR-048): resource and runtime-support format tags, kept in
# lockstep with scripts/verify_resource_manifest.py and the codex skill manifest reader.
_MANIFEST_SCHEMA: Final = "yoetz.resource-manifest/1"
_SUPPORT_SCHEMA: Final = "yoetz.runtime-support/1"
_RESOURCE_ROOT: Final = "finishup.resources"
_MANIFEST_LIMIT: Final = 1_048_576
_RESOURCE_LIMIT: Final = 4_194_304
# One independently reviewed cardinality tripwire guards the generated resource manifest. All
# per-kind counts are derived from the manifest entries so adding a resource has exactly one
# hand-authored count to review and the owning resource-ripple command can regenerate the rest.
# 306 + 3: the publish-action-notices canonical vector (was unpackaged), the review-packet-row
# 2.0.0 provider contract, and its golden-vector case; +1: the advice egress/category-denial
# canonical vector (#1019). ADR-049: +1 schema decision-recorded 1.1.0, +1 canonical
# review-mode vectors (CAN-020). n6 item 4: +2 schemas (check-result 1.5.0,
# check-recorded 1.5.0) and +1 canonical deferred-before-first-edit case (CAN-021). #1084: +1
# canonical server-filled publish and brief status vectors (CAN-022). W6 #1107: +1 canonical
# check agent_next vectors (AGN-001), +1 status check_outcome vector (AGN-002). #1118 unit 2: +1
# reviewer-reply 1.0.0 schema. #1118: +2 schemas (check-result 1.6.0, check-recorded 1.6.0) and
# +1 canonical reviewer-record case (REV-001). #1122/#1123: +2 schemas (host-connection-batch
# 1.0.0, ai-status 1.0.0) and +1 canonical host-connection-batch case. #1118: +1 runtime config
# (the reviewer's derived Codex 0.162.1 model catalog).
REVIEWED_RESOURCE_COUNT: Final = 327
_RESOURCE_KINDS: Final = frozenset(
    {
        "canonical_vector",
        "compatibility_manifest",
        "guidance",
        "json_schema",
        "migration",
        "runtime_support",
        "runtime_config",
        "skill",
    }
)
_REQUEST_RESULT_VERSIONS: Final = (
    ("actor-assertion", "1.0.0"),
    ("ai-status", "1.0.0"),
    ("catalog", "7.0.0"),
    ("chat-user-attestation", "1.0.0"),
    ("check-request", "1.1.0"),
    ("check-result", "1.6.0"),
    ("closure-prepare-request", "1.0.0"),
    ("closure-prepare-result", "1.0.0"),
    ("client-info", "1.0.0"),
    ("control-hello", "2.9.0"),
    ("control-hello-result", "2.9.0"),
    ("control-request", "2.9.0"),
    ("control-result", "2.9.0"),
    ("coverage", "1.0.0"),
    ("egress-receipt", "1.1.0"),
    ("finding", "1.4.0"),
    ("frontier", "1.0.0"),
    ("lineage-acceptance", "1.0.0"),
    ("lineage-origin", "1.0.0"),
    ("host-connection", "1.0.0"),
    ("host-connection-batch", "1.0.0"),
    ("mcp-removal", "1.0.0"),
    ("isolation-report", "1.0.0"),
    ("operation-result", "1.0.0"),
    ("outbound-case", "1.2.0"),
    ("pending-agent", "7.0.0"),
    ("prepare-result", "7.0.0"),
    ("privacy-policy", "1.2.0"),
    ("provider-judgment", "1.2.0"),
    ("public-error", "1.0.0"),
    ("publish-work-request", "1.2.0"),
    ("publish-work-result", "1.1.0"),
    ("read-guidance-request", "1.1.0"),
    ("read-guidance-result", "1.1.0"),
    ("receipt-document", "1.3.0"),
    ("receipt-request", "1.0.0"),
    ("receipt-result", "1.3.0"),
    ("respond-request", "1.1.0"),
    ("respond-result", "1.1.0"),
    ("review-packet-row", "2.0.0"),
    ("review-result", "7.0.0"),
    ("reviewer-reply", "1.0.0"),
    ("routine-read-summary", "1.0.0"),
    ("runtime-attempt-evidence", "1.1.0"),
    ("semantic-provenance", "1.2.0"),
    ("service-status", "1.0.0"),
    ("session-health", "1.0.0"),
    ("setup-readiness", "1.0.0"),
    ("setup-status", "2.0.0"),
    ("setup-wizard-contract", "1.0.0"),
    ("start-request", "1.1.0"),
    ("start-result", "1.1.0"),
    ("status", "7.0.0"),
    ("status-request", "1.2.0"),
    ("status-result", "1.4.0"),
    ("subject-state-ref", "1.0.0"),
    ("work-state", "1.0.0"),
)
_EVENT_NAMES: Final = (
    "action_recorded",
    "assignment_recorded",
    "check_recorded",
    "child_accepted",
    "child_dependencies_recorded",
    "child_rejected",
    "child_written_off",
    "claim_recorded",
    "coordination_context_recorded",
    "coordination_disposition_recorded",
    "coordination_obligation_declared",
    "decision_recorded",
    "delegation_cancelled",
    "delegation_declared",
    "evidence_recorded",
    "finding_recorded",
    "obligation_published",
    "plan_published",
    "plan_revised",
    "receipt_recorded",
    "redaction_recorded",
    "response_recorded",
    "result_recorded",
    "session_opened",
    "session_resumed",
    "work_abandoned",
    "work_cancelled",
    "work_closed",
    "work_written_off",
)
_EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


class ResourceIntegrityError(ValueError):
    """A required installed resource failed a bounded integrity check."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ResourceIdentity:
    name: str
    media_type: str
    size_bytes: int
    sha256_digest: str

    def __post_init__(self) -> None:
        if (
            not self.name
            or self.name.startswith(("/", "."))
            or "\\" in self.name
            or any(part in {"", ".", ".."} for part in self.name.split("/"))
        ):
            raise ValueError("resource_name_invalid")
        if "/" not in self.media_type or self.media_type.lower() != self.media_type:
            raise ValueError("resource_media_type_invalid")
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= _RESOURCE_LIMIT:
            raise ValueError("resource_size_invalid")
        _validate_digest(self.sha256_digest)


@dataclass(frozen=True, slots=True)
class CapabilitySet:
    name: str
    supported_versions: tuple[str, ...]
    tested_versions: tuple[str, ...]
    denied_versions: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("capability_name_invalid")
        for values in (
            self.supported_versions,
            self.tested_versions,
            self.denied_versions,
        ):
            if values != tuple(sorted(set(values), key=str.encode)):
                raise ValueError("capability_versions_invalid")


type Component = Mapping[str, str]
type VersionPairs = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class VersionManifest:
    schema_version: str
    package_name: str
    package_version: str
    protocol_version: str
    engine_version: str
    projection_version: str
    control_protocol_version: str
    privacy_policy_schema_version: str
    egress_receipt_schema_version: str
    privacy_classifier_ruleset_version: str
    request_result_schema_versions: VersionPairs
    event_schema_versions: VersionPairs
    policy_versions: tuple[str, ...]
    object_format_version: str
    catalog_schema_version: str
    bundle_schema_version: str
    application_id: str
    python_implementation: str
    python_version: str
    python_abi: str
    os_name: str
    os_version: str
    machine: str
    platform_tag: str
    apsw_version: Component
    sqlite_version: Component
    sqlite_source_id: Component
    sqlite_compile_options_digest: Component
    mcp_sdk_version: Component
    mcp_protocol_supported: tuple[str, ...]
    provider_adapters: tuple[Mapping[str, str], ...]
    service_capabilities: tuple[CapabilitySet, ...]
    codex_capability_profiles: tuple[Mapping[str, JsonValue], ...]
    subject_state_capabilities: Mapping[str, JsonValue]
    resource_manifest_digest: str
    resource_counts: VersionPairs
    resources: tuple[ResourceIdentity, ...]
    build_identity: str
    support_status: str
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PlatformCell:
    """The host's (OS, architecture, CPython minor) cell against ADR-007's advertised matrix.

    ``python_version`` names the interpreter (``3.14.6``, or ``PyPy 3.14.6``); it is not part of
    the wire shape.
    """

    os_name: str
    machine: str
    certified: bool
    cell: str | None
    python_version: str = ".".join(str(part) for part in _CERTIFIED_PYTHON[1])

    def as_json(self) -> dict[str, JsonValue]:
        certified_cells: list[JsonValue] = [
            cell for cell in sorted(set(_CERTIFIED_PLATFORM_CELLS.values()))
        ]
        return {
            "cell": self.cell,
            "certified": self.certified,
            "certified_cells": certified_cells,
            "machine": self.machine,
            "os_name": self.os_name,
        }


def platform_cell(
    *,
    os_name: str | None = None,
    machine: str | None = None,
    libc: tuple[str, str] | None = None,
    python: tuple[int, int, int] | None = None,
    implementation: str | None = None,
) -> PlatformCell:
    """Classify this host (or the given one) as a certified or an untested platform cell."""

    resolved_os = (platform.system() or sys.platform) if os_name is None else os_name
    resolved_machine = (platform.machine() or "unknown") if machine is None else machine
    resolved_python = (
        (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
        if python is None
        else python
    )
    resolved_implementation = (
        platform.python_implementation() if implementation is None else implementation
    )
    cell = _CERTIFIED_PLATFORM_CELLS.get((resolved_os, resolved_machine))
    if (resolved_implementation, resolved_python) != _CERTIFIED_PYTHON:
        cell = None
    if cell is not None and resolved_os == "Linux":
        libc_name, libc_version = platform.libc_ver() if libc is None else libc
        match = re.fullmatch(r"([0-9]+)\.([0-9]+)(?:\.[0-9]+)*", libc_version)
        if (
            libc_name != "glibc"
            or match is None
            or tuple(int(part) for part in match.group(1, 2)) < (2, 28)
        ):
            cell = None
    return PlatformCell(
        os_name=resolved_os,
        machine=resolved_machine,
        certified=cell is not None,
        cell=cell,
        python_version=(
            ("" if resolved_implementation == "CPython" else f"{resolved_implementation} ")
            + ".".join(str(part) for part in resolved_python)
        ),
    )


@dataclass(frozen=True, slots=True)
class StatusVersionSliceFacts:
    """Live and static facts for MCP/CLI ``status view=versions``.

    Runtime-probed values come from the same producer as ``version --json``.
    Contract identities are package constants. ``provider_profiles`` is the
    packaged support-catalog inventory, not live AI-powered evaluator presence.
    """

    protocol_version: str
    engine_version: str
    projection_version: str
    object_format: str
    storage_schema: str
    python_version: str
    apsw_version: str
    sqlite_version: str
    sqlite_source_id: str
    policy_packs: tuple[str, ...]
    provider_profiles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ResourceEntry:
    logical_name: str
    source_path: str
    package_path: str
    kind: str
    media_type: str
    size: int
    sha256: str
    contract_version: str | None

    def identity(self) -> ResourceIdentity:
        return ResourceIdentity(self.logical_name, self.media_type, self.size, self.sha256)

    def stable_json(self) -> Mapping[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "kind": self.kind,
            "logical_name": self.logical_name,
            "media_type": self.media_type,
            "package_path": self.package_path,
            "source_path": self.source_path,
        }
        if self.kind != "runtime_support":
            result["sha256"] = self.sha256
            result["size"] = self.size
        if self.contract_version is not None:
            result["contract_version"] = self.contract_version
        return result


@dataclass(frozen=True, slots=True)
class _ResourceManifest:
    resource_set_version: str
    resource_set_digest: str
    entries: tuple[_ResourceEntry, ...]


def _validate_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ResourceIntegrityError("digest_invalid")
    return value


def _mapping(value: object, reason: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ResourceIntegrityError(reason)
    return cast(Mapping[str, JsonValue], value)


def _canonical_document(raw: bytes, *, limit: int, reason: str) -> Mapping[str, JsonValue]:
    if len(raw) > limit or not raw.endswith(b"\n") or b"\r" in raw:
        raise ResourceIntegrityError(reason)
    try:
        parsed = _mapping(strict_json_parse(raw), reason)
    except (ProtocolValueError, UnicodeError) as exc:
        raise ResourceIntegrityError(reason) from exc
    if raw != canonical_encode(parsed) + b"\n":
        raise ResourceIntegrityError(reason)
    return parsed


def _package_bytes(package_path: str) -> bytes:
    if (
        not package_path
        or package_path.startswith(("/", "."))
        or "\\" in package_path
        or any(part in {"", ".", ".."} for part in package_path.split("/"))
    ):
        raise ResourceIntegrityError("resource_path_invalid")
    node = resources.files(_RESOURCE_ROOT)
    for part in package_path.split("/"):
        node = node.joinpath(part)
    try:
        raw = node.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise ResourceIntegrityError("resource_missing") from exc
    if len(raw) > _RESOURCE_LIMIT:
        raise ResourceIntegrityError("resource_too_large")
    return raw


def _entry_from_json(value: JsonValue) -> _ResourceEntry:
    entry = _mapping(value, "resource_entry_invalid")
    allowed = {
        "contract_version",
        "kind",
        "logical_name",
        "media_type",
        "package_path",
        "sha256",
        "size",
        "source_path",
    }
    if not set(entry) <= allowed or set(entry) - {"contract_version"} != allowed - {
        "contract_version"
    }:
        raise ResourceIntegrityError("resource_entry_invalid")
    logical_name = entry["logical_name"]
    source_path = entry["source_path"]
    package_path = entry["package_path"]
    kind = entry["kind"]
    media_type = entry["media_type"]
    size = entry["size"]
    digest = entry["sha256"]
    contract_version = entry.get("contract_version")
    if (
        type(logical_name) is not str
        or type(source_path) is not str
        or type(package_path) is not str
        or type(kind) is not str
        or kind not in _RESOURCE_KINDS
        or type(media_type) is not str
        or type(size) is not int
        or type(digest) is not str
        or (contract_version is not None and type(contract_version) is not str)
    ):
        raise ResourceIntegrityError("resource_entry_invalid")
    identity = ResourceIdentity(logical_name, media_type, size, digest)
    if package_path != logical_name:
        raise ResourceIntegrityError("resource_path_mapping_invalid")
    for candidate in (source_path, package_path):
        if (
            candidate.startswith(("/", "."))
            or "\\" in candidate
            or any(part in {"", ".", ".."} for part in candidate.split("/"))
        ):
            raise ResourceIntegrityError("resource_path_invalid")
    return _ResourceEntry(
        identity.name,
        source_path,
        package_path,
        kind,
        identity.media_type,
        identity.size_bytes,
        identity.sha256_digest,
        contract_version,
    )


def _load_resource_manifest() -> _ResourceManifest:
    raw = _package_bytes("manifest.json")
    manifest = _canonical_document(raw, limit=_MANIFEST_LIMIT, reason="manifest_invalid")
    if set(manifest) != {
        "entries",
        "package",
        "resource_set_digest",
        "resource_set_version",
        "schema",
    }:
        raise ResourceIntegrityError("manifest_shape_invalid")
    if manifest["schema"] != _MANIFEST_SCHEMA or manifest["package"] != "finishup":
        raise ResourceIntegrityError("manifest_identity_invalid")
    version = manifest["resource_set_version"]
    digest = manifest["resource_set_digest"]
    raw_entries = manifest["entries"]
    if type(version) is not str or type(raw_entries) is not list:
        raise ResourceIntegrityError("manifest_shape_invalid")
    entries = tuple(_entry_from_json(item) for item in raw_entries)
    names = tuple(entry.logical_name for entry in entries)
    if (
        len(entries) != REVIEWED_RESOURCE_COUNT
        or names != tuple(sorted(set(names), key=str.encode))
        or len({entry.package_path for entry in entries}) != len(entries)
        or sum(entry.kind == "runtime_support" for entry in entries) != 1
    ):
        raise ResourceIntegrityError("manifest_inventory_invalid")
    stable: Mapping[str, JsonValue] = {
        "entries": [entry.stable_json() for entry in entries],
        "package": "finishup",
        "resource_set_version": version,
        "schema": _MANIFEST_SCHEMA,
    }
    if _validate_digest(digest) != canonical_digest(stable):
        raise ResourceIntegrityError("manifest_digest_mismatch")
    return _ResourceManifest(version, cast(str, digest), entries)


def read_verified_resource(logical_name: str) -> bytes:
    """Read one exact installed resource after closed-manifest size/digest verification."""

    if type(logical_name) is not str:
        raise ResourceIntegrityError("resource_name_invalid")
    manifest = _load_resource_manifest()
    entry = next((item for item in manifest.entries if item.logical_name == logical_name), None)
    if entry is None:
        raise ResourceIntegrityError("resource_unknown")
    raw = _package_bytes(entry.package_path)
    if len(raw) != entry.size or f"sha256:{hashlib.sha256(raw).hexdigest()}" != entry.sha256:
        raise ResourceIntegrityError("resource_digest_mismatch")
    return raw


def _load_support(manifest: _ResourceManifest) -> Mapping[str, JsonValue]:
    raw = read_verified_resource("support/runtime-support.json")
    support = _canonical_document(raw, limit=_MANIFEST_LIMIT, reason="support_invalid")
    required = {
        "capability_matrix",
        "codex_profiles",
        "denied_cells",
        "dependency_lock",
        "key_backend_cells",
        "limitations",
        "local_service_cells",
        "manifest_digest",
        "manifest_version",
        "mcp_cells",
        "package_artifact",
        "privacy_enforcement_cells",
        "provider_profiles",
        "release_evidence",
        "release_version",
        "resource_set_digest",
        "runtime_cells",
        "schema",
        "secret_memory_cells",
        "session_event_cells",
        "subject_state_cells",
        "user_presence_cells",
    }
    if set(support) != required or support["schema"] != _SUPPORT_SCHEMA:
        raise ResourceIntegrityError("support_shape_invalid")
    digest = support["manifest_digest"]
    without_digest = {key: value for key, value in support.items() if key != "manifest_digest"}
    if _validate_digest(digest) != canonical_digest(without_digest):
        raise ResourceIntegrityError("support_digest_mismatch")
    if support["resource_set_digest"] != manifest.resource_set_digest:
        raise ResourceIntegrityError("support_resource_set_mismatch")
    _validate_support_reference(support["package_artifact"], allow_digest=False)
    _validate_support_reference(support["capability_matrix"], allow_digest=True)
    _validate_support_reference(support["release_evidence"], allow_digest=True)
    _validate_support_reference(support["dependency_lock"], allow_digest=True)
    for key in required & {
        "codex_profiles",
        "denied_cells",
        "key_backend_cells",
        "limitations",
        "local_service_cells",
        "mcp_cells",
        "privacy_enforcement_cells",
        "provider_profiles",
        "runtime_cells",
        "secret_memory_cells",
        "session_event_cells",
        "subject_state_cells",
        "user_presence_cells",
    }:
        if type(support[key]) is not list:
            raise ResourceIntegrityError("support_shape_invalid")
    return support


def _validate_support_reference(value: JsonValue, *, allow_digest: bool) -> None:
    reference = _mapping(value, "support_reference_invalid")
    status = reference.get("status")
    if status == "absent":
        if set(reference) != {"reason_code", "status"} or type(reference["reason_code"]) is not str:
            raise ResourceIntegrityError("support_reference_invalid")
        return
    if status == "external":
        if set(reference) == {"status"}:
            return
        if allow_digest and set(reference) == {"digest", "status"}:
            _validate_digest(reference["digest"])
            return
    raise ResourceIntegrityError("support_reference_invalid")


def _component(*, value: str | None, field: str) -> Component:
    if value is None:
        return MappingProxyType({"status": "absent"})
    return MappingProxyType({"status": "present", field: value})


def _wire_version(value: str) -> str:
    if type(value) is not str or _VERSION_WIRE_PATTERN.fullmatch(value) is None:
        return UNAVAILABLE_RUNTIME_FACT
    return value


def _wire_component(
    component: Component,
    *,
    field: str,
    max_length: int,
    ascii_printable: bool = False,
) -> str:
    if component.get("status") != "present":
        return UNAVAILABLE_RUNTIME_FACT
    value = component.get(field)
    if type(value) is not str or not value or len(value) > max_length:
        return UNAVAILABLE_RUNTIME_FACT
    if ascii_printable:
        if _ASCII_PRINTABLE_PATTERN.fullmatch(value) is None:
            return UNAVAILABLE_RUNTIME_FACT
        return value
    return _wire_version(value)


def _support_provider_profile_ids(raw: JsonValue) -> tuple[str, ...]:
    if type(raw) is not list:
        raise ResourceIntegrityError("support_shape_invalid")
    profiles: list[str] = []
    for item in raw:
        if (
            type(item) is not str
            or len(item) > 128
            or _PROFILE_ID_WIRE_PATTERN.fullmatch(item) is None
        ):
            raise ResourceIntegrityError("support_shape_invalid")
        profiles.append(item)
    ordered = tuple(sorted(set(profiles), key=str.encode))
    if len(ordered) > 16:
        raise ResourceIntegrityError("support_shape_invalid")
    return ordered


def _distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _runtime_components() -> tuple[Component, Component, Component, Component]:
    try:
        import apsw
    except ImportError:
        absent = _component(value=None, field="version")
        return (
            absent,
            absent,
            _component(value=None, field="source_id"),
            _component(value=None, field="digest"),
        )
    options = tuple(sorted(apsw.compile_options, key=str.encode))
    return (
        _component(value=apsw.apsw_version(), field="version"),
        _component(value=apsw.sqlitelibversion(), field="version"),
        _component(value=apsw.sqlite3_sourceid(), field="source_id"),
        _component(value=canonical_digest(options), field="digest"),
    )


def _provider_adapters() -> tuple[Mapping[str, str], ...]:
    sdk_version = _distribution_version("openai")
    if sdk_version is None:
        return (MappingProxyType({"name": "openai", "status": "absent"}),)
    return (
        MappingProxyType(
            {
                "adapter_version": "openai-adapter/0.1.0",
                "name": "openai",
                "sdk_distribution": "openai",
                "sdk_version": sdk_version,
                "status": "present",
            }
        ),
    )


def _resource_counts(entries: tuple[_ResourceEntry, ...]) -> VersionPairs:
    counts = {
        "canonical_vectors": sum(item.kind == "canonical_vector" for item in entries),
        "guidance_resources": sum(item.kind == "guidance" for item in entries),
        "migrations": sum(item.kind == "migration" for item in entries),
        "runtime_support_resources": sum(item.kind == "runtime_support" for item in entries),
        "runtime_config_resources": sum(item.kind == "runtime_config" for item in entries),
        "schema_resources": sum(item.kind == "json_schema" for item in entries),
        "skill_resources": sum(
            item.kind in {"compatibility_manifest", "skill"} for item in entries
        ),
        "total": len(entries),
    }
    categorized_total = sum(count for name, count in counts.items() if name != "total")
    if counts["total"] != REVIEWED_RESOURCE_COUNT or categorized_total != counts["total"]:
        raise ResourceIntegrityError("resource_counts_invalid")
    return tuple((name, str(counts[name])) for name in sorted(counts, key=str.encode))


def build_version_manifest(*, include_optional_probes: bool = False) -> VersionManifest:
    """Build the deterministic installed manifest without network, config, or storage access."""

    if type(include_optional_probes) is not bool:
        raise TypeError("include_optional_probes_must_be_bool")
    manifest = _load_resource_manifest()
    support = _load_support(manifest)
    apsw_version, sqlite_version, sqlite_source_id, compile_digest = _runtime_components()
    mcp_version = _distribution_version("mcp")
    limitations = tuple(cast(list[str], support["limitations"]))
    if mcp_version is not None and not cast(list[JsonValue], support["mcp_cells"]):
        limitations = tuple(sorted({*limitations, "mcp_capability_unverified"}, key=str.encode))
    if not platform_cell().certified:
        limitations = tuple(sorted({*limitations, PLATFORM_CELL_UNTESTED}, key=str.encode))
    return VersionManifest(
        schema_version="2.3.0",
        package_name="finishup",
        package_version=_distribution_version("finishup") or "0.1.0",
        protocol_version=PROTOCOL_VERSION,
        engine_version=ENGINE_VERSION,
        projection_version=PROJECTION_VERSION,
        control_protocol_version=CONTROL_PROTOCOL_VERSION,
        privacy_policy_schema_version=PRIVACY_POLICY_SCHEMA_VERSION,
        egress_receipt_schema_version=EGRESS_RECEIPT_SCHEMA_VERSION,
        privacy_classifier_ruleset_version=PRIVACY_CLASSIFIER_RULESET_VERSION,
        request_result_schema_versions=_REQUEST_RESULT_VERSIONS,
        event_schema_versions=tuple(
            (
                name,
                "1.6.0"
                if name == "check_recorded"
                else "1.4.0"
                if name == "finding_recorded"
                else "1.2.0"
                if name in {"evidence_recorded", "session_opened", "session_resumed"}
                else "1.1.0"
                if name
                in {
                    "claim_recorded",
                    "decision_recorded",
                    "obligation_published",
                    "plan_published",
                    "plan_revised",
                    "response_recorded",
                    "session_opened",
                    "session_resumed",
                }
                else "1.0.0",
            )
            for name in _EVENT_NAMES
        ),
        policy_versions=(
            COORDINATION_POLICY_VERSION,
            RESEARCH_EVIDENCE_POLICY_VERSION,
            WORK_INTEGRITY_POLICY_VERSION,
        ),
        object_format_version=OBJECT_FORMAT_VERSION,
        catalog_schema_version=CATALOG_SCHEMA_VERSION,
        bundle_schema_version=BUNDLE_SCHEMA_VERSION,
        application_id=SQLITE_APPLICATION_ID,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        python_abi=str(sysconfig.get_config_var("SOABI") or "unknown"),
        os_name=platform.system() or sys.platform,
        os_version=platform.release() or "unknown",
        machine=platform.machine() or "unknown",
        platform_tag=sysconfig.get_platform().replace("-", "_"),
        apsw_version=apsw_version,
        sqlite_version=sqlite_version,
        sqlite_source_id=sqlite_source_id,
        sqlite_compile_options_digest=compile_digest,
        mcp_sdk_version=_component(value=mcp_version, field="version"),
        mcp_protocol_supported=(),
        provider_adapters=_provider_adapters(),
        service_capabilities=(),
        codex_capability_profiles=_codex_capability_profiles(),
        subject_state_capabilities=MappingProxyType({"status": "absent"}),
        resource_manifest_digest=manifest.resource_set_digest,
        resource_counts=_resource_counts(manifest.entries),
        resources=tuple(entry.identity() for entry in manifest.entries),
        build_identity="development-unavailable",
        support_status="development_unverified",
        limitations=limitations,
    )


def build_status_version_slice_facts(
    *, manifest: VersionManifest | None = None
) -> StatusVersionSliceFacts:
    """Project ``version --json`` runtime facts onto the status versions slice."""

    resolved = build_version_manifest() if manifest is None else manifest
    if type(resolved) is not VersionManifest:
        raise TypeError("manifest_must_be_version_manifest")
    support = _load_support(_load_resource_manifest())
    return StatusVersionSliceFacts(
        protocol_version=PROTOCOL_VERSION,
        engine_version=ENGINE_VERSION,
        projection_version=PROJECTION_VERSION,
        object_format=OBJECT_FORMAT_VERSION,
        storage_schema=STATUS_VERSION_STORAGE_SCHEMA,
        python_version=_wire_version(resolved.python_version),
        apsw_version=_wire_component(resolved.apsw_version, field="version", max_length=64),
        sqlite_version=_wire_component(resolved.sqlite_version, field="version", max_length=64),
        sqlite_source_id=_wire_component(
            resolved.sqlite_source_id,
            field="source_id",
            max_length=160,
            ascii_printable=True,
        ),
        policy_packs=(RESEARCH_EVIDENCE_POLICY_VERSION, WORK_INTEGRITY_POLICY_VERSION),
        provider_profiles=_support_provider_profile_ids(support["provider_profiles"]),
    )


def _codex_capability_profiles() -> tuple[Mapping[str, JsonValue], ...]:
    from finishup.adapters.integrations.codex_capability_cells import (
        codex_version_manifest_profiles,
    )

    return codex_version_manifest_profiles()


def _component_json(value: Mapping[str, str]) -> Mapping[str, JsonValue]:
    return dict(value)


def _manifest_json(
    manifest: VersionManifest, *, include_resources: bool
) -> Mapping[str, JsonValue]:
    if type(manifest) is not VersionManifest:
        raise TypeError("manifest_must_be_version_manifest")
    resources_json: list[JsonValue] = []
    if include_resources:
        resources_json = [
            {
                "media_type": item.media_type,
                "name": item.name,
                "sha256_digest": item.sha256_digest,
                "size_bytes": str(item.size_bytes),
            }
            for item in manifest.resources
        ]
    return {
        "application_id": manifest.application_id,
        "apsw_version": _component_json(manifest.apsw_version),
        "build_identity": manifest.build_identity,
        "bundle_schema_version": manifest.bundle_schema_version,
        "catalog_schema_version": manifest.catalog_schema_version,
        "codex_capability_profiles": [dict(item) for item in manifest.codex_capability_profiles],
        "control_protocol_version": manifest.control_protocol_version,
        "egress_receipt_schema_version": manifest.egress_receipt_schema_version,
        "engine_version": manifest.engine_version,
        "event_schema_versions": dict(manifest.event_schema_versions),
        "limitations": list(manifest.limitations),
        "machine": manifest.machine,
        "mcp_protocol_supported": list(manifest.mcp_protocol_supported),
        "mcp_sdk_version": _component_json(manifest.mcp_sdk_version),
        "object_format_version": manifest.object_format_version,
        "os_name": manifest.os_name,
        "os_version": manifest.os_version,
        "package_name": manifest.package_name,
        "package_version": manifest.package_version,
        "platform_tag": manifest.platform_tag,
        "policy_versions": list(manifest.policy_versions),
        "privacy_classifier_ruleset_version": manifest.privacy_classifier_ruleset_version,
        "privacy_policy_schema_version": manifest.privacy_policy_schema_version,
        "projection_version": manifest.projection_version,
        "protocol_version": manifest.protocol_version,
        "provider_adapters": [dict(item) for item in manifest.provider_adapters],
        "python_abi": manifest.python_abi,
        "python_implementation": manifest.python_implementation,
        "python_version": manifest.python_version,
        "request_result_schema_versions": dict(manifest.request_result_schema_versions),
        "resource_counts": dict(manifest.resource_counts),
        "resource_manifest_digest": manifest.resource_manifest_digest,
        "resources": resources_json,
        "schema_version": manifest.schema_version,
        "service_capabilities": [
            {
                "denied_versions": list(item.denied_versions),
                "name": item.name,
                "supported_versions": list(item.supported_versions),
                "tested_versions": list(item.tested_versions),
            }
            for item in manifest.service_capabilities
        ],
        "sqlite_compile_options_digest": _component_json(manifest.sqlite_compile_options_digest),
        "sqlite_source_id": _component_json(manifest.sqlite_source_id),
        "sqlite_version": _component_json(manifest.sqlite_version),
        "subject_state_capabilities": dict(manifest.subject_state_capabilities),
        "support_status": manifest.support_status,
    }


def version_manifest_json(manifest: VersionManifest, *, include_resources: bool = False) -> bytes:
    """Render canonical protocol JSON bytes without a transport newline."""

    if type(include_resources) is not bool:
        raise TypeError("include_resources_must_be_bool")
    return canonical_encode(_manifest_json(manifest, include_resources=include_resources))


def verify_resource_manifest(manifest: VersionManifest) -> tuple[StartupCheckResult, ...]:
    """Verify every installed resource and return one bounded startup diagnostic."""

    try:
        installed = _load_resource_manifest()
        expected = tuple(entry.identity() for entry in installed.entries)
        if (
            manifest.resources != expected
            or manifest.resource_manifest_digest != installed.resource_set_digest
        ):
            raise ResourceIntegrityError("version_resource_identity_mismatch")
        for entry in installed.entries:
            read_verified_resource(entry.logical_name)
    except (ResourceIntegrityError, OSError, ValueError):
        return (
            StartupCheckResult(
                "resources.manifest",
                StartupCheckArea.RESOURCES,
                StartupCheckOutcome.BLOCKED,
                "resource_integrity_failed",
                frozenset(),
                {},
                _EPOCH,
            ),
        )
    return (
        StartupCheckResult(
            "resources.manifest",
            StartupCheckArea.RESOURCES,
            StartupCheckOutcome.OK,
            None,
            frozenset(),
            {
                "resource_count": len(installed.entries),
                "resource_set_digest": installed.resource_set_digest,
            },
            _EPOCH,
        ),
    )
