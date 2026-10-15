"""Harness-neutral trusted-project guidance integration boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast

from yoetz.domain.values import JsonObject, JsonValue, RequestId, request_id, validate_sha256_digest
from yoetz.domain.yoetz_tools import (
    YOETZ_MCP_TOOL_NAMES,
    YOETZ_SUPPORT_TOOL_NAMES,
    YOETZ_WORKFLOW_TOOL_NAMES,
)
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.errors import PROTOCOL_REASON_CODES, ProtocolValueError

__all__ = [
    "YOETZ_MCP_TOOL_NAMES",
    "YOETZ_SUPPORT_TOOL_NAMES",
    "YOETZ_WORKFLOW_TOOL_NAMES",
    "HookCorrelationKind",
    "HookPairingMode",
    "HarnessHookProfile",
    "HarnessId",
    "HarnessProfile",
    "IntegrationAction",
    "IntegrationError",
    "IntegrationFile",
    "IntegrationPreview",
    "IntegrationReason",
    "IntegrationResult",
    "IntegrationScope",
    "IntegrationState",
    "IntegrationStatus",
    "IntegrationTarget",
    "IntegrationsPort",
    "SkillApplyCommand",
    "SkillPreviewCommand",
    "SkillSource",
    "SkillStatusCommand",
    "observation_pairing_contract",
]

type Compatibility = Literal["supported", "unsupported", "untested"]
HookPairingMode = Literal["paired", "post_only"]
HookCorrelationKind = Literal["tool_call_id", "generation_id", "none"]

# Pairing is a host/profile fact, rather than a property of the shared hook
# transport. Keep the exact reviewed profile cells here so hook ingress can
# apply the contract without importing a renderer (and its filesystem/process
# dependencies). An omitted profile is the compatibility path for an already
# installed legacy Claude/Cursor carrier. A nonempty unknown profile is a
# future claim, so it stays paired until that exact cell is reviewed.
_DEFAULT_HOOK_PAIRING: Final[tuple[HookPairingMode, HookCorrelationKind]] = (
    "paired",
    "tool_call_id",
)
_LEGACY_HOST_PAIRING: Final[Mapping[str, tuple[HookPairingMode, HookCorrelationKind]]] = (
    MappingProxyType(
        {
            "claude": ("post_only", "tool_call_id"),
            "cursor": ("post_only", "generation_id"),
        }
    )
)
_HOOK_PAIRING_BY_PROFILE: Final[
    Mapping[tuple[str, str], tuple[HookPairingMode, HookCorrelationKind]]
] = MappingProxyType(
    {
        (
            "claude",
            "claude-code-cli-local-project-2.1.241",
        ): ("post_only", "tool_call_id"),
        ("cursor", "cursor-ide-3.17.8"): ("post_only", "generation_id"),
    }
)


def observation_pairing_contract(
    harness_id: str, capability_profile_id: str | None
) -> tuple[HookPairingMode, HookCorrelationKind]:
    """Return the reviewed pairing contract for one host/profile cell.

    The mapping is intentionally exact. A missing Claude/Cursor profile uses
    the installed legacy post-only contract without claiming a supported
    host/version cell. A nonempty unknown profile stays on the conservative
    paired contract until its exact hook shape is reviewed.
    """

    if type(harness_id) is not str:
        return _DEFAULT_HOOK_PAIRING
    if type(capability_profile_id) is str:
        exact = _HOOK_PAIRING_BY_PROFILE.get((harness_id, capability_profile_id))
        if exact is not None:
            return exact
        return _DEFAULT_HOOK_PAIRING
    return _LEGACY_HOST_PAIRING.get(harness_id, _DEFAULT_HOOK_PAIRING)


_MAX_LOCATION_CHARS = 4_096
_MAX_FILES = 64
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$", re.ASCII)
_RELATIVE_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*/?$", re.ASCII)
_MEDIA_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(?:;[ -~]+)?$", re.ASCII)


def _port_error(reason: str) -> ProtocolValueError:
    if reason not in PROTOCOL_REASON_CODES:
        reason = "invalid_event_value_type"
    return ProtocolValueError(reason)


class HarnessId(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    CLAUDE = "claude"
    CODEX = "codex"
    CURSOR = "cursor"


class IntegrationScope(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    TRUSTED_PROJECT = "trusted_project"


class IntegrationAction(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    INSTALL = "install"
    REPLACE = "replace"
    REMOVE = "remove"
    NOOP = "noop"


class IntegrationState(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    ABSENT = "absent"
    INSTALLED_EXACT = "installed_exact"
    MODIFIED = "modified"
    PARTIAL = "partial"
    INCOMPATIBLE = "incompatible"
    UNSAFE = "unsafe"


class IntegrationReason(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    CONFIRMATION_REQUIRED = "confirmation_required"
    PREVIEW_STALE = "preview_stale"
    TARGET_UNTRUSTED = "target_untrusted"
    TARGET_UNSAFE = "target_unsafe"
    SOURCE_INVALID = "source_invalid"
    DESTINATION_CONFLICT = "destination_conflict"
    MODIFIED_COPY = "modified_copy"
    PARTIAL_INSTALL = "partial_install"
    VERSION_INCOMPATIBLE = "version_incompatible"
    MARKER_INVALID = "marker_invalid"
    WRITE_FAILED = "write_failed"
    REMOVE_REFUSED = "remove_refused"
    # The same project directory is already connected to this host configuration root under a
    # different path (a symlink, a case variant, or a moved directory) (#1058).
    PROJECT_CONNECTED_VIA_OTHER_PATH = "project_connected_via_other_path"


def _token(value: object, reason: str = "integration_value_invalid") -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise _port_error(reason)
    return value


def _relative_path(value: object) -> str:
    if type(value) is not str or _RELATIVE_PATH_RE.fullmatch(value) is None:
        raise _port_error("integration_path_invalid")
    if value.startswith("/") or "//" in value:
        raise _port_error("integration_path_invalid")
    parts = value.rstrip("/").split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _port_error("integration_path_invalid")
    return value


def _tuple(value: object, *, maximum: int, reason: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise _port_error(reason)
    result = cast(tuple[object, ...], value)
    if len(result) > maximum:
        raise _port_error(reason)
    return result


def _sorted_unique_strings(
    value: object,
    *,
    maximum: int = _MAX_FILES,
    token: bool = False,
) -> tuple[str, ...]:
    raw = _tuple(value, maximum=maximum, reason="integration_value_invalid")
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        member = _token(item) if token else _relative_path(item)
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _port_error(
                "duplicate_set_member" if member == previous else "unsorted_set_field"
            )
        result.append(member)
        previous = member
    return tuple(result)


def _compatibility(value: object) -> Compatibility:
    if type(value) is not str or value not in {"supported", "unsupported", "untested"}:
        raise _port_error("integration_compatibility_invalid")
    return cast(Compatibility, value)


def _digest_or_none(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise _port_error("invalid_digest")
    return validate_sha256_digest(value)


def _structural_rows(value: object, *, kind: Literal["change", "state"]) -> tuple[JsonObject, ...]:
    raw = _tuple(value, maximum=_MAX_FILES, reason="integration_file_rows_invalid")
    rows: list[JsonObject] = []
    previous: str | None = None
    for item in raw:
        try:
            row = item if type(item) is JsonObject else JsonObject(item)
        except ProtocolValueError as exc:
            raise _port_error("integration_file_rows_invalid") from exc
        expected = (
            frozenset(
                {
                    "action",
                    "relative_path",
                    "before_digest",
                    "before_size",
                    "after_digest",
                    "after_size",
                }
            )
            if kind == "change"
            else frozenset({"relative_path", "state", "digest", "size"})
        )
        if not frozenset(row).issubset(expected):
            raise _port_error("integration_file_rows_invalid")
        try:
            path = _relative_path(row["relative_path"])
        except (KeyError, ProtocolValueError) as exc:
            raise _port_error("integration_file_rows_invalid") from exc
        if previous is not None and path.encode("ascii") <= previous.encode("ascii"):
            raise _port_error("duplicate_set_member" if path == previous else "unsorted_set_field")
        if kind == "change":
            _validate_file_change(row)
        else:
            _validate_file_state(row)
        rows.append(row)
        previous = path
    return tuple(rows)


def _validate_optional_size(row: JsonObject, key: str) -> None:
    if key not in row:
        return
    value = row[key]
    if type(value) is not int or not 0 <= value <= 9_007_199_254_740_991:
        raise _port_error("integration_file_rows_invalid")


def _validate_optional_digest(row: JsonObject, key: str) -> None:
    if key not in row:
        return
    value = row[key]
    if type(value) is not str:
        raise _port_error("integration_file_rows_invalid")
    try:
        validate_sha256_digest(value)
    except ProtocolValueError as exc:
        raise _port_error("integration_file_rows_invalid") from exc


def _validate_file_change(row: JsonObject) -> None:
    try:
        action = row["action"]
    except KeyError as exc:
        raise _port_error("integration_file_rows_invalid") from exc
    if type(action) is not str or action not in {"create", "replace", "remove", "unchanged"}:
        raise _port_error("integration_file_rows_invalid")
    before = "before_digest" in row or "before_size" in row
    after = "after_digest" in row or "after_size" in row
    if ("before_digest" in row) != ("before_size" in row):
        raise _port_error("integration_file_rows_invalid")
    if ("after_digest" in row) != ("after_size" in row):
        raise _port_error("integration_file_rows_invalid")
    expected_presence = {
        "create": (False, True),
        "replace": (True, True),
        "remove": (True, False),
        "unchanged": (True, True),
    }
    if (before, after) != expected_presence[action]:
        raise _port_error("integration_file_rows_invalid")
    _validate_optional_digest(row, "before_digest")
    _validate_optional_digest(row, "after_digest")
    _validate_optional_size(row, "before_size")
    _validate_optional_size(row, "after_size")


def _validate_file_state(row: JsonObject) -> None:
    try:
        state = row["state"]
    except KeyError as exc:
        raise _port_error("integration_file_rows_invalid") from exc
    if type(state) is not str or state not in {"absent", "exact", "modified", "unexpected"}:
        raise _port_error("integration_file_rows_invalid")
    has_digest = "digest" in row
    has_size = "size" in row
    if has_digest != has_size or (state == "absent") == has_digest:
        raise _port_error("integration_file_rows_invalid")
    _validate_optional_digest(row, "digest")
    _validate_optional_size(row, "size")


@dataclass(frozen=True, slots=True)
class HarnessHookProfile:
    trigger_event: str
    trigger_payload_profile_id: str
    evidence_case_ids: tuple[str, ...]
    trigger_action: Literal["reground_status"] = "reground_status"
    duplicate_policy: Literal["coalesce"] = "coalesce"
    loop_policy: Literal["single_flight"] = "single_flight"
    failure_policy: Literal["best_effort"] = "best_effort"
    observation_events: tuple[str, ...] = ()
    pairing_mode: HookPairingMode = "paired"
    correlation_kind: HookCorrelationKind = "tool_call_id"

    def __post_init__(self) -> None:
        object.__setattr__(self, "trigger_event", _token(self.trigger_event))
        object.__setattr__(
            self,
            "trigger_payload_profile_id",
            _token(self.trigger_payload_profile_id),
        )
        cases = _sorted_unique_strings(self.evidence_case_ids, maximum=64, token=True)
        if not cases:
            raise _port_error("integration_hook_invalid")
        object.__setattr__(self, "evidence_case_ids", cases)
        if self.trigger_action != "reground_status":
            raise _port_error("integration_hook_invalid")
        if self.duplicate_policy != "coalesce":
            raise _port_error("integration_hook_invalid")
        if self.loop_policy != "single_flight":
            raise _port_error("integration_hook_invalid")
        if self.failure_policy != "best_effort":
            raise _port_error("integration_hook_invalid")
        if type(self.observation_events) is not tuple:
            raise _port_error("integration_hook_invalid")
        object.__setattr__(
            self,
            "observation_events",
            _sorted_unique_strings(self.observation_events, maximum=64, token=True),
        )
        if self.pairing_mode not in {"paired", "post_only"}:
            raise _port_error("integration_hook_invalid")
        if self.correlation_kind not in {"tool_call_id", "generation_id", "none"}:
            raise _port_error("integration_hook_invalid")
        # A generation identifies a host turn/conversation, never a tool call.
        # Pairing a pre/post action on it would manufacture identity and can
        # merge unrelated tools from one generation.
        if self.pairing_mode == "paired" and self.correlation_kind != "tool_call_id":
            raise _port_error("integration_hook_invalid")


@dataclass(frozen=True, slots=True)
class HarnessProfile:
    harness_id: HarnessId
    skill_root: str
    frontmatter_profile: str
    capability_profile_ids: tuple[str, ...]
    supported_versions: tuple[str, ...]
    hooks_by_capability_profile: Mapping[str, HarnessHookProfile | None]

    def __post_init__(self) -> None:
        if type(self.harness_id) is not HarnessId:
            raise _port_error("integration_harness_invalid")
        root = _relative_path(self.skill_root)
        if not root.endswith("/"):
            raise _port_error("integration_path_invalid")
        object.__setattr__(self, "skill_root", root)
        object.__setattr__(self, "frontmatter_profile", _token(self.frontmatter_profile))
        profiles = _sorted_unique_strings(self.capability_profile_ids, maximum=64, token=True)
        versions = _sorted_unique_strings(self.supported_versions, maximum=64, token=True)
        try:
            hooks = dict(self.hooks_by_capability_profile)
        except Exception as exc:
            raise _port_error("integration_profile_invalid") from exc
        if tuple(sorted(hooks, key=str.encode)) != profiles:
            raise _port_error("integration_profile_invalid")
        if bool(profiles) != bool(versions):
            raise _port_error("integration_profile_invalid")
        if any(type(key) is not str for key in hooks):
            raise _port_error("integration_profile_invalid")
        if any(
            value is not None and type(value) is not HarnessHookProfile for value in hooks.values()
        ):
            raise _port_error("integration_profile_invalid")
        object.__setattr__(self, "capability_profile_ids", profiles)
        object.__setattr__(self, "supported_versions", versions)
        object.__setattr__(self, "hooks_by_capability_profile", MappingProxyType(hooks))


@dataclass(frozen=True, slots=True, repr=False)
class IntegrationTarget:
    scope: IntegrationScope
    project_root: str

    def __post_init__(self) -> None:
        if type(self.scope) is not IntegrationScope:
            raise _port_error("integration_scope_invalid")
        if (
            type(self.project_root) is not str
            or not 1 <= len(self.project_root) <= _MAX_LOCATION_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in self.project_root)
        ):
            raise _port_error("integration_target_invalid")

    def __repr__(self) -> str:
        return "<IntegrationTarget redacted>"

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class IntegrationFile:
    relative_path: str
    size: int
    sha256: str
    media_type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "relative_path", _relative_path(self.relative_path))
        if type(self.size) is not int or not 0 <= self.size <= 9_007_199_254_740_991:
            raise _port_error("integration_file_invalid")
        validate_sha256_digest(self.sha256)
        if type(self.media_type) is not str or _MEDIA_TYPE_RE.fullmatch(self.media_type) is None:
            raise _port_error("integration_file_invalid")


@dataclass(frozen=True, slots=True)
class SkillSource:
    harness_id: HarnessId
    skill_version: str
    protocol_range: str
    harness_tested_set: tuple[str, ...]
    resource_set_digest: str
    files: tuple[IntegrationFile, ...]

    def __post_init__(self) -> None:
        if type(self.harness_id) is not HarnessId:
            raise _port_error("integration_harness_invalid")
        object.__setattr__(self, "skill_version", _token(self.skill_version))
        object.__setattr__(self, "protocol_range", _token(self.protocol_range))
        tested = _sorted_unique_strings(self.harness_tested_set, maximum=64, token=True)
        object.__setattr__(self, "harness_tested_set", tested)
        validate_sha256_digest(self.resource_set_digest)
        raw_files = _tuple(self.files, maximum=_MAX_FILES, reason="integration_source_invalid")
        files: list[IntegrationFile] = []
        previous: str | None = None
        for item in raw_files:
            if type(item) is not IntegrationFile:
                raise _port_error("integration_source_invalid")
            path = item.relative_path
            if previous is not None and path.encode("ascii") <= previous.encode("ascii"):
                raise _port_error(
                    "duplicate_set_member" if path == previous else "unsorted_set_field"
                )
            files.append(item)
            previous = path
        if not files:
            raise _port_error("integration_source_invalid")
        object.__setattr__(self, "files", tuple(files))


@dataclass(frozen=True, slots=True)
class SkillPreviewCommand:
    request_id: RequestId
    target: IntegrationTarget
    requested_action: IntegrationAction
    replace_modified: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        if type(self.target) is not IntegrationTarget:
            raise _port_error("integration_target_invalid")
        if (
            type(self.requested_action) is not IntegrationAction
            or self.requested_action is IntegrationAction.NOOP
        ):
            raise _port_error("integration_action_invalid")
        if type(self.replace_modified) is not bool:
            raise _port_error("integration_action_invalid")
        if self.replace_modified and self.requested_action is not IntegrationAction.REPLACE:
            raise _port_error("integration_action_invalid")


@dataclass(frozen=True, slots=True)
class SkillApplyCommand:
    request_id: RequestId
    target: IntegrationTarget
    requested_action: IntegrationAction
    preview_digest: str
    explicitly_accepted: bool
    replace_modified: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        if type(self.target) is not IntegrationTarget:
            raise _port_error("integration_target_invalid")
        if (
            type(self.requested_action) is not IntegrationAction
            or self.requested_action is IntegrationAction.NOOP
        ):
            raise _port_error("integration_action_invalid")
        validate_sha256_digest(self.preview_digest)
        if type(self.explicitly_accepted) is not bool or type(self.replace_modified) is not bool:
            raise _port_error("integration_action_invalid")
        if self.replace_modified and self.requested_action is not IntegrationAction.REPLACE:
            raise _port_error("integration_action_invalid")


@dataclass(frozen=True, slots=True)
class SkillStatusCommand:
    target: IntegrationTarget

    def __post_init__(self) -> None:
        if type(self.target) is not IntegrationTarget:
            raise _port_error("integration_target_invalid")


@dataclass(frozen=True, slots=True)
class IntegrationPreview:
    action: IntegrationAction
    state_before: IntegrationState
    source_digest: str
    installed_digest: str | None
    compatibility: Compatibility
    file_changes: tuple[JsonObject, ...]
    warnings: tuple[str, ...]
    preview_digest: str

    def __post_init__(self) -> None:
        if type(self.action) is not IntegrationAction:
            raise _port_error("integration_action_invalid")
        if type(self.state_before) is not IntegrationState:
            raise _port_error("integration_state_invalid")
        validate_sha256_digest(self.source_digest)
        object.__setattr__(self, "installed_digest", _digest_or_none(self.installed_digest))
        object.__setattr__(self, "compatibility", _compatibility(self.compatibility))
        object.__setattr__(self, "file_changes", _structural_rows(self.file_changes, kind="change"))
        object.__setattr__(self, "warnings", _sorted_unique_strings(self.warnings, token=True))
        validate_sha256_digest(self.preview_digest)


@dataclass(frozen=True, slots=True)
class IntegrationStatus:
    state: IntegrationState
    source_digest: str
    installed_digest: str | None
    compatibility: Compatibility
    file_states: tuple[JsonObject, ...]
    managed_marker_valid: bool

    def __post_init__(self) -> None:
        if type(self.state) is not IntegrationState:
            raise _port_error("integration_state_invalid")
        validate_sha256_digest(self.source_digest)
        object.__setattr__(self, "installed_digest", _digest_or_none(self.installed_digest))
        object.__setattr__(self, "compatibility", _compatibility(self.compatibility))
        object.__setattr__(self, "file_states", _structural_rows(self.file_states, kind="state"))
        if type(self.managed_marker_valid) is not bool:
            raise _port_error("integration_state_invalid")


@dataclass(frozen=True, slots=True)
class IntegrationResult:
    action: IntegrationAction
    state_before: IntegrationState
    state_after: IntegrationState
    source_digest: str
    installed_digest: str | None
    changed_files: tuple[str, ...]
    preview_digest: str

    def __post_init__(self) -> None:
        if type(self.action) is not IntegrationAction:
            raise _port_error("integration_action_invalid")
        if (
            type(self.state_before) is not IntegrationState
            or type(self.state_after) is not IntegrationState
        ):
            raise _port_error("integration_state_invalid")
        validate_sha256_digest(self.source_digest)
        object.__setattr__(self, "installed_digest", _digest_or_none(self.installed_digest))
        object.__setattr__(self, "changed_files", _sorted_unique_strings(self.changed_files))
        validate_sha256_digest(self.preview_digest)


@dataclass(frozen=True, slots=True)
class _IntegrationErrorFields(Exception):
    reason: IntegrationReason
    safe_details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if type(self.reason) is not IntegrationReason:
            raise _port_error("integration_reason_invalid")
        try:
            details = JsonObject(self.safe_details)
        except ProtocolValueError as exc:
            raise _port_error("integration_error_invalid") from exc
        if (
            len(details) > 16
            or len(canonical_encode(details)) > 4_096
            or any(_TOKEN_RE.fullmatch(key) is None for key in details)
        ):
            raise _port_error("integration_error_invalid")
        object.__setattr__(self, "safe_details", details)
        Exception.__init__(self, self.reason.value)


class IntegrationError(_IntegrationErrorFields):
    """Typed integration failure with frozen ``reason`` and ``safe_details``.

    The frozen dataclass ``__setattr__`` rejects every attribute assignment on its own exact
    class, including the ``__traceback__`` assignment Python 3.14 ``contextlib`` performs when an
    error propagates through a ``@contextmanager``, which masked the real error with
    ``FrozenInstanceError``. Raising through this thin subclass keeps the fields frozen and value
    equality while leaving interpreter-owned exception state assignable.
    """

    __slots__ = ()


class IntegrationsPort(Protocol):
    async def preview_skill(
        self,
        harness: HarnessId,
        command: SkillPreviewCommand,
    ) -> IntegrationPreview: ...

    async def install_skill(
        self,
        harness: HarnessId,
        command: SkillApplyCommand,
    ) -> IntegrationResult: ...

    async def status_skill(
        self,
        harness: HarnessId,
        command: SkillStatusCommand,
    ) -> IntegrationStatus: ...

    async def remove_skill(
        self,
        harness: HarnessId,
        command: SkillApplyCommand,
    ) -> IntegrationResult: ...
