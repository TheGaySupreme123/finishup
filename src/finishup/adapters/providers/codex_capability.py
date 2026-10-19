"""Capability-checked admission of the Codex subscription evaluator runtime (ADR-006).

The evaluator no longer pins one reviewed Codex build per platform. Any stable Codex release at
or above :data:`CODEX_EVALUATOR_RUNTIME_FLOOR` is admitted when the bytes FinishUP will launch pass
a capability check:

* the generated app-server v2 schema still carries every method, field and closed value the
  evaluator relies on (:func:`check_app_server_schema`, structural, never a whole-schema digest);
* a zero-inference app-server session reports the same version, keeps every pre-disclosure event
  inside the reviewed allowlist, and proves the read-only, network-off, ephemeral thread posture
  before any case could be sent (``codex_app_server.codex_capability_probe``);
* the configured model is listed for the dedicated home (the readiness probe and every attempt).

The result is a :class:`CodexCapabilityRecord`, kept beside the retained runtime. It is
provenance, not an admission list: the binding commits to its digest, and the launch fence checks
that the bytes and record it launches are the ones that passed. Nothing in this module starts an
app-server session or reads a credential.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast

from finishup.domain.values import validate_sha256_digest
from finishup.protocol.canonical import JsonValue, canonical_digest, strict_json_parse
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "CODEX_CAPABILITY_CHECKS",
    "CODEX_CAPABILITY_RECORD_NAME",
    "CODEX_CAPABILITY_RECORD_SCHEMA",
    "CODEX_PROBE_CLEANUP_UNCONFIRMED",
    "CODEX_CODE_MODE_HOST_NAME",
    "CODEX_EVALUATOR_CAPABILITY_PROFILE",
    "CODEX_EVALUATOR_RUNTIME_FLOOR",
    "CodexCapabilityRecord",
    "CodexPlatform",
    "capability_record_path",
    "check_app_server_schema",
    "codex_bundled_model_catalog",
    "codex_cli_version",
    "codex_platform_for",
    "codex_source_identity",
    "codex_version_key",
    "generate_app_server_schema",
    "host_codex_platform",
    "parse_codex_source_identity",
    "read_capability_record",
    "require_admitted_version",
    "validate_capability_binding",
    "write_capability_record",
]

# The oldest Codex release whose evaluator-facing behaviour was reviewed end to end: the
# code-mode host beside the executable, ``remoteControl/status/changed`` after initialize, and
# the ``normalModelSlug`` rate-limit field. The protocol subset below holds unchanged from it
# through 0.162.1 (2026-10-13 review, issue #1056).
CODEX_EVALUATOR_RUNTIME_FLOOR: Final = "0.157.1"
# Names the FinishUP-side contract: this floor, the reviewed subset, and the probe procedure. A
# change to any of them is a new profile, which existing bindings meet as
# ``codex_runtime_profile_outdated`` until ``repair`` re-runs the check.
# v3 (#1118 unit 3): ``initialize`` opts into the experimental API only to send
# ``thread/start.environments: []``; the isolated config disables the plan and user-input
# utilities; the schema is generated with ``--experimental`` so that field is checked.
CODEX_EVALUATOR_CAPABILITY_PROFILE: Final = "codex-evaluator/capability/v3"
CODEX_CAPABILITY_RECORD_NAME: Final = "capability.json"
# Frozen legacy identifier (ADR-048): stored in capability.json records; protocol 0.1 keeps one
# `yoetz.<name>/<n>` tag namespace.
CODEX_CAPABILITY_RECORD_SCHEMA: Final = "yoetz.codex-evaluator-capability/1"
CODEX_CODE_MODE_HOST_NAME: Final = "codex-code-mode-host"
CODEX_CAPABILITY_CHECKS: Final[tuple[str, ...]] = (
    "app_server_schema_subset",
    "code_mode_host_present",
    "initialize_version",
    "predisclosure_events",
    "thread_isolation",
    "version_floor",
)

_VERSION: Final = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")
_CLI_VERSION: Final = re.compile(
    r"^codex-cli ((?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8}))\s*$"
)
_IDENTITY: Final = re.compile(r"^openai-codex-npm-(darwin-arm64|linux-x64)-([0-9.]{5,32})$")
_RECORD_MAX_BYTES: Final = 64 * 1024
_SCHEMA_MAX_BYTES: Final = 16 * 1024 * 1024
# ``codex debug models --bundled`` prints about 650 KiB for 0.162.1.
_CATALOG_MAX_BYTES: Final = 8 * 1024 * 1024
_SCHEMA_FILE: Final = "codex_app_server_protocol.v2.schemas.json"
_SUBPROCESS_TIMEOUT_SECONDS: Final = 60.0
# How long a killed candidate process group has to disappear before cleanup is unconfirmed.
_GROUP_CLEANUP_GRACE_SECONDS: Final = 5.0
# The one closed token for a candidate subprocess whose process group could not be confirmed
# gone. It stops runtime selection outright: no other candidate is tried after it.
CODEX_PROBE_CLEANUP_UNCONFIRMED: Final = "codex_capability_probe_cleanup_unconfirmed"


@dataclass(frozen=True, slots=True)
class CodexPlatform:
    """One supported host platform and the npm native package layout Codex ships for it."""

    os: Literal["darwin", "linux"]
    architecture: Literal["arm64", "x86_64"]
    npm_suffix: Literal["darwin-arm64", "linux-x64"]
    native_executable_relative: Path

    @property
    def npm_cpu(self) -> str:
        return "arm64" if self.architecture == "arm64" else "x64"

    @property
    def native_package_directory(self) -> str:
        return f"codex-{self.npm_suffix}"

    def native_package_version(self, version: str) -> str:
        return f"{version}-{self.npm_suffix}"

    def native_package_spec(self, version: str) -> str:
        # npm resolves the platform alias through the canonical package name (the upstream
        # wrapper metadata uses ``npm:@openai/codex@<version>-linux-x64`` and its darwin twin).
        return f"npm:@openai/codex@{self.native_package_version(version)}"


_PLATFORMS: Final[Mapping[tuple[str, str], CodexPlatform]] = {
    ("darwin", "arm64"): CodexPlatform(
        "darwin", "arm64", "darwin-arm64", Path("vendor/aarch64-apple-darwin/bin/codex")
    ),
    ("linux", "x86_64"): CodexPlatform(
        "linux", "x86_64", "linux-x64", Path("vendor/x86_64-unknown-linux-musl/bin/codex")
    ),
}


def codex_platform_for(platform_os: str, architecture: str) -> CodexPlatform:
    """The supported platform for one host, or the closed ``platform_unsupported`` refusal."""

    normalized_os = "linux" if platform_os.startswith("linux") else platform_os
    normalized_architecture = "x86_64" if architecture == "amd64" else architecture
    try:
        return _PLATFORMS[(normalized_os, normalized_architecture)]
    except KeyError as error:
        raise ValueError("codex_runtime_platform_unsupported") from error


def host_codex_platform() -> CodexPlatform:
    """The supported platform of the running interpreter."""

    import platform
    import sys

    return codex_platform_for(sys.platform, platform.machine())


def codex_version_key(version: object) -> tuple[int, int, int] | None:
    """The comparable key of one stable ``X.Y.Z`` release; prereleases and builds are ``None``."""

    if type(version) is not str:
        return None
    match = _VERSION.fullmatch(version)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


_FLOOR_KEY: Final = codex_version_key(CODEX_EVALUATOR_RUNTIME_FLOOR)


def require_admitted_version(version: object) -> str:
    """Return ``version`` when it is a stable release at or above the floor."""

    key = codex_version_key(version)
    if key is None or _FLOOR_KEY is None or key < _FLOOR_KEY:
        raise ValueError("codex_runtime_version_unsupported")
    return cast(str, version)


def codex_source_identity(platform: CodexPlatform, version: str) -> str:
    """The retained-store identity of one platform release, also its directory name."""

    require_admitted_version(version)
    return f"openai-codex-npm-{platform.npm_suffix}-{version}"


def parse_codex_source_identity(identity: object) -> tuple[CodexPlatform, str] | None:
    """Invert :func:`codex_source_identity`; ``None`` for anything else."""

    if type(identity) is not str:
        return None
    match = _IDENTITY.fullmatch(identity)
    if match is None or codex_version_key(match.group(2)) is None:
        return None
    platform = next(item for item in _PLATFORMS.values() if item.npm_suffix == match.group(1))
    return platform, match.group(2)


def capability_record_path(executable: Path) -> Path:
    """The record kept beside one retained runtime executable; the only location read."""

    return executable.parent / CODEX_CAPABILITY_RECORD_NAME


@dataclass(frozen=True, slots=True)
class CodexCapabilityRecord:
    """Deterministic provenance of one passed capability check.

    It carries no time, path, account or model, so re-checking the same bytes under the same
    profile yields the same record and digest: setup, repair and install stay idempotent.
    """

    runtime_version: str
    source_identity: str
    platform_os: str
    platform_architecture: str
    executable_sha256: str
    code_mode_host_sha256: str
    app_server_schema_sha256: str
    isolated_config_sha256: str
    capability_profile: str = CODEX_EVALUATOR_CAPABILITY_PROFILE
    runtime_floor: str = CODEX_EVALUATOR_RUNTIME_FLOOR
    checks: tuple[str, ...] = field(default=CODEX_CAPABILITY_CHECKS)

    def __post_init__(self) -> None:
        parsed = parse_codex_source_identity(self.source_identity)
        if (
            parsed is None
            or parsed[1] != self.runtime_version
            or parsed[0].os != self.platform_os
            or parsed[0].architecture != self.platform_architecture
            or type(self.capability_profile) is not str
            or type(self.runtime_floor) is not str
            or type(self.checks) is not tuple
            or any(type(item) is not str for item in self.checks)
        ):
            raise ValueError("codex_runtime_capability_record_invalid")
        try:
            for digest in (
                self.executable_sha256,
                self.code_mode_host_sha256,
                self.app_server_schema_sha256,
                self.isolated_config_sha256,
            ):
                validate_sha256_digest(digest)
        except ProtocolValueError as error:
            raise ValueError("codex_runtime_capability_record_invalid") from error

    @property
    def current(self) -> bool:
        """Checked under this release's profile, floor and procedure."""

        return (
            self.capability_profile == CODEX_EVALUATOR_CAPABILITY_PROFILE
            and self.runtime_floor == CODEX_EVALUATOR_RUNTIME_FLOOR
            and self.checks == CODEX_CAPABILITY_CHECKS
            and codex_version_key(self.runtime_version) is not None
            and _FLOOR_KEY is not None
            and cast(tuple[int, int, int], codex_version_key(self.runtime_version)) >= _FLOOR_KEY
        )

    def to_json(self) -> dict[str, JsonValue]:
        return {
            "schema": CODEX_CAPABILITY_RECORD_SCHEMA,
            "capability_profile": self.capability_profile,
            "runtime_floor": self.runtime_floor,
            "runtime_version": self.runtime_version,
            "source_identity": self.source_identity,
            "platform": {"os": self.platform_os, "architecture": self.platform_architecture},
            "executable_sha256": self.executable_sha256,
            "code_mode_host_sha256": self.code_mode_host_sha256,
            "app_server_schema_sha256": self.app_server_schema_sha256,
            "isolated_config_sha256": self.isolated_config_sha256,
            "checks": list(self.checks),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_json())

    @classmethod
    def from_json(cls, value: object) -> CodexCapabilityRecord:
        if type(value) is not dict:
            raise ValueError("codex_runtime_capability_record_invalid")
        source = cast(dict[str, object], value)
        expected = {
            "schema",
            "capability_profile",
            "runtime_floor",
            "runtime_version",
            "source_identity",
            "platform",
            "executable_sha256",
            "code_mode_host_sha256",
            "app_server_schema_sha256",
            "isolated_config_sha256",
            "checks",
        }
        platform = source.get("platform")
        checks = source.get("checks")
        if (
            set(source) != expected
            or source["schema"] != CODEX_CAPABILITY_RECORD_SCHEMA
            or type(platform) is not dict
            or set(cast(dict[str, object], platform)) != {"os", "architecture"}
            or type(checks) is not list
        ):
            raise ValueError("codex_runtime_capability_record_invalid")
        platform_facts = cast(dict[str, object], platform)
        strings = (
            "capability_profile",
            "runtime_floor",
            "runtime_version",
            "source_identity",
            "executable_sha256",
            "code_mode_host_sha256",
            "app_server_schema_sha256",
            "isolated_config_sha256",
        )
        if any(type(source[name]) is not str for name in strings) or any(
            type(platform_facts[name]) is not str for name in ("os", "architecture")
        ):
            raise ValueError("codex_runtime_capability_record_invalid")
        return cls(
            runtime_version=cast(str, source["runtime_version"]),
            source_identity=cast(str, source["source_identity"]),
            platform_os=cast(str, platform_facts["os"]),
            platform_architecture=cast(str, platform_facts["architecture"]),
            executable_sha256=cast(str, source["executable_sha256"]),
            code_mode_host_sha256=cast(str, source["code_mode_host_sha256"]),
            app_server_schema_sha256=cast(str, source["app_server_schema_sha256"]),
            isolated_config_sha256=cast(str, source["isolated_config_sha256"]),
            capability_profile=cast(str, source["capability_profile"]),
            runtime_floor=cast(str, source["runtime_floor"]),
            checks=tuple(cast(list[str], checks)),
        )


def read_capability_record(directory: Path) -> CodexCapabilityRecord:
    """Read the record kept in one retained-runtime directory without following a symlink.

    A missing record raises ``FileNotFoundError``; anything else unusable is the closed
    ``codex_runtime_capability_record_invalid`` token.
    """

    path = directory / CODEX_CAPABILITY_RECORD_NAME
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as error:
        raise ValueError("codex_runtime_capability_record_invalid") from error
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or not 0 < facts.st_size <= _RECORD_MAX_BYTES:
            raise ValueError("codex_runtime_capability_record_invalid")
        raw = os.read(descriptor, _RECORD_MAX_BYTES + 1)
    except OSError as error:
        raise ValueError("codex_runtime_capability_record_invalid") from error
    finally:
        os.close(descriptor)
    try:
        return CodexCapabilityRecord.from_json(strict_json_parse(raw))
    except (ProtocolValueError, RecursionError) as error:
        raise ValueError("codex_runtime_capability_record_invalid") from error


def write_capability_record(directory: Path, record: CodexCapabilityRecord) -> None:
    """Atomically commit ``record`` beside its retained runtime, owner-read-only."""

    payload = (json.dumps(record.to_json(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        handle, name = tempfile.mkstemp(prefix=".record-", dir=directory)
        temporary = Path(name)
        with os.fdopen(handle, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o400)
        os.replace(temporary, directory / CODEX_CAPABILITY_RECORD_NAME)
        temporary = None
    except OSError as error:
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def validate_capability_binding(
    *,
    source_identity: str,
    executable_sha256: str,
    runtime_version: str,
    app_server_schema_sha256: str,
    capability_cell_sha256: str,
    capability_profile: str,
    capability_evidence_expires_at: str,
    isolated_config_sha256: str,
    expected_isolated_config_sha256: str,
    expected_evidence_expires_at: str,
) -> CodexPlatform:
    """Validate a binding's capability fields without touching any file.

    A binding written under an earlier contract (an exact-cell profile such as
    ``codex-evaluator/0.157.1/v2``, another isolated config, another evidence window) is
    ``codex_runtime_profile_outdated``: ``repair`` re-runs the check. A current-profile binding
    naming a release below the floor, or an identity that disagrees with its version, is
    ``codex_runtime_version_unsupported`` / ``codex_runtime_capability_unsupported``.
    """

    if (
        capability_profile != CODEX_EVALUATOR_CAPABILITY_PROFILE
        or isolated_config_sha256 != expected_isolated_config_sha256
        or capability_evidence_expires_at != expected_evidence_expires_at
    ):
        raise ValueError("codex_runtime_profile_outdated")
    require_admitted_version(runtime_version)
    parsed = parse_codex_source_identity(source_identity)
    if parsed is None or parsed[1] != runtime_version:
        raise ValueError("codex_runtime_capability_unsupported")
    try:
        for digest in (
            executable_sha256,
            app_server_schema_sha256,
            capability_cell_sha256,
            isolated_config_sha256,
        ):
            validate_sha256_digest(digest)
    except ProtocolValueError as error:
        raise ValueError("codex_runtime_binding_invalid") from error
    return parsed[0]


# -- the reviewed app-server protocol subset ------------------------------------------------------

type _Requirement = tuple[str, str, object]

# Every request the evaluator sends, every response and notification field it reads, and every
# closed value it interprets. Checked structurally against the schema the candidate binary
# generates: a renamed method, a removed field, or a field whose type no longer admits the shape
# the evaluator sends or reads makes the candidate incompatible. Additive fields, new methods and
# new notifications pass: the runtime allowlists still fail closed on anything unreviewed.
_REVIEWED_SUBSET: Final[tuple[_Requirement, ...]] = (
    (
        "methods",
        "ClientRequest",
        (
            "account/login/cancel",
            "account/login/start",
            "account/logout",
            "account/read",
            "initialize",
            "model/list",
            "thread/start",
            "turn/interrupt",
            "turn/start",
        ),
    ),
    (
        "methods",
        "ServerNotification",
        (
            "account/login/completed",
            "account/rateLimits/updated",
            "account/updated",
            "error",
            "item/completed",
            "item/started",
            "model/rerouted",
            "remoteControl/status/changed",
            "thread/tokenUsage/updated",
            "turn/completed",
            "warning",
        ),
    ),
    ("props", "InitializeParams", {"capabilities": "object", "clientInfo": "object"}),
    (
        "props",
        "InitializeCapabilities",
        {
            "experimentalApi": "boolean",
            "mcpServerOpenaiFormElicitation": "boolean",
            "requestAttestation": "boolean",
        },
    ),
    ("props", "ClientInfo", {"name": "string", "title": "string", "version": "string"}),
    ("props", "GetAccountParams", {"refreshToken": "boolean"}),
    ("props", "GetAccountResponse", {"account": "object"}),
    ("variant", "Account", ("chatgpt", ("planType",))),
    (
        "props",
        "ModelListParams",
        {"cursor": "string", "includeHidden": "boolean", "limit": "integer"},
    ),
    ("props", "ModelListResponse", {"data": "array", "nextCursor": "string"}),
    ("props", "Model", {"id": "string", "model": "string", "supportedReasoningEfforts": "array"}),
    ("props", "ReasoningEffortOption", {"reasoningEffort": "string"}),
    ("variant", "LoginAccountParams", ("chatgpt", ())),
    ("variant", "LoginAccountParams", ("chatgptDeviceCode", ())),
    ("variant", "LoginAccountResponse", ("chatgpt", ("authUrl", "loginId"))),
    (
        "variant",
        "LoginAccountResponse",
        ("chatgptDeviceCode", ("loginId", "userCode", "verificationUrl")),
    ),
    ("props", "AccountLoginCompletedNotification", {"loginId": "string", "success": "boolean"}),
    ("props", "CancelLoginAccountParams", {"loginId": "string"}),
    (
        "props",
        "ThreadStartParams",
        {
            "approvalPolicy": "string",
            "approvalsReviewer": "string",
            "baseInstructions": "string",
            "cwd": "string",
            "environments": "array",
            "ephemeral": "boolean",
            "model": "string",
            "modelProvider": "string",
            "personality": "string",
            "sandbox": "string",
            "serviceName": "string",
        },
    ),
    ("values", "AskForApproval", ("never",)),
    ("values", "ApprovalsReviewer", ("user",)),
    ("values", "Personality", ("none",)),
    ("values", "SandboxMode", ("read-only",)),
    (
        "props",
        "ThreadStartResponse",
        {
            "cwd": "string",
            "instructionSources": "array",
            "model": "string",
            "modelProvider": "string",
            "sandbox": "object",
            "thread": "object",
        },
    ),
    ("props", "Thread", {"cwd": "string", "ephemeral": "boolean", "id": "string", "path": "null"}),
    ("variant", "SandboxPolicy", ("readOnly", ("networkAccess",))),
    (
        "props",
        "TurnStartParams",
        {
            "approvalPolicy": "string",
            "approvalsReviewer": "string",
            "effort": "string",
            "input": "array",
            "model": "string",
            "outputSchema": "object",
            "personality": "string",
            "sandboxPolicy": "object",
            "summary": "string",
            "threadId": "string",
        },
    ),
    ("variant", "UserInput", ("text", ("text",))),
    ("values", "ReasoningSummary", ("none",)),
    ("props", "TurnStartResponse", {"turn": "object"}),
    ("props", "Turn", {"error": "null", "id": "string", "status": "string"}),
    ("values", "TurnStatus", ("completed", "inProgress")),
    ("props", "TurnCompletedNotification", {"threadId": "string", "turn": "object"}),
    ("props", "ItemStartedNotification", {"item": "object"}),
    ("props", "ItemCompletedNotification", {"item": "object"}),
    ("variant", "ThreadItem", ("agentMessage", ("phase", "text"))),
    ("closed", "MessagePhase", ("commentary", "final_answer", "partial_answer")),
    ("props", "TurnInterruptParams", {"threadId": "string", "turnId": "string"}),
    ("props", "WarningNotification", {"message": "string", "threadId": "string"}),
    ("props", "ErrorNotification", {"error": "object"}),
    ("props", "TurnError", {"codexErrorInfo": "null"}),
    ("props", "RemoteControlStatusChangedNotification", {"status": "string"}),
    ("values", "RemoteControlConnectionStatus", ("disabled",)),
    (
        "props",
        "ThreadTokenUsageUpdatedNotification",
        {
            "threadId": "string",
            "tokenUsage": "object",
            "turnId": "string",
        },
    ),
    ("props", "AccountRateLimitsUpdatedNotification", {"rateLimits": "object"}),
)


# Every field the evaluator always sends in each request object it builds (``cursor`` is sent
# only on later ``model/list`` pages, so it is not here). A definition whose ``required`` set
# names anything else would reject the request -- for ``turn/start`` only after the packet
# arrived -- so the candidate is incompatible. The checked required sets enter the digest.
_SENT_FIELDS: Final[Mapping[str, frozenset[str]]] = {
    "InitializeParams": frozenset({"capabilities", "clientInfo"}),
    "InitializeCapabilities": frozenset(
        {"experimentalApi", "mcpServerOpenaiFormElicitation", "requestAttestation"}
    ),
    "ClientInfo": frozenset({"name", "title", "version"}),
    "GetAccountParams": frozenset({"refreshToken"}),
    "ModelListParams": frozenset({"includeHidden", "limit"}),
    "CancelLoginAccountParams": frozenset({"loginId"}),
    "ThreadStartParams": frozenset(
        {
            "approvalPolicy",
            "approvalsReviewer",
            "baseInstructions",
            "cwd",
            "environments",
            "ephemeral",
            "model",
            "modelProvider",
            "personality",
            "sandbox",
            "serviceName",
        }
    ),
    "TurnStartParams": frozenset(
        {
            "approvalPolicy",
            "approvalsReviewer",
            "effort",
            "input",
            "model",
            "outputSchema",
            "personality",
            "sandboxPolicy",
            "summary",
            "threadId",
        }
    ),
    "TurnInterruptParams": frozenset({"threadId", "turnId"}),
}
# The same rule for the tagged request variants the evaluator sends (``type`` included).
_SENT_VARIANT_FIELDS: Final[Mapping[tuple[str, str], frozenset[str]]] = {
    ("LoginAccountParams", "chatgpt"): frozenset({"type"}),
    ("LoginAccountParams", "chatgptDeviceCode"): frozenset({"type"}),
    ("UserInput", "text"): frozenset({"text", "type"}),
    ("SandboxPolicy", "readOnly"): frozenset({"networkAccess", "type"}),
}
# The exact closed values the evaluator sends. Each request field must still admit its value
# (through whatever definition it now references); the configured reasoning effort is proven
# per model by ``model/list`` instead.
_SENT_VALUES: Final[tuple[tuple[str, str, str], ...]] = (
    ("ThreadStartParams", "approvalPolicy", "never"),
    ("ThreadStartParams", "approvalsReviewer", "user"),
    ("ThreadStartParams", "modelProvider", "openai"),
    ("ThreadStartParams", "personality", "none"),
    ("ThreadStartParams", "sandbox", "read-only"),
    ("TurnStartParams", "approvalPolicy", "never"),
    ("TurnStartParams", "approvalsReviewer", "user"),
    ("TurnStartParams", "personality", "none"),
    ("TurnStartParams", "summary", "none"),
)


def _definitions(document: object) -> Mapping[str, object]:
    if not isinstance(document, Mapping):
        raise ValueError("codex_runtime_protocol_incompatible")
    definitions = cast(Mapping[str, object], document).get("definitions")
    if not isinstance(definitions, Mapping):
        raise ValueError("codex_runtime_protocol_incompatible")
    return cast(Mapping[str, object], definitions)


def _resolve(schema: object, definitions: Mapping[str, object]) -> Mapping[str, object]:
    for _ in range(16):
        if not isinstance(schema, Mapping):
            return {}
        source = cast(Mapping[str, object], schema)
        reference = source.get("$ref")
        if type(reference) is not str:
            return source
        if not reference.startswith("#/definitions/"):
            return {}
        schema = definitions.get(reference.rsplit("/", 1)[-1])
    return {}


def _accepted(
    schema: object, definitions: Mapping[str, object], depth: int = 0
) -> tuple[set[str], set[str]]:
    """(JSON types, string values) one schema admits; ``any`` when it does not constrain."""

    if depth > 16:
        return {"any"}, set()
    source = _resolve(schema, definitions)
    types: set[str] = set()
    values: set[str] = set()
    raw_type = source.get("type")
    if type(raw_type) is str:
        types.add(raw_type)
    elif isinstance(raw_type, list):
        types.update(item for item in cast(list[object], raw_type) if type(item) is str)
    for key in ("enum",):
        raw = source.get(key)
        if isinstance(raw, list):
            for item in cast(list[object], raw):
                if type(item) is str:
                    values.add(item)
                    types.add("string")
                elif item is None:
                    types.add("null")
    if type(source.get("const")) is str:
        values.add(cast(str, source["const"]))
        types.add("string")
    for key in ("anyOf", "oneOf", "allOf"):
        raw = source.get(key)
        if isinstance(raw, list):
            for item in cast(list[object], raw):
                nested_types, nested_values = _accepted(item, definitions, depth + 1)
                types.update(nested_types)
                values.update(nested_values)
    if "integer" in types:
        types.add("number")
    if not types and not values:
        types.add("any")
    return types, values


def _methods(definition: Mapping[str, object], definitions: Mapping[str, object]) -> set[str]:
    methods: set[str] = set()
    for key in ("oneOf", "anyOf"):
        raw = definition.get(key)
        if not isinstance(raw, list):
            continue
        for variant in cast(list[object], raw):
            properties = _resolve(variant, definitions).get("properties")
            if isinstance(properties, Mapping):
                method = cast(Mapping[str, object], properties).get("method")
                methods.update(_accepted(method, definitions)[1])
    return methods


def _variant_schema(
    definition: Mapping[str, object], definitions: Mapping[str, object], tag: str
) -> Mapping[str, object] | None:
    for key in ("oneOf", "anyOf"):
        raw = definition.get(key)
        if not isinstance(raw, list):
            continue
        for variant in cast(list[object], raw):
            resolved = _resolve(variant, definitions)
            properties = resolved.get("properties")
            if not isinstance(properties, Mapping):
                continue
            discriminator = cast(Mapping[str, object], properties).get("type")
            if tag in _accepted(discriminator, definitions)[1]:
                return resolved
    return None


def _variant(
    definition: Mapping[str, object], definitions: Mapping[str, object], tag: str
) -> Mapping[str, object] | None:
    schema = _variant_schema(definition, definitions, tag)
    return None if schema is None else cast(Mapping[str, object], schema["properties"])


def _required(schema: Mapping[str, object]) -> frozenset[str]:
    """The ``required`` set of one object schema; anything but a list of names is incompatible."""

    raw = schema.get("required", [])
    if not isinstance(raw, list) or any(type(item) is not str for item in cast(list[object], raw)):
        raise ValueError("codex_runtime_protocol_incompatible")
    return frozenset(cast(list[str], raw))


def _admits_string(
    schema: object, definitions: Mapping[str, object], value: str, depth: int = 0
) -> bool:
    """Whether ``schema`` admits the exact string ``value`` the evaluator sends."""

    if depth > 16:
        return False
    source = _resolve(schema, definitions)
    if "const" in source:
        return source["const"] == value
    raw_enum = source.get("enum")
    if isinstance(raw_enum, list):
        return value in cast(list[object], raw_enum)
    branches = [
        cast(list[object], source[key])
        for key in ("anyOf", "oneOf")
        if isinstance(source.get(key), list)
    ]
    if branches and not any(
        _admits_string(item, definitions, value, depth + 1)
        for branch in branches
        for item in branch
    ):
        return False
    raw_all = source.get("allOf")
    if isinstance(raw_all, list) and not all(
        _admits_string(item, definitions, value, depth + 1) for item in cast(list[object], raw_all)
    ):
        return False
    if branches or isinstance(raw_all, list):
        return True
    raw_type = source.get("type")
    if raw_type is None:
        return True
    if type(raw_type) is str:
        return raw_type == "string"
    return isinstance(raw_type, list) and "string" in cast(list[object], raw_type)


def _strings(values: set[str] | tuple[str, ...]) -> JsonValue:
    return [cast(JsonValue, item) for item in sorted(values)]


def check_app_server_schema(document: object) -> str:
    """Structurally check the reviewed subset; return the digest of the facts that were checked.

    The digest is provenance for the record (which methods, fields, types and values the
    candidate's own schema declared for the reviewed subset), not an admission key.
    """

    definitions = _definitions(document)
    facts: dict[str, JsonValue] = {}
    for kind, name, expectation in _REVIEWED_SUBSET:
        definition = definitions.get(name)
        if not isinstance(definition, Mapping):
            raise ValueError("codex_runtime_protocol_incompatible")
        source = cast(Mapping[str, object], definition)
        key = f"{kind}:{name}"
        if kind == "methods":
            declared = _methods(source, definitions)
            required = set(cast(tuple[str, ...], expectation))
            if not required <= declared:
                raise ValueError("codex_runtime_protocol_incompatible")
            facts[key] = _strings(required)
        elif kind == "props":
            properties = source.get("properties")
            if not isinstance(properties, Mapping):
                raise ValueError("codex_runtime_protocol_incompatible")
            checked: dict[str, JsonValue] = {}
            for prop, expected_type in cast(Mapping[str, str], expectation).items():
                if prop not in properties:
                    raise ValueError("codex_runtime_protocol_incompatible")
                types, _values = _accepted(
                    cast(Mapping[str, object], properties)[prop], definitions
                )
                if "any" not in types and expected_type not in types:
                    raise ValueError("codex_runtime_protocol_incompatible")
                checked[prop] = _strings(types)
            facts[key] = checked
        elif kind == "values":
            _types, values = _accepted(source, definitions)
            if not set(cast(tuple[str, ...], expectation)) <= values:
                raise ValueError("codex_runtime_protocol_incompatible")
            facts[key] = _strings(cast(tuple[str, ...], expectation))
        elif kind == "closed":
            _types, values = _accepted(source, definitions)
            if not values or not values <= set(cast(tuple[str, ...], expectation)):
                raise ValueError("codex_runtime_protocol_incompatible")
            facts[key] = _strings(values)
        elif kind == "variant":
            tag, props = cast(tuple[str, tuple[str, ...]], expectation)
            variant = _variant(source, definitions, tag)
            if variant is None or not set(props) <= set(variant):
                raise ValueError("codex_runtime_protocol_incompatible")
            facts[f"{key}:{tag}"] = _strings(props)
        else:  # pragma: no cover - the table above is closed
            raise ValueError("codex_runtime_protocol_incompatible")
    for name, sent in _SENT_FIELDS.items():
        if not isinstance(definitions.get(name), Mapping):
            raise ValueError("codex_runtime_protocol_incompatible")
        required = _required(_resolve(definitions[name], definitions))
        if not required <= sent:
            raise ValueError("codex_runtime_protocol_incompatible")
        facts[f"required:{name}"] = _strings(set(required))
    for (name, tag), sent in _SENT_VARIANT_FIELDS.items():
        definition = definitions.get(name)
        variant = (
            None
            if not isinstance(definition, Mapping)
            else _variant_schema(cast(Mapping[str, object], definition), definitions, tag)
        )
        if variant is None:
            raise ValueError("codex_runtime_protocol_incompatible")
        required = _required(variant)
        if not required <= sent:
            raise ValueError("codex_runtime_protocol_incompatible")
        facts[f"required:{name}:{tag}"] = _strings(set(required))
    for name, prop, value in _SENT_VALUES:
        definition = _resolve(definitions.get(name), definitions)
        properties = definition.get("properties")
        if not isinstance(properties, Mapping) or prop not in properties:
            raise ValueError("codex_runtime_protocol_incompatible")
        field_schema = cast(Mapping[str, object], properties)[prop]
        if not _admits_string(field_schema, definitions, value):
            raise ValueError("codex_runtime_protocol_incompatible")
        facts[f"sent:{name}.{prop}"] = _strings(_accepted(field_schema, definitions)[1])
    return canonical_digest(facts)


# -- zero-inference subprocesses ------------------------------------------------------------------

type SubprocessRunner = Callable[[Sequence[str], Path, Mapping[str, str]], tuple[int, bytes]]


def _run(argv: Sequence[str], cwd: Path, env: Mapping[str, str]) -> tuple[int, bytes]:
    """Run one bounded candidate subprocess; at most 4 KiB of stdout is returned."""

    return _run_bounded(argv, cwd, env, 4096)


def _run_catalog(argv: Sequence[str], cwd: Path, env: Mapping[str, str]) -> tuple[int, bytes]:
    """Run ``codex debug models --bundled``; stdout over the catalog bound reads as truncated."""

    return _run_bounded(argv, cwd, env, _CATALOG_MAX_BYTES + 1)


def _run_bounded(
    argv: Sequence[str], cwd: Path, env: Mapping[str, str], limit: int
) -> tuple[int, bytes]:
    """Run one bounded candidate subprocess; stdout is returned, stderr is discarded unread.

    The candidate leads its own new session, so it and every descendant it starts share one
    process group. Whatever happens (normal exit, timeout, or any other failure), that whole
    group is killed and the leader reaped before this returns, and the group must then be
    confirmed empty. A group that cannot be confirmed gone raises
    ``codex_capability_probe_cleanup_unconfirmed`` chained to the original failure, if any, so a
    probe failure never masks a lingering process.
    """

    process = subprocess.Popen(  # noqa: S603 - fixed argv on a selected local executable
        tuple(argv),
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    failure: BaseException | None = None
    stdout = b""
    try:
        stdout, _stderr = process.communicate(timeout=_SUBPROCESS_TIMEOUT_SECONDS)
    except BaseException as error:  # noqa: BLE001 - re-raised below after group cleanup
        failure = error
    confirmed = _kill_process_group(process)
    if not confirmed and (failure is None or isinstance(failure, Exception)):
        raise ValueError(CODEX_PROBE_CLEANUP_UNCONFIRMED) from failure
    if failure is not None:
        raise failure
    return cast(int, process.returncode), stdout[:limit]


def _kill_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Kill the candidate's whole process group, reap its leader, and confirm the group is gone."""

    group = process.pid
    confirmed = True
    try:
        os.killpg(group, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # Already gone, or (macOS) members still exiting; the bounded check below decides.
        pass
    except OSError:
        confirmed = False
    try:
        process.wait(timeout=_GROUP_CLEANUP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        confirmed = False
    if process.stdout is not None:
        process.stdout.close()
    return confirmed and _group_gone(group)


def _group_gone(group: int) -> bool:
    """Whether no live member of process group ``group`` remains, within a bounded grace.

    ``ESRCH`` confirms the group is empty. macOS briefly answers ``EPERM`` for a group whose
    killed members are still exiting, so ``EPERM`` is re-polled rather than taken as final; a
    member that genuinely survives (or genuinely cannot be signalled) keeps the group visible
    until the grace expires, which stays unconfirmed. The poll only observes: it never signals
    the numeric group again, because once the leader is reaped that id could in principle be
    reused by an unrelated group, and SIGKILL is not ignorable, so the one kill above suffices.
    """

    deadline = time.monotonic() + _GROUP_CLEANUP_GRACE_SECONDS
    while True:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        except OSError:
            return False
        else:
            if _only_zombies(group):
                # Killed members already exited; only their reaping (by init) is outstanding.
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _only_zombies(group: int) -> bool:
    """On Linux, whether every remaining member of ``group`` has already exited (zombie).

    An init that does not reap promptly (a minimal container PID 1) leaves exited members as
    zombies that still answer ``killpg(group, 0)``. Elsewhere this reports ``False`` and the
    bounded wait above decides.
    """

    proc = Path("/proc")
    if not proc.is_dir():
        return False
    members = 0
    try:
        entries = tuple(proc.iterdir())
    except OSError:
        return False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rpartition(")")[2].split()
        except OSError:
            continue
        if len(fields) < 3 or fields[2] != str(group):
            continue
        if fields[0] not in {"Z", "X"}:
            return False
        members += 1
    return members > 0


def _scratch_environment(home: Path) -> dict[str, str]:
    return {
        "CODEX_HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "RUST_LOG": "error",
    }


def _scratch(parent: Path) -> Path:
    try:
        scratch = Path(tempfile.mkdtemp(prefix=".probe-", dir=parent))
        os.chmod(scratch, 0o700)
        (scratch / "home").mkdir(mode=0o700)
    except OSError as error:
        raise ValueError("codex_evaluator_runtime_store_unavailable") from error
    return scratch


def codex_cli_version(
    executable: Path, *, scratch_parent: Path, runner: SubprocessRunner | None = None
) -> str:
    """Ask one candidate executable its version (``codex --version``) under a scratch home.

    Nothing is read from or written to any real Codex home; the scratch directory is removed.
    """

    scratch = _scratch(scratch_parent)
    try:
        try:
            code, output = (_run if runner is None else runner)(
                (str(executable), "--version"), scratch, _scratch_environment(scratch / "home")
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("codex_runtime_version_unknown") from error
        lines = output.decode("utf-8", errors="replace").splitlines()
        match = _CLI_VERSION.fullmatch(lines[0]) if code == 0 and lines else None
        if match is None:
            raise ValueError("codex_runtime_version_unknown")
        return match.group(1)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def codex_bundled_model_catalog(
    executable: Path, *, scratch_parent: Path, runner: SubprocessRunner | None = None
) -> object:
    """Have the candidate print the model catalog compiled into its bytes, and parse it.

    ``codex debug models --bundled`` serializes the bundled catalog without building a config,
    reading a login or touching the network; it runs under a scratch home that is removed. Any
    failure is the closed ``codex_bundled_catalog_unavailable`` token.
    """

    scratch = _scratch(scratch_parent)
    try:
        try:
            code, output = (_run_catalog if runner is None else runner)(
                (str(executable), "debug", "models", "--bundled"),
                scratch,
                _scratch_environment(scratch / "home"),
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("codex_bundled_catalog_unavailable") from error
        if code != 0 or not output or len(output) > _CATALOG_MAX_BYTES:
            raise ValueError("codex_bundled_catalog_unavailable")
        try:
            return json.loads(output.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as error:
            raise ValueError("codex_bundled_catalog_unavailable") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def generate_app_server_schema(
    executable: Path, *, scratch_parent: Path, runner: SubprocessRunner | None = None
) -> object:
    """Have the candidate write its app-server v2 schema into a scratch directory and parse it."""

    scratch = _scratch(scratch_parent)
    try:
        out = scratch / "schema"
        try:
            out.mkdir(mode=0o700)
            code, _output = (_run if runner is None else runner)(
                (
                    str(executable),
                    "app-server",
                    "generate-json-schema",
                    "--experimental",
                    "--out",
                    str(out),
                ),
                scratch,
                _scratch_environment(scratch / "home"),
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("codex_runtime_protocol_unavailable") from error
        if code != 0:
            raise ValueError("codex_runtime_protocol_unavailable")
        path = out / _SCHEMA_FILE
        try:
            facts = path.lstat()
            if not stat.S_ISREG(facts.st_mode) or not 0 < facts.st_size <= _SCHEMA_MAX_BYTES:
                raise ValueError("codex_runtime_protocol_unavailable")
            raw = path.read_bytes()
        except OSError as error:
            raise ValueError("codex_runtime_protocol_unavailable") from error
        try:
            # The generated schema carries float bounds (``minimum: 0.0``), which the strict
            # FinishUP JSON profile rejects; it is parsed as ordinary JSON and only its subset facts
            # (strings) enter the record digest.
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as error:
            raise ValueError("codex_runtime_protocol_unavailable") from error
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
