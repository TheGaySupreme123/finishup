"""Synthetic capability-checked Codex evaluator runtimes for unit tests.

No real Codex is run: a retained runtime is two synthetic files plus the capability record the
check would have committed for them, and the binding commits to that record's digest exactly as
setup and repair write it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

from yoetz.adapters.providers.codex_app_server import (
    CODEX_EVALUATOR_CONFIG,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CodexAppServerProfile,
)
from yoetz.adapters.providers.codex_capability import (
    CODEX_CODE_MODE_HOST_NAME,
    CodexCapabilityRecord,
    CodexPlatform,
    codex_platform_for,
    codex_source_identity,
    write_capability_record,
)
from yoetz.adapters.providers.data_use_catalog import data_use_record_for_endpoint
from yoetz.config.models import ExternalRuntimeProfileConfig
from yoetz.config.write import codex_subscription_runtime

__all__ = [
    "MAC",
    "LINUX",
    "SCHEMA_SUBSET_DIGEST",
    "binding_for",
    "minimal_app_server_schema",
    "plain_digest",
    "private_dirs",
    "profile_for",
    "record_for",
    "retained_runtime",
    "write_home",
]

MAC: CodexPlatform = codex_platform_for("darwin", "arm64")
LINUX: CodexPlatform = codex_platform_for("linux", "x86_64")
SCHEMA_SUBSET_DIGEST = "sha256:" + "5" * 64


def plain_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def record_for(
    executable: bytes,
    host: bytes,
    *,
    version: str = "0.159.0",
    platform: CodexPlatform = MAC,
) -> CodexCapabilityRecord:
    """The record a passed check would commit for these synthetic bytes."""

    return CodexCapabilityRecord(
        runtime_version=version,
        source_identity=codex_source_identity(platform, version),
        platform_os=platform.os,
        platform_architecture=platform.architecture,
        executable_sha256=plain_digest(executable),
        code_mode_host_sha256=plain_digest(host),
        app_server_schema_sha256=SCHEMA_SUBSET_DIGEST,
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
    )


def private_dirs(base: Path, directory: Path) -> None:
    """Create ``directory`` below ``base`` with every new component owner-only (0700)."""

    directory.mkdir(parents=True, exist_ok=True)
    current = directory
    while current != base and base in current.parents:
        current.chmod(0o700)
        current = current.parent


def retained_runtime(
    bundle: Path,
    *,
    version: str = "0.159.0",
    platform: CodexPlatform = MAC,
    executable: bytes = b"retained codex native bytes",
    host: bytes | None = b"retained codex code-mode host bytes",
    record: bool = True,
) -> tuple[Path, CodexCapabilityRecord]:
    """Write one retained release into ``bundle``'s store; return its executable and record."""

    identity = codex_source_identity(platform, version)
    directory = bundle / "external-runtimes" / "codex-evaluator" / identity
    private_dirs(bundle.parent, directory)
    bundle.chmod(0o700)
    path = directory / "codex"
    path.write_bytes(executable)
    path.chmod(0o500)
    if host is not None:
        sibling = directory / CODEX_CODE_MODE_HOST_NAME
        sibling.write_bytes(host)
        sibling.chmod(0o500)
    checked = record_for(executable, host or b"", version=version, platform=platform)
    if record:
        write_capability_record(directory, checked)
    return path, checked


def write_home(home: Path) -> Path:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    home.chmod(0o700)
    (home / "config.toml").write_bytes(CODEX_EVALUATOR_CONFIG.encode())
    return home


def binding_for(
    record: CodexCapabilityRecord,
    executable: Path,
    home: Path,
    **overrides: object,
) -> ExternalRuntimeProfileConfig:
    binding = codex_subscription_runtime(
        executable_path=str(executable),
        executable_sha256=record.executable_sha256,
        runtime_version=record.runtime_version,
        source_identity=record.source_identity,
        app_server_schema_sha256=record.app_server_schema_sha256,
        capability_cell_sha256=record.digest,
        isolated_config_sha256=record.isolated_config_sha256,
        capability_profile=record.capability_profile,
        capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        codex_home=str(home),
        model="gpt-5.6-sol",
        reasoning_effort="high",
    )
    return binding.model_copy(update=overrides)


def profile_for(
    record: CodexCapabilityRecord | None = None,
    *,
    executable: Path = Path("/opt/codex/0.159.0/codex"),
    home: Path = Path("/var/lib/yoetz/codex-0.150.1"),
    in_memory: bool = True,
    model: str = "gpt-5.6-sol",
    timeout_seconds: int = 30,
) -> CodexAppServerProfile:
    """An adapter profile for ``record`` (synthetic by default); no file needs to exist."""

    checked = record or record_for(b"profile codex", b"profile host")
    return CodexAppServerProfile(
        provider_id="openai-codex",
        endpoint_profile_id="codex-chatgpt-subscription",
        endpoint_profile_version="1.0.0",
        executable_path=executable,
        executable_sha256=checked.executable_sha256,
        runtime_version=checked.runtime_version,
        source_identity=checked.source_identity,
        app_server_schema_sha256=checked.app_server_schema_sha256,
        capability_cell_sha256=checked.digest,
        capability_profile=checked.capability_profile,
        capability_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
        codex_home=home,
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        model=model,
        reasoning_effort="high",
        timeout_seconds=timeout_seconds,
        data_use_profile=data_use_record_for_endpoint("codex-chatgpt-subscription").profile,
        capability_record=checked if in_memory else None,
    )


def minimal_app_server_schema() -> dict[str, object]:
    """The smallest generated-schema document that carries the reviewed subset.

    Real generated schemas (0.157.1, 0.159.0, 0.162.1) are hundreds of kilobytes; this keeps only
    what the structural check reads, so a test can remove or change exactly one fact.
    """

    from yoetz.adapters.providers.codex_capability import (
        _REVIEWED_SUBSET,  # pyright: ignore[reportPrivateUsage]
    )

    definitions: dict[str, dict[str, object]] = {}
    for kind, name, expectation in _REVIEWED_SUBSET:
        definition = definitions.setdefault(name, {})
        if kind == "methods":
            variants = cast(list[object], definition.setdefault("oneOf", []))
            for method in cast(tuple[str, ...], expectation):
                variants.append({"type": "object", "properties": {"method": {"enum": [method]}}})
        elif kind == "props":
            properties = cast(dict[str, object], definition.setdefault("properties", {}))
            for prop, expected in cast(dict[str, str], expectation).items():
                properties[prop] = {"type": [expected, "null"]}
        elif kind in {"values", "closed"}:
            definition["type"] = "string"
            definition["enum"] = list(cast(tuple[str, ...], expectation))
        elif kind == "variant":
            tag, props = cast(tuple[str, tuple[str, ...]], expectation)
            variants = cast(list[object], definition.setdefault("oneOf", []))
            variants.append(
                {
                    "type": "object",
                    "properties": {"type": {"enum": [tag]}, **{prop: {} for prop in props}},
                }
            )
    return {"definitions": definitions}
