"""Codex subscription setup binds only capability-checked, nonsecret runtime state."""

from __future__ import annotations

import inspect
import json
import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from builders.codex_capability import LINUX, MAC, binding_for, record_for
from yoetz.adapters.providers.codex_app_server import (
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    CodexRuntimeStatus,
)
from yoetz.adapters.providers.codex_capability import CodexCapabilityRecord, CodexPlatform
from yoetz.adapters.providers.codex_evaluator_runtime import (
    CodexBindingDiagnosis,
    managed_runtime_path,
)
from yoetz.cli import codex_subscription as module
from yoetz.config.models import ConfigError, ExternalRuntimeProfileConfig, YoetzConfig
from yoetz.config.write import render_config_toml


@pytest.fixture(autouse=True)
def _ambient_config_environment(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Resolve the default evaluator home from an empty configuration, not the ambient one.

    ``default_codex_home`` reads the process environment through the strict loader, which
    refuses every unknown ``YOETZ_``-prefixed variable. A developer machine can carry
    configuration overrides and its own ``config.toml``; neither is under test here, so every
    case starts from no ``YOETZ_`` variables and a config path that does not exist.
    """

    for name in tuple(os.environ):
        if name.startswith("YOETZ_"):
            monkeypatch.delenv(name)
    absent = tmp_path_factory.mktemp("config") / "absent.toml"
    monkeypatch.setenv("YOETZ_CONFIG", str(absent))
    # The retained evaluator runtime lives in the data bundle. No case may reach the invoking
    # user's real data directory, discover a real Codex on PATH, run a real capability check, or
    # download with a real npm (#855); a case that exercises any of them opts in explicitly.
    bundle = tmp_path_factory.mktemp("bundle")

    def runtime_bundle(_config: YoetzConfig | None = None) -> Path:
        return bundle

    monkeypatch.setattr(module, "runtime_bundle", runtime_bundle)
    _mock_macos_arm64_host(monkeypatch)

    # This module stubs runtime retention and the capability check; the store and the check
    # are covered by the adapter tests. Keep the real lock for the synthetic test bundle.
    def allow_private(_path: Path) -> None:
        return None

    monkeypatch.setattr(
        "yoetz.adapters.providers.codex_evaluator_runtime.verify_private_local_bundle",
        allow_private,
    )
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", lambda: ()
    )

    def no_download(**_kwargs: object) -> Path:
        raise AssertionError("unit tests never download a real evaluator runtime")

    def candidates(
        _config: YoetzConfig, *, executable: Path | None = None
    ) -> tuple[module.EvaluatorCandidate, ...]:
        selected = Path("/opt/codex/0.159.0/codex") if executable is None else executable
        source = "discovered" if executable is None else "selected"
        return (module.EvaluatorCandidate(source, selected, "0.159.0"),)

    async def checked(candidate: module.EvaluatorCandidate, *, bundle: Path) -> object:
        record = record_for(b"codex", b"host", version=candidate.version)
        return module._Checked(  # pyright: ignore[reportPrivateUsage]
            candidate, managed_runtime_path(bundle, record.source_identity), record
        )

    monkeypatch.setattr(module, "provision_codex_runtime", no_download)
    monkeypatch.setattr(module, "evaluator_candidates", candidates)
    monkeypatch.setattr(module, "_check_candidate", checked)


def _assume_structurally_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """Treat a synthetic binding as structurally ready; its paths are never real executables."""

    def ready(_binding: ExternalRuntimeProfileConfig) -> CodexBindingDiagnosis:
        return CodexBindingDiagnosis("ready", "current", "admitted", "ready")

    monkeypatch.setattr(module, "diagnose_bound_runtime", ready)


def _binding(executable: Path, home: Path) -> ExternalRuntimeProfileConfig:
    return binding_for(record_for(b"codex", b"host"), executable, home)


async def _logged_out_probe(_profile: object) -> CodexRuntimeStatus:
    """The pre-login readiness probe for a dedicated home Codex reports as logged out."""

    return CodexRuntimeStatus(True, None, None, False, "terminated")


def _stub_setup_persistence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    binding: ExternalRuntimeProfileConfig,
    written: list[object],
) -> None:
    """Replace every local persistence step of ``setup`` with recording stubs."""

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    def build_profile(_binding: ExternalRuntimeProfileConfig) -> object:
        return object()

    def write_binding(_config: YoetzConfig, **_kwargs: object) -> Path:
        written.append(binding)
        return tmp_path / "config.toml"

    def snapshot(_path: Path) -> tuple[YoetzConfig, bytes | None]:
        return YoetzConfig(), None

    def preflight(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    def prepare(_home: Path) -> None:
        return None

    monkeypatch.setattr(module, "_binding", build_binding)
    monkeypatch.setattr(module, "_profile", build_profile)
    monkeypatch.setattr(module, "_config_snapshot", snapshot)
    monkeypatch.setattr(module, "preflight_config_write", preflight)
    monkeypatch.setattr(module, "prepare_codex_home", prepare)
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", write_binding)


async def _run_setup(
    tmp_path: Path, *, switch_account: bool = False, config_path: Path | None = None
) -> Mapping[str, object]:
    return await module.codex_subscription_setup(
        executable=tmp_path / "codex",
        codex_home=tmp_path / "dedicated-home",
        model="gpt-5.6-sol",
        reasoning_effort="high",
        login_mode="browser",
        open_browser=False,
        switch_account=switch_account,
        config_path=config_path,
    )


def _write_codex_package_layout(
    root: Path,
    *,
    nested: bool,
    platform: CodexPlatform = MAC,
    version: str = "0.159.0",
    native_manifest: Mapping[str, object] | None = None,
    wrapper_manifest: Mapping[str, object] | None = None,
    native_bytes: bytes = b"native-codex",
    code_mode_host: bytes | None = b"code-mode-host",
) -> tuple[Path, Path]:
    wrapper_root = root / "node_modules" / "@openai" / "codex"
    wrapper_bin = wrapper_root / "bin"
    wrapper_bin.mkdir(parents=True, exist_ok=True)
    wrapper = wrapper_bin / "codex.js"
    wrapper.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    wrapper_document: Mapping[str, object] = (
        {
            "name": "@openai/codex",
            "version": version,
            "bin": {"codex": "bin/codex.js"},
            "optionalDependencies": {
                f"@openai/{platform.native_package_directory}": platform.native_package_spec(
                    version
                )
            },
        }
        if wrapper_manifest is None
        else wrapper_manifest
    )
    (wrapper_root / "package.json").write_text(json.dumps(wrapper_document), encoding="utf-8")

    native_root = (
        wrapper_root / "node_modules" / "@openai" / platform.native_package_directory
        if nested
        else wrapper_root.parent / platform.native_package_directory
    )
    native_bin = native_root / platform.native_executable_relative.parent
    native_bin.mkdir(parents=True, exist_ok=True)
    native = native_bin / "codex"
    native.write_bytes(native_bytes)
    native.chmod(0o700)
    if code_mode_host is not None:
        host = native_bin / "codex-code-mode-host"
        host.write_bytes(code_mode_host)
        host.chmod(0o700)
    native_document: Mapping[str, object] = (
        {
            "name": "@openai/codex",
            "version": platform.native_package_version(version),
            "os": [platform.os],
            "cpu": [platform.npm_cpu],
        }
        if native_manifest is None
        else native_manifest
    )
    (native_root / "package.json").write_text(json.dumps(native_document), encoding="utf-8")
    return wrapper, native


def _mock_macos_arm64_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep Mac fixtures coherent when this slice runs on Linux CI."""

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("platform.machine", lambda: "arm64")


def _mock_linux_x64_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")


def _cli_version(version: str) -> object:
    def probe(_native: Path) -> str:
        if version == "unknown":
            raise ValueError("codex_runtime_version_unknown")
        return version

    return probe


def _layout(wrapper: Path, platform: CodexPlatform = MAC) -> tuple[Path, str]:
    return module._resolve_codex_package_layout(wrapper, platform)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("platform_os", "architecture"),
    [("darwin", "x86_64"), ("linux", "aarch64"), ("win32", "AMD64")],
)
def test_unsupported_host_fails_before_any_file_access(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform_os: str, architecture: str
) -> None:
    monkeypatch.setattr(sys, "platform", platform_os)
    monkeypatch.setattr("platform.machine", lambda: architecture)

    with pytest.raises(ValueError, match="^codex_runtime_platform_unsupported$"):
        module.resolve_codex_executable(tmp_path / "missing" / "codex")


def test_codex_package_layout_resolves_nested_optional_dependency(tmp_path: Path) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=True)

    assert _layout(wrapper) == (native, "0.159.0")


def test_codex_package_layout_resolves_npm_prefix_hoisted_sibling(tmp_path: Path) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=False, version="0.162.1")

    assert _layout(wrapper) == (native, "0.162.1")


def test_codex_package_layout_nested_candidate_has_deterministic_precedence(
    tmp_path: Path,
) -> None:
    wrapper, nested_native = _write_codex_package_layout(
        tmp_path, nested=True, native_bytes=b"nested"
    )
    _, hoisted_native = _write_codex_package_layout(tmp_path, nested=False, native_bytes=b"hoisted")

    assert nested_native != hoisted_native
    assert _layout(wrapper)[0] == nested_native


def test_codex_package_layout_does_not_fall_back_after_invalid_nested_candidate(
    tmp_path: Path,
) -> None:
    wrapper, _ = _write_codex_package_layout(
        tmp_path,
        nested=True,
        native_manifest={
            "name": "@openai/codex",
            "version": "0.0.0-darwin-arm64",
            "os": ["darwin"],
            "cpu": ["arm64"],
        },
    )
    _write_codex_package_layout(tmp_path, nested=False)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


@pytest.mark.parametrize(
    ("manifest_kind", "field", "value", "token"),
    [
        ("wrapper", "name", "@openai/not-codex", "codex_runtime_capability_unsupported"),
        # Below the floor, or not a stable release: never eligible, whatever the layout.
        ("wrapper", "version", "0.153.4", "codex_runtime_version_unsupported"),
        ("wrapper", "version", "0.163.0-alpha.9", "codex_runtime_version_unsupported"),
        ("wrapper", "bin", {"codex": "other.js"}, "codex_runtime_capability_unsupported"),
        ("wrapper", "optionalDependencies", {}, "codex_runtime_capability_unsupported"),
        ("native", "name", "@openai/not-codex", "codex_runtime_capability_unsupported"),
        ("native", "version", "0.162.1-darwin-arm64", "codex_runtime_capability_unsupported"),
        ("native", "os", ["linux"], "codex_runtime_capability_unsupported"),
        ("native", "cpu", ["x64"], "codex_runtime_capability_unsupported"),
    ],
)
def test_codex_package_layout_rejects_mismatched_package_metadata(
    tmp_path: Path, manifest_kind: str, field: str, value: object, token: str
) -> None:
    if manifest_kind == "wrapper":
        wrapper_manifest: dict[str, object] = {
            "name": "@openai/codex",
            "version": "0.159.0",
            "bin": {"codex": "bin/codex.js"},
            "optionalDependencies": {
                "@openai/codex-darwin-arm64": MAC.native_package_spec("0.159.0")
            },
        }
        wrapper_manifest[field] = value
        wrapper, _ = _write_codex_package_layout(
            tmp_path, nested=True, wrapper_manifest=wrapper_manifest
        )
    else:
        native_manifest: dict[str, object] = {
            "name": "@openai/codex",
            "version": MAC.native_package_version("0.159.0"),
            "os": ["darwin"],
            "cpu": ["arm64"],
        }
        native_manifest[field] = value
        wrapper, _ = _write_codex_package_layout(
            tmp_path, nested=True, native_manifest=native_manifest
        )

    with pytest.raises(ValueError, match=token):
        _layout(wrapper)


def test_codex_package_layout_does_not_search_ancestors_or_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    selected_root = tmp_path / "selected"
    wrapper, native = _write_codex_package_layout(selected_root, nested=True)
    shutil.rmtree(native.parents[3])
    ancestor_native = selected_root / "node_modules" / "codex-darwin-arm64"
    ancestor_native.mkdir(parents=True)
    path_native = tmp_path / "path-entry" / "codex"
    path_native.parent.mkdir()
    path_native.write_bytes(b"path-native")
    path_native.chmod(0o700)
    monkeypatch.setenv("PATH", str(path_native.parent))

    with pytest.raises(ValueError, match="codex_runtime_not_found"):
        _layout(wrapper)


def test_codex_package_layout_rejects_native_executable_symlink_escape(tmp_path: Path) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=True)
    outside = tmp_path / "outside-codex"
    outside.write_bytes(b"outside")
    outside.chmod(0o700)
    native.unlink()
    native.symlink_to(outside)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


def test_codex_package_layout_rejects_native_package_symlink_escape(tmp_path: Path) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=True)
    native_root = native.parents[3]
    outside_root = tmp_path / "outside-native-package"
    native_root.rename(outside_root)
    native_root.symlink_to(outside_root, target_is_directory=True)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


def test_codex_package_layout_rejects_same_parent_native_package_symlink(
    tmp_path: Path,
) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=True)
    native_root = native.parents[3]
    sibling_root = native_root.with_name("codex-darwin-arm64-real")
    native_root.rename(sibling_root)
    native_root.symlink_to(sibling_root, target_is_directory=True)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


def test_codex_package_layout_rejects_intermediate_dependency_symlink_escape(
    tmp_path: Path,
) -> None:
    wrapper, _native = _write_codex_package_layout(tmp_path, nested=True)
    dependency_root = wrapper.parent.parent / "node_modules"
    outside_root = tmp_path / "outside-dependencies"
    dependency_root.rename(outside_root)
    dependency_root.symlink_to(outside_root, target_is_directory=True)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


@pytest.mark.parametrize("manifest_owner", ["wrapper", "native"])
def test_codex_package_layout_rejects_symlinked_manifest(
    tmp_path: Path, manifest_owner: str
) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=True)
    package_root = wrapper.parent.parent if manifest_owner == "wrapper" else native.parents[3]
    manifest = package_root / "package.json"
    outside = tmp_path / f"outside-{manifest_owner}.json"
    manifest.rename(outside)
    manifest.symlink_to(outside)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


def test_codex_package_layout_rejects_oversized_manifest_before_parsing(tmp_path: Path) -> None:
    wrapper, _native = _write_codex_package_layout(tmp_path, nested=True)
    (wrapper.parent.parent / "package.json").write_bytes(
        b" " * (module._CODEX_PACKAGE_JSON_MAX_BYTES + 1)  # pyright: ignore[reportPrivateUsage]
    )

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        _layout(wrapper)


@pytest.mark.parametrize(
    ("reported", "token"),
    [
        ("0.159.0", None),
        ("0.162.1", None),
        ("0.153.4", "codex_runtime_version_unsupported"),
        ("unknown", "codex_runtime_version_unknown"),
    ],
)
def test_a_direct_native_executable_is_versioned_by_asking_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reported: str, token: str | None
) -> None:
    native = tmp_path / "vendor" / "aarch64-apple-darwin" / "bin" / "codex"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"native")
    native.chmod(0o700)
    (native.parent / "codex-code-mode-host").write_bytes(b"host")
    (native.parent / "codex-code-mode-host").chmod(0o700)
    monkeypatch.setattr(module, "_codex_cli_version", _cli_version(reported))

    if token is None:
        resolved = module.resolve_codex_executable(native)
        assert (resolved.native, resolved.version, resolved.platform) == (native, reported, MAC)
        assert resolved.source_identity == f"openai-codex-npm-darwin-arm64-{reported}"
    else:
        with pytest.raises(ValueError, match=token):
            module.resolve_codex_executable(native)


def test_a_wrapper_is_versioned_from_its_manifests_without_running_anything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_linux_x64_host(monkeypatch)
    wrapper, native = _write_codex_package_layout(
        tmp_path, nested=True, platform=LINUX, version="0.162.1"
    )

    def forbidden(_native: Path) -> str:
        raise AssertionError("a wrapper's release comes from its manifests")

    monkeypatch.setattr(module, "_codex_cli_version", forbidden)

    resolved = module.resolve_codex_executable(wrapper)

    assert (resolved.native, resolved.version, resolved.platform) == (native, "0.162.1", LINUX)
    assert resolved.source_identity == "openai-codex-npm-linux-x64-0.162.1"


@pytest.mark.parametrize("layout", ["nested", "hoisted", "native"])
@pytest.mark.parametrize(
    ("host", "mode", "token"),
    [
        (b"code-mode-host", 0o700, None),
        (None, 0o700, "codex_runtime_code_mode_host_missing"),
        (b"code-mode-host", 0o600, "codex_runtime_executable_invalid"),
    ],
)
def test_every_supported_layout_requires_the_code_mode_host_beside_codex(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    layout: str,
    host: bytes | None,
    mode: int,
    token: str | None,
) -> None:
    """Nested, hoisted, and native selections all resolve the sibling Codex starts (#874)."""

    _mock_linux_x64_host(monkeypatch)
    wrapper, native = _write_codex_package_layout(
        tmp_path, nested=layout != "hoisted", platform=LINUX, code_mode_host=host
    )
    if host is not None:
        (native.parent / "codex-code-mode-host").chmod(mode)
    monkeypatch.setattr(module, "_codex_cli_version", _cli_version("0.159.0"))
    selected = native if layout == "native" else wrapper

    if token is None:
        assert module.resolve_codex_executable(selected).native == native
    else:
        with pytest.raises(ValueError, match=token):
            module.resolve_codex_executable(selected)


def test_preview_resolves_the_selected_runtime_without_creating_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    wrapper, native = _write_codex_package_layout(tmp_path, nested=True, version="0.162.1")
    home = tmp_path / "dedicated-home"

    preview = module.codex_subscription_preview(
        executable=wrapper,
        codex_home=home,
        model="gpt-6.1-sol",
        reasoning_effort="max",
    )

    assert preview["credential_authority"] == "external_runtime_oauth"
    assert preview["runtime_version"] == "0.162.1"
    assert preview["runtime_floor"] == "0.157.1"
    assert preview["runtime_source_identity"] == "openai-codex-npm-darwin-arm64-0.162.1"
    assert preview["capability_profile"] == CODEX_EVALUATOR_CAPABILITY_PROFILE
    assert preview["capability_evidence_expires_at"] == CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT
    assert preview["upstream_body_observability"] == "unavailable"
    assert preview["executable_path"] == str(native)
    assert preview["reasoning_effort"] == "max"
    assert not home.exists()
    assert "token" not in repr(preview).casefold()


def test_a_same_name_executable_that_is_not_codex_is_never_eligible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"#!/bin/sh\necho not codex\n")
    executable.chmod(0o700)
    monkeypatch.setattr(module, "_codex_cli_version", _cli_version("unknown"))

    with pytest.raises(ValueError, match="codex_runtime_version_unknown"):
        module.resolve_codex_executable(executable)


def test_environment_selected_config_path_is_used_for_reads_and_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    selected = tmp_path / "isolated" / "config.toml"
    monkeypatch.setenv("YOETZ_CONFIG", str(selected))

    assert module._target_config_path(None) == selected  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_setup_persists_binding_only_after_codex_confirms_chatgpt_readiness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "codex"
    home = tmp_path / "dedicated-home"
    binding = _binding(executable, home)
    written: list[object] = []

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    def build_profile(_binding: ExternalRuntimeProfileConfig) -> object:
        return object()

    def write_binding(_config: YoetzConfig, **_kwargs: object) -> Path:
        written.append(binding)
        return tmp_path / "config.toml"

    def snapshot(_path: Path) -> tuple[YoetzConfig, bytes | None]:
        return YoetzConfig(), None

    def preflight(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    def prepare(_home: Path) -> None:
        return None

    monkeypatch.setattr(module, "_binding", build_binding)
    monkeypatch.setattr(module, "_profile", build_profile)

    monkeypatch.setattr(module, "_config_snapshot", snapshot)
    monkeypatch.setattr(module, "preflight_config_write", preflight)
    monkeypatch.setattr(module, "prepare_codex_home", prepare)

    async def login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    monkeypatch.setattr(module, "codex_account_status", _logged_out_probe)
    monkeypatch.setattr(module, "codex_login", login)
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", write_binding)

    result = await module.codex_subscription_setup(
        executable=executable,
        codex_home=home,
        model="gpt-5.6-sol",
        reasoning_effort="high",
        login_mode="browser",
        open_browser=False,
        switch_account=False,
    )

    assert written == [binding]
    assert result["auth_mode"] == "chatgpt"
    assert result["plan_type"] == "plus"
    assert result["process_cleanup"] == "terminated"


@pytest.mark.anyio
async def test_setup_failure_never_writes_a_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    def build_profile(_binding: ExternalRuntimeProfileConfig) -> object:
        return object()

    def forbidden_write(*_args: object, **_kwargs: object) -> Path:
        pytest.fail("failed readiness must not persist a binding")

    def snapshot(_path: Path) -> tuple[YoetzConfig, bytes | None]:
        return YoetzConfig(), None

    def preflight(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    def prepare(_home: Path) -> None:
        return None

    monkeypatch.setattr(module, "_binding", build_binding)
    monkeypatch.setattr(module, "_profile", build_profile)

    monkeypatch.setattr(module, "_config_snapshot", snapshot)
    monkeypatch.setattr(module, "preflight_config_write", preflight)
    monkeypatch.setattr(module, "prepare_codex_home", prepare)

    async def login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, None, None, False, "terminated")

    monkeypatch.setattr(module, "codex_account_status", _logged_out_probe)
    monkeypatch.setattr(module, "codex_login", login)
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", forbidden_write)

    with pytest.raises(ValueError, match="codex_subscription_readiness_unproven"):
        await module.codex_subscription_setup(
            executable=tmp_path / "codex",
            codex_home=tmp_path / "dedicated-home",
            model="gpt-5.6-sol",
            reasoning_effort="high",
            login_mode="browser",
            open_browser=False,
            switch_account=False,
        )


@pytest.mark.anyio
async def test_setup_preserves_a_concurrent_config_edit_during_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "config.toml"
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    def build_profile(_binding: ExternalRuntimeProfileConfig) -> object:
        return object()

    def prepare(_home: Path) -> None:
        return None

    monkeypatch.setattr(module, "_binding", build_binding)
    monkeypatch.setattr(module, "_profile", build_profile)
    monkeypatch.setattr(module, "prepare_codex_home", prepare)

    async def login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        target.write_text("# concurrent config edit\n", encoding="utf-8")
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    monkeypatch.setattr(module, "codex_account_status", _logged_out_probe)
    monkeypatch.setattr(module, "codex_login", login)

    with pytest.raises(ValueError, match="config_preimage_mismatch"):
        await module.codex_subscription_setup(
            executable=tmp_path / "codex",
            codex_home=tmp_path / "dedicated-home",
            model="gpt-5.6-sol",
            reasoning_effort="high",
            login_mode="browser",
            open_browser=False,
            switch_account=False,
            config_path=target,
        )

    assert target.read_text(encoding="utf-8") == "# concurrent config edit\n"


@pytest.mark.anyio
async def test_disconnect_confirms_logout_before_removing_only_the_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assume_structurally_ready(monkeypatch)
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    config = YoetzConfig(profile="codex-subscription", external_runtime=binding)
    removed: list[object] = []

    def build_profile(_binding: ExternalRuntimeProfileConfig) -> object:
        return object()

    def clear_binding(_config: YoetzConfig, **_kwargs: object) -> Path:
        removed.append(binding)
        return tmp_path / "config.toml"

    def snapshot(_path: Path) -> tuple[YoetzConfig, bytes | None]:
        return config, b"before"

    def preflight(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    monkeypatch.setattr(module, "_config_snapshot", snapshot)
    monkeypatch.setattr(module, "preflight_config_write", preflight)
    monkeypatch.setattr(module, "_profile", build_profile)

    async def logout(_profile: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, None, None, False, "terminated")

    monkeypatch.setattr(module, "codex_logout", logout)
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", clear_binding)

    result = await module.codex_subscription_disconnect(config_path=tmp_path / "config.toml")

    assert removed == [binding]
    assert result["binding_removed"] is True
    assert result["process_cleanup"] == "terminated"


@pytest.mark.anyio
async def test_disconnect_preserves_a_concurrent_config_edit_during_logout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assume_structurally_ready(monkeypatch)
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    target = _bound_config_file(tmp_path, binding)
    before = target.read_text(encoding="utf-8")

    async def logout(_profile: object) -> CodexRuntimeStatus:
        target.write_text(before + "# concurrent config edit\n", encoding="utf-8")
        return CodexRuntimeStatus(True, None, None, False, "terminated")

    monkeypatch.setattr(module, "codex_logout", logout)

    with pytest.raises(ValueError, match="config_preimage_mismatch"):
        await module.codex_subscription_disconnect(config_path=target)

    assert target.read_text(encoding="utf-8") == before + "# concurrent config edit\n"


def test_rollback_preserves_the_dedicated_home_and_installation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    config = YoetzConfig(profile="codex-subscription", external_runtime=binding)

    def clear_binding(_config: YoetzConfig, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    def snapshot(_path: Path) -> tuple[YoetzConfig, bytes | None]:
        return config, b"before"

    monkeypatch.setattr(module, "_config_snapshot", snapshot)
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", clear_binding)

    result = module.codex_subscription_rollback(config_path=tmp_path / "config.toml")

    assert result["binding_removed"] is True
    assert result["codex_home_preserved"] == str(tmp_path / "dedicated-home")
    assert result["codex_installation_preserved"] is True


def test_subscription_failure_reason_never_echoes_native_os_text() -> None:
    missing = FileNotFoundError(2, "No such file or directory", "/secret/codex")
    denied = PermissionError(13, "Permission denied", "/secret/codex")

    assert module.subscription_failure_reason(missing) == "codex_runtime_not_found"
    assert module.subscription_failure_reason(denied) == "codex_runtime_unavailable"
    assert module.subscription_failure_reason(TimeoutError()) == "codex_subscription_timeout"
    assert (
        module.subscription_failure_reason(ConfigError("config_value_invalid"))
        == "config_value_invalid"
    )
    assert (
        module.subscription_failure_reason(ValueError("codex_runtime_capability_unsupported"))
        == "codex_runtime_capability_unsupported"
    )
    assert "secret" not in module.subscription_failure_reason(missing)
    assert "Permission denied" not in module.subscription_failure_reason(denied)


def test_missing_executable_is_a_closed_token(tmp_path: Path) -> None:
    missing = tmp_path / "no-such-codex"

    with pytest.raises(ValueError, match="codex_runtime_not_found"):
        module.resolve_codex_executable(missing)


def test_cli_setup_maps_missing_executable_without_echoing_the_path(tmp_path: Path) -> None:
    from yoetz.cli.app import app

    missing = tmp_path / "no-such-codex"
    result = CliRunner().invoke(
        app,
        [
            "provider",
            "codex-subscription",
            "setup",
            "--executable",
            str(missing),
            "--accept",
        ],
    )

    assert result.exit_code == 20
    assert "codex_runtime_not_found" in result.stderr
    assert str(missing) not in result.stderr
    assert "No such file" not in result.stderr


def test_cli_setup_disconnect_and_rollback_recompose_the_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_macos_arm64_host(monkeypatch)
    from yoetz.cli.app import app

    restarts: list[str] = []

    def resolve(selected: Path) -> module.ResolvedCodex:
        return module.ResolvedCodex(selected, "0.159.0", MAC)

    async def setup(**_kwargs: object) -> dict[str, object]:
        return {"schema": "yoetz.codex-subscription-status/1", "model_available": True}

    async def disconnect(**_kwargs: object) -> dict[str, object]:
        return {"binding_removed": True, "process_cleanup": "terminated"}

    def rollback(**_kwargs: object) -> dict[str, object]:
        return {"binding_removed": True, "codex_installation_preserved": True}

    async def restart() -> dict[str, object]:
        restarts.append("restart")
        return {"reachable": True, "state": "ready", "vault_mode": None}

    monkeypatch.setattr(module, "resolve_codex_executable", resolve)
    monkeypatch.setattr(module, "codex_subscription_setup", setup)
    monkeypatch.setattr(module, "codex_subscription_disconnect", disconnect)
    monkeypatch.setattr(module, "codex_subscription_rollback", rollback)
    monkeypatch.setattr(
        "yoetz.cli.setup.restart_service_for_semantic_composition",
        restart,
    )

    runner = CliRunner()
    executable = tmp_path / "codex"
    setup_result = runner.invoke(
        app,
        [
            "provider",
            "codex-subscription",
            "setup",
            "--executable",
            str(executable),
            "--accept",
            "--no-open-browser",
        ],
    )
    disconnect_result = runner.invoke(
        app,
        ["provider", "codex-subscription", "disconnect", "--accept"],
    )
    rollback_result = runner.invoke(app, ["provider", "codex-subscription", "rollback"])

    assert setup_result.exit_code == 0
    assert disconnect_result.exit_code == 0
    assert rollback_result.exit_code == 0
    assert restarts == ["restart", "restart", "restart"]


def test_menu_disconnect_and_rollback_recompose_the_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.cli import menu

    restarts: list[str] = []

    async def disconnect(**_kwargs: object) -> dict[str, object]:
        return {"binding_removed": True}

    def rollback(**_kwargs: object) -> dict[str, object]:
        return {"binding_removed": True}

    async def restart() -> dict[str, object]:
        restarts.append("restart")
        return {"reachable": True}

    def ask_disconnect(_choices: object) -> str:
        return "6"

    def always_confirm(*_args: object, **_kwargs: object) -> bool:
        return True

    def hide(_value: object) -> None:
        return None

    monkeypatch.setattr(menu, "_ask", ask_disconnect)
    monkeypatch.setattr("typer.confirm", always_confirm)
    monkeypatch.setattr(module, "codex_subscription_disconnect", disconnect)
    monkeypatch.setattr(
        "yoetz.cli.setup.restart_service_for_semantic_composition",
        restart,
    )
    monkeypatch.setattr(menu, "_show", hide)

    menu._provider_menu()  # pyright: ignore[reportPrivateUsage]

    def ask_rollback(_choices: object) -> str:
        return "7"

    monkeypatch.setattr(menu, "_ask", ask_rollback)
    monkeypatch.setattr(module, "codex_subscription_rollback", rollback)
    menu._provider_menu()  # pyright: ignore[reportPrivateUsage]

    assert restarts == ["restart", "restart"]


def test_guided_setup_offers_account_switch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(module, "default_codex_evaluator_executable", lambda: tmp_path / "codex")
    prompts = iter(
        [
            str(tmp_path / "codex"),
            str(tmp_path / "home"),
            "gpt-5.6-luna",
            "high",
            "medium",
            "browser",
        ]
    )
    confirms: list[str] = []
    prompt_defaults: dict[str, object] = {}

    def prompt(message: str, **kwargs: object) -> str:
        if "default" in kwargs:
            prompt_defaults[message] = kwargs["default"]
        return next(prompts)

    def confirm(message: str, **_kwargs: object) -> bool:
        confirms.append(message)
        return True

    captured: list[bool] = []

    async def setup(**kwargs: object) -> dict[str, object]:
        captured.append(bool(kwargs["switch_account"]))
        return {"auth_mode": "chatgpt"}

    def preview(**_kwargs: object) -> dict[str, str]:
        return {
            "executable_path": "/opt/codex",
            "executable_sha256": "sha256:" + "a" * 64,
            "code_mode_host_sha256": "sha256:" + "c" * 64,
            "runtime_version": "0.159.0",
            "runtime_floor": "0.157.1",
            "runtime_source_identity": "openai-codex-npm-darwin-arm64-0.159.0",
            "capability_profile": "codex-evaluator/capability/v2",
            "capability_evidence_expires_at": "2026-11-30T00:00:00Z",
            "codex_home": "/home",
            "disconnect_command": "yoetz provider codex-subscription disconnect",
            "rollback_command": "yoetz provider codex-subscription rollback",
        }

    monkeypatch.setattr("yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", list)
    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr("typer.confirm", confirm)
    monkeypatch.setattr(module, "codex_subscription_preview", preview)
    monkeypatch.setattr(module, "codex_subscription_setup", setup)

    import anyio

    anyio.run(module.prompt_codex_subscription_setup)

    assert prompt_defaults["Exact model"] == "gpt-6-luna"
    assert prompt_defaults["Final review reasoning effort"] == "high"
    assert any(item.startswith("Continue to Codex sign-in") for item in confirms)
    assert any("switch ChatGPT account" in item for item in confirms)
    assert captured == [True]


def test_guided_setup_preserves_existing_model_when_switching_accounts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(module, "default_codex_evaluator_executable", lambda: tmp_path / "codex")
    prompts = iter(
        [
            str(tmp_path / "codex"),
            str(tmp_path / "home"),
            "high",
            "medium",
            "browser",
        ]
    )
    setup_args: list[tuple[object, object]] = []

    def prompt(message: str, **kwargs: object) -> str:
        if message == "Exact model":
            assert kwargs["default"] == "gpt-5.6-sol"
            return str(kwargs["default"])
        return next(prompts)

    def confirm(_message: str, **_kwargs: object) -> bool:
        return True

    async def setup(**kwargs: object) -> dict[str, object]:
        setup_args.append((kwargs["model"], kwargs["switch_account"]))
        return {"auth_mode": "chatgpt"}

    def preview(**kwargs: object) -> dict[str, str]:
        assert kwargs["model"] == "gpt-5.6-sol"
        return {
            "executable_path": "/opt/codex",
            "executable_sha256": "sha256:" + "a" * 64,
            "code_mode_host_sha256": "sha256:" + "c" * 64,
            "runtime_version": "0.159.0",
            "runtime_floor": "0.157.1",
            "runtime_source_identity": "openai-codex-npm-darwin-arm64-0.159.0",
            "capability_profile": "codex-evaluator/capability/v2",
            "capability_evidence_expires_at": "2026-11-30T00:00:00Z",
            "codex_home": "/home",
            "disconnect_command": "yoetz provider codex-subscription disconnect",
            "rollback_command": "yoetz provider codex-subscription rollback",
        }

    monkeypatch.setattr("yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", list)
    monkeypatch.setattr(module, "default_codex_subscription_model", lambda: "gpt-5.6-sol")
    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr("typer.confirm", confirm)
    monkeypatch.setattr(module, "codex_subscription_preview", preview)
    monkeypatch.setattr(module, "codex_subscription_setup", setup)

    import anyio

    anyio.run(module.prompt_codex_subscription_setup)

    assert setup_args == [("gpt-5.6-sol", True)]


def test_guided_setup_discloses_login_reuse_before_the_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The prompt-loop screen must say a signed-in home is reused before asking to continue."""

    prompts = iter(
        [
            str(tmp_path / "codex"),
            str(tmp_path / "home"),
            "gpt-5.6-luna",
            "high",
            "medium",
            "browser",
        ]
    )
    disclosed_before_confirm: list[bool] = []

    def prompt(message: str, **kwargs: object) -> str:
        del kwargs
        return next(prompts)

    def confirm(message: str, **_kwargs: object) -> bool:
        if message.startswith("Continue to Codex sign-in"):
            disclosed_before_confirm.append(
                "reused without a new sign-in" in capsys.readouterr().out
            )
            return True
        return False

    async def setup(**_kwargs: object) -> dict[str, object]:
        return {"auth_mode": "chatgpt", "login_reused": False}

    def preview(**_kwargs: object) -> dict[str, str]:
        return {
            "executable_path": "/opt/codex",
            "executable_sha256": "sha256:" + "a" * 64,
            "code_mode_host_sha256": "sha256:" + "c" * 64,
            "runtime_version": "0.159.0",
            "runtime_floor": "0.157.1",
            "runtime_source_identity": "openai-codex-npm-darwin-arm64-0.159.0",
            "capability_profile": "codex-evaluator/capability/v2",
            "capability_evidence_expires_at": "2026-11-30T00:00:00Z",
            "codex_home": "/home",
            "disconnect_command": "yoetz provider codex-subscription disconnect",
            "rollback_command": "yoetz provider codex-subscription rollback",
        }

    monkeypatch.setattr("yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", list)
    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr("typer.confirm", confirm)
    monkeypatch.setattr(module, "codex_subscription_preview", preview)
    monkeypatch.setattr(module, "codex_subscription_setup", setup)

    import anyio

    anyio.run(module.prompt_codex_subscription_setup)

    assert disclosed_before_confirm == [True]


def test_cli_setup_discloses_reuse_and_names_its_override_before_the_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The `setup` notice must state reuse and the flag that forces a fresh sign-in (#534)."""

    _mock_macos_arm64_host(monkeypatch)
    from yoetz.cli.app import app

    def resolve(selected: Path) -> module.ResolvedCodex:
        return module.ResolvedCodex(selected, "0.159.0", MAC)

    selected_models: list[object] = []

    async def setup(**kwargs: object) -> dict[str, object]:
        selected_models.append(kwargs["model"])
        return {"schema": "yoetz.codex-subscription-status/1", "login_reused": True}

    async def restart() -> dict[str, object]:
        return {"reachable": True, "state": "ready", "vault_mode": None}

    monkeypatch.setattr(module, "resolve_codex_executable", resolve)
    monkeypatch.setattr(module, "default_codex_subscription_model", lambda: "gpt-5.6-sol")
    monkeypatch.setattr(module, "codex_subscription_setup", setup)
    monkeypatch.setattr("yoetz.cli.setup.restart_service_for_semantic_composition", restart)

    runner = CliRunner()
    arguments = [
        "provider",
        "codex-subscription",
        "setup",
        "--executable",
        str(tmp_path / "codex"),
        "--accept",
        "--no-open-browser",
    ]
    reuse = runner.invoke(app, arguments)
    switch = runner.invoke(app, [*arguments, "--switch-account"])

    assert reuse.exit_code == 0
    assert "existing sign-in: reused when Codex reports the home already signed in" in reuse.stdout
    assert "--switch-account" in reuse.stdout
    assert '"login_reused":true' in reuse.stdout
    assert switch.exit_code == 0
    assert "existing sign-in: logged out first, then a new Codex sign-in" in switch.stdout
    assert "reused when Codex reports" not in switch.stdout
    explicit = runner.invoke(app, [*arguments, "--model", "gpt-5.6-terra"])
    assert explicit.exit_code == 0
    assert selected_models == ["gpt-5.6-sol", "gpt-5.6-sol", "gpt-5.6-terra"]


@pytest.mark.anyio
async def test_setup_reuses_an_already_signed_in_dedicated_home_without_a_login_challenge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The second setup against the same logged-in home must not open a sign-in (#534)."""

    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, binding, written)
    calls: list[str] = []

    async def probe(_profile: object) -> CodexRuntimeStatus:
        calls.append("account_status")
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    async def forbidden_login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        pytest.fail("a home Codex reports as signed in must not receive a new login challenge")

    async def forbidden_logout(_profile: object) -> CodexRuntimeStatus:
        pytest.fail("reuse must not log the dedicated home out")

    monkeypatch.setattr(module, "codex_account_status", probe)
    monkeypatch.setattr(module, "codex_login", forbidden_login)
    monkeypatch.setattr(module, "codex_logout", forbidden_logout)

    result = await _run_setup(tmp_path)

    assert calls == ["account_status"]
    assert written == [binding]
    assert result["login_reused"] is True
    assert result["auth_mode"] == "chatgpt"
    assert result["model_available"] is True
    assert result["process_cleanup"] == "terminated"


@pytest.mark.anyio
async def test_setup_reports_a_completed_login_as_not_reused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, binding, written)
    calls: list[str] = []

    async def probe(_profile: object) -> CodexRuntimeStatus:
        calls.append("account_status")
        return CodexRuntimeStatus(True, None, None, False, "terminated")

    async def login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        calls.append("login")
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    monkeypatch.setattr(module, "codex_account_status", probe)
    monkeypatch.setattr(module, "codex_login", login)

    result = await _run_setup(tmp_path)

    assert calls == ["account_status", "login"]
    assert written == [binding]
    assert result["login_reused"] is False


@pytest.mark.anyio
async def test_setup_signed_in_home_without_the_model_fails_without_a_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A signed-in home whose model no admitted Codex lists is named, not sent to sign-in.

    Starting ``account/login/start`` on a home Codex already reports as signed in surfaced as
    ``codex_login_event_invalid`` (the gpt-6.1-sol report on Codex 0.157.1); a new sign-in cannot
    add a model the runtime does not list.
    """

    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, binding, written)
    calls: list[str] = []

    async def probe(_profile: object) -> CodexRuntimeStatus:
        calls.append("account_status")
        return CodexRuntimeStatus(True, "chatgpt", "plus", False, "terminated")

    async def forbidden_login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        pytest.fail("a signed-in home must not receive a new login challenge")

    monkeypatch.setattr(module, "codex_account_status", probe)
    monkeypatch.setattr(module, "codex_login", forbidden_login)

    with pytest.raises(ValueError, match="^codex_model_unavailable$"):
        await _run_setup(tmp_path)

    assert calls == ["account_status"]
    assert written == []
    assert "--switch-account" in (module.subscription_remediation("codex_model_unavailable") or "")


def _three_releases(monkeypatch: pytest.MonkeyPatch, failing: dict[str, str]) -> list[str]:
    """Candidates 0.162.1, 0.159.0, 0.157.1; ``failing`` maps a release to its check token."""

    checked: list[str] = []

    def candidates(
        _config: YoetzConfig, *, executable: Path | None = None
    ) -> tuple[module.EvaluatorCandidate, ...]:
        del executable
        return tuple(
            module.EvaluatorCandidate("discovered", Path(f"/opt/codex/{version}/codex"), version)
            for version in ("0.162.1", "0.159.0", "0.157.1")
        )

    async def check(candidate: module.EvaluatorCandidate, *, bundle: Path) -> object:
        checked.append(candidate.version)
        if candidate.version in failing:
            raise ValueError(failing[candidate.version])
        record = record_for(b"codex", b"host", version=candidate.version)
        return module._Checked(  # pyright: ignore[reportPrivateUsage]
            candidate, managed_runtime_path(bundle, record.source_identity), record
        )

    monkeypatch.setattr(module, "evaluator_candidates", candidates)
    monkeypatch.setattr(module, "_check_candidate", check)
    return checked


@pytest.mark.anyio
async def test_setup_binds_the_newest_release_that_passes_the_capability_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    checked = _three_releases(monkeypatch, {})
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, _binding(tmp_path / "c", tmp_path / "h"), [])
    monkeypatch.setattr(module, "_binding", _record_binding(tmp_path))
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", _record_write(tmp_path, written))
    monkeypatch.setattr(module, "codex_account_status", _ready_probe)

    result = await _run_setup_without_executable(tmp_path)

    assert checked == ["0.162.1"]
    (binding,) = written
    assert cast(ExternalRuntimeProfileConfig, binding).runtime_version == "0.162.1"
    assert result["runtime_version"] == "0.162.1"
    assert result["runtimes_passed_over"] == []


@pytest.mark.anyio
async def test_a_newer_release_that_fails_the_check_falls_back_to_the_previous_good_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    checked = _three_releases(monkeypatch, {"0.162.1": "codex_runtime_protocol_incompatible"})
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, _binding(tmp_path / "c", tmp_path / "h"), [])
    monkeypatch.setattr(module, "_binding", _record_binding(tmp_path))
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", _record_write(tmp_path, written))
    monkeypatch.setattr(module, "codex_account_status", _ready_probe)

    result = await _run_setup_without_executable(tmp_path)

    assert checked == ["0.162.1", "0.159.0"]
    assert result["runtime_version"] == "0.159.0"
    assert result["runtimes_passed_over"] == ["codex_runtime_protocol_incompatible"]


@pytest.mark.anyio
async def test_a_release_whose_catalog_lacks_the_model_falls_back_to_one_that_lists_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _three_releases(monkeypatch, {})
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, _binding(tmp_path / "c", tmp_path / "h"), [])
    monkeypatch.setattr(module, "_binding", _record_binding(tmp_path))
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", _record_write(tmp_path, written))
    probed: list[str] = []

    async def probe(profile: object) -> CodexRuntimeStatus:
        version = cast(ExternalRuntimeProfileConfig, profile).runtime_version
        probed.append(version)
        return CodexRuntimeStatus(True, "chatgpt", "pro", version != "0.162.1", "terminated")

    def profile_is_binding(binding: ExternalRuntimeProfileConfig) -> object:
        return binding

    monkeypatch.setattr(module, "_profile", profile_is_binding)
    monkeypatch.setattr(module, "codex_account_status", probe)

    result = await _run_setup_without_executable(tmp_path)

    assert probed == ["0.162.1", "0.159.0"]
    assert result["runtime_version"] == "0.159.0"
    assert result["runtimes_passed_over"] == ["codex_model_unavailable"]


@pytest.mark.anyio
async def test_a_release_that_warns_during_authenticated_readiness_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A release that passed the scratch probe but warns under the signed-in home is not bound."""

    _three_releases(monkeypatch, {})
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, _binding(tmp_path / "c", tmp_path / "h"), [])
    monkeypatch.setattr(module, "_binding", _record_binding(tmp_path))
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", _record_write(tmp_path, written))
    probed: list[str] = []

    async def probe(profile: object) -> CodexRuntimeStatus:
        version = cast(ExternalRuntimeProfileConfig, profile).runtime_version
        probed.append(version)
        if version == "0.162.1":
            raise ValueError("codex_app_server_predisclosure_event_forbidden")
        return CodexRuntimeStatus(True, "chatgpt", "pro", True, "terminated")

    def profile_is_binding(binding: ExternalRuntimeProfileConfig) -> object:
        return binding

    monkeypatch.setattr(module, "_profile", profile_is_binding)
    monkeypatch.setattr(module, "codex_account_status", probe)

    result = await _run_setup_without_executable(tmp_path)

    assert probed == ["0.162.1", "0.159.0"]
    (binding,) = written
    assert cast(ExternalRuntimeProfileConfig, binding).runtime_version == "0.159.0"
    assert result["runtimes_passed_over"] == ["codex_app_server_predisclosure_event_forbidden"]


@pytest.mark.anyio
async def test_no_release_passing_the_check_refuses_with_the_first_cause(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _three_releases(
        monkeypatch,
        {
            "0.162.1": "codex_runtime_protocol_incompatible",
            "0.159.0": "codex_app_server_predisclosure_event_forbidden",
            "0.157.1": "codex_thread_isolation_unproven",
        },
    )
    written: list[object] = []
    _stub_setup_persistence(
        monkeypatch, tmp_path, _binding(tmp_path / "c", tmp_path / "h"), written
    )

    async def forbidden(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        pytest.fail("no runtime passed the check, so no Codex session may start")

    monkeypatch.setattr(module, "codex_account_status", forbidden)
    monkeypatch.setattr(module, "codex_login", forbidden)

    with pytest.raises(ValueError, match="^codex_runtime_protocol_incompatible$"):
        await _run_setup_without_executable(tmp_path)
    assert written == []
    assert module.subscription_remediation("codex_runtime_protocol_incompatible") is not None


def _record_binding(tmp_path: Path) -> object:
    """``_binding`` that keeps the checked record's identity (so tests see the adopted release)."""

    def build(**kwargs: object) -> ExternalRuntimeProfileConfig:
        record = cast(CodexCapabilityRecord, kwargs["record"])
        return binding_for(record, cast(Path, kwargs["executable"]), tmp_path / "home")

    return build


def _record_write(tmp_path: Path, written: list[object]) -> object:
    def write(config: YoetzConfig, **_kwargs: object) -> Path:
        written.append(config.external_runtime)
        return tmp_path / "config.toml"

    return write


async def _ready_probe(_profile: object) -> CodexRuntimeStatus:
    return CodexRuntimeStatus(True, "chatgpt", "pro", True, "terminated")


async def _run_setup_without_executable(tmp_path: Path) -> Mapping[str, object]:
    return await module.codex_subscription_setup(
        executable=None,
        codex_home=tmp_path / "dedicated-home",
        model="gpt-6.1-sol",
        reasoning_effort="max",
        login_mode="browser",
        open_browser=False,
        switch_account=False,
    )


@pytest.mark.anyio
async def test_setup_switch_account_always_logs_out_and_signs_in_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, binding, written)
    calls: list[str] = []

    async def forbidden_probe(_profile: object) -> CodexRuntimeStatus:
        pytest.fail("switching accounts must not consult the current login")

    async def logout(_profile: object) -> CodexRuntimeStatus:
        calls.append("logout")
        return CodexRuntimeStatus(True, None, None, False, "terminated")

    async def login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        calls.append("login")
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    monkeypatch.setattr(module, "codex_account_status", forbidden_probe)
    monkeypatch.setattr(module, "codex_logout", logout)
    monkeypatch.setattr(module, "codex_login", login)

    result = await _run_setup(tmp_path, switch_account=True)

    assert calls == ["logout", "login"]
    assert written == [binding]
    assert result["login_reused"] is False


@pytest.mark.anyio
async def test_setup_unconfirmed_probe_cleanup_fails_closed_before_login_or_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    written: list[object] = []
    _stub_setup_persistence(monkeypatch, tmp_path, binding, written)

    async def probe(_profile: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "failed")

    async def forbidden_login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        pytest.fail("a probe whose process group is unconfirmed must not launch another child")

    monkeypatch.setattr(module, "codex_account_status", probe)
    monkeypatch.setattr(module, "codex_login", forbidden_login)

    with pytest.raises(ValueError, match="codex_subscription_readiness_unproven"):
        await _run_setup(tmp_path)

    assert written == []


class _SignedInAppServer:
    """Fake app-server v2 runtime whose dedicated home Codex already reports as signed in."""

    def __init__(self, profile: object) -> None:
        self.profile = profile
        self.workdir = Path("/private/empty-setup-attempt")
        self.pending_notifications: list[dict[str, object]] = []
        self.methods: list[str] = []
        self.sent: list[dict[str, object]] = []

    async def send(self, value: dict[str, object]) -> None:
        self.sent.append(value)

    async def request(
        self, request_id: int, method: str, params: object, timeout: float
    ) -> Mapping[str, object]:
        del request_id, timeout
        self.methods.append(method)
        if method == "initialize":
            return {
                "codexHome": str(getattr(self.profile, "codex_home")),
                "userAgent": "yoetz_semantic_evaluator/0.159.0 (Mac OS 26.6.2; arm64) unknown",
            }
        if method == "account/read":
            assert params == {"refreshToken": False}
            return {"account": {"type": "chatgpt", "planType": "plus", "email": "x@y"}}
        if method == "model/list":
            return {
                "data": [
                    {
                        "id": "gpt-5.6-sol",
                        "supportedReasoningEfforts": [{"reasoningEffort": "high"}],
                    }
                ],
                "nextCursor": None,
            }
        pytest.fail(f"unexpected app-server request {method}")

    async def read(self, timeout: float) -> dict[str, object]:
        del timeout
        pytest.fail("a reused login must not wait on login notifications")


@pytest.mark.anyio
async def test_setup_against_fake_app_server_reads_account_and_never_starts_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """End to end through the real adapter: ``account/read`` ready means no ``account/login/start``."""

    from yoetz.adapters.providers import codex_app_server

    executable = tmp_path / "codex"
    home = tmp_path / "dedicated-home"
    target = tmp_path / "config.toml"
    target.write_text(_data_dir_config_text(tmp_path / "state"), encoding="utf-8")
    binding = _binding(executable, home)
    runtimes: list[_SignedInAppServer] = []

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    async def launch(profile: object) -> _SignedInAppServer:
        runtime = _SignedInAppServer(profile)
        runtimes.append(runtime)
        return runtime

    async def cleanup(value: object) -> str:
        assert value is runtimes[-1]
        return "terminated"

    def allow_private_bundle(_path: Path) -> None:
        # pytest's temp root is shared temp on Linux; the owner-only gate is locked elsewhere.
        return None

    monkeypatch.setattr(module, "_binding", build_binding)
    monkeypatch.setattr(codex_app_server, "verify_private_local_bundle", allow_private_bundle)
    monkeypatch.setattr(codex_app_server, "_launch", launch)
    monkeypatch.setattr(codex_app_server, "_cleanup", cleanup)

    result = await _run_setup(tmp_path, config_path=target)

    # The trailing account/read is the barrier that closes the pre-disclosure window.
    assert [runtime.methods for runtime in runtimes] == [
        ["initialize", "account/read", "model/list", "account/read"]
    ]
    assert "account/login/start" not in runtimes[0].methods
    assert result["login_reused"] is True
    assert result["auth_mode"] == "chatgpt"
    assert (home / "config.toml").read_bytes() == codex_app_server.CODEX_EVALUATOR_CONFIG.encode()
    rewritten = module._base_config(target)  # pyright: ignore[reportPrivateUsage]
    assert rewritten.external_runtime is not None
    assert rewritten.external_runtime.codex_home == str(home)
    assert "x@y" not in json.dumps(result)


def test_setup_rejects_a_reused_home_whose_config_differs_before_any_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from yoetz.adapters.providers import codex_app_server
    from yoetz.adapters.providers.codex_app_server import prepare_codex_home

    def allow_private_bundle(_path: Path) -> None:
        return None

    monkeypatch.setattr(codex_app_server, "verify_private_local_bundle", allow_private_bundle)
    home = tmp_path / "dedicated-home"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text('model = "other"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="codex_runtime_config_conflict"):
        prepare_codex_home(home)


def _data_dir_config_text(data_dir: Path) -> str:
    return f'schema_version = "1"\nprofile = "strict-local"\n\n[storage]\ndata_dir = "{data_dir}"\n'


def _bound_config_file(tmp_path: Path, binding: ExternalRuntimeProfileConfig) -> Path:
    """Write the exact rendered config selecting the binding, with an explicit data_dir."""

    from yoetz.config.models import StorageConfig

    config = YoetzConfig(
        profile="codex-subscription",
        storage=StorageConfig(data_dir=tmp_path / "state"),
        external_runtime=binding,
    )
    target = tmp_path / "config.toml"
    target.write_text(render_config_toml(config), encoding="utf-8")
    return target


def test_base_config_accepts_valid_storage_data_dir_through_the_canonical_loader(
    tmp_path: Path,
) -> None:
    """A file the service loader accepts is a file the lifecycle commands accept (#520)."""

    target = tmp_path / "config.toml"
    target.write_text(_data_dir_config_text(tmp_path / "state"), encoding="utf-8")

    config = module._base_config(target)  # pyright: ignore[reportPrivateUsage]

    assert config.storage.data_dir == tmp_path / "state"


def test_base_config_fails_as_one_closed_token_on_invalid_configuration(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_text("[storage]\ndata_dir = 5\n", encoding="utf-8")

    with pytest.raises(ValueError, match="config_value_invalid"):
        module._base_config(target)  # pyright: ignore[reportPrivateUsage]

    target.write_text("not [ valid toml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="config_toml_invalid"):
        module._base_config(target)  # pyright: ignore[reportPrivateUsage]


def test_rollback_preserves_storage_data_dir_while_removing_only_the_binding(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    target = _bound_config_file(tmp_path, binding)

    result = module.codex_subscription_rollback(config_path=target)

    assert result["binding_removed"] is True
    rewritten = module._base_config(target)  # pyright: ignore[reportPrivateUsage]
    assert rewritten.external_runtime is None
    assert rewritten.storage.data_dir == tmp_path / "state"
    assert rewritten.profile == "strict-local"


@pytest.mark.anyio
async def test_status_reads_a_binding_from_a_config_with_explicit_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assume_structurally_ready(monkeypatch)
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    target = _bound_config_file(tmp_path, binding)

    async def account_status(_profile: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    monkeypatch.setattr(module, "codex_account_status", account_status)

    result = await module.codex_subscription_status(config_path=target)

    assert result["codex_home"] == str(tmp_path / "dedicated-home")
    assert result["auth_mode"] == "chatgpt"


@pytest.mark.anyio
async def test_disconnect_preserves_storage_data_dir_from_a_valid_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assume_structurally_ready(monkeypatch)
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    target = _bound_config_file(tmp_path, binding)

    async def logout(_profile: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, None, None, False, "terminated")

    monkeypatch.setattr(module, "codex_logout", logout)

    result = await module.codex_subscription_disconnect(config_path=target)

    assert result["binding_removed"] is True
    rewritten = module._base_config(target)  # pyright: ignore[reportPrivateUsage]
    assert rewritten.external_runtime is None
    assert rewritten.storage.data_dir == tmp_path / "state"


@pytest.mark.anyio
async def test_setup_validates_configuration_before_any_login_or_home_side_effect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An invalid config is a deterministic local failure; login must never open (#520)."""

    target = tmp_path / "config.toml"
    target.write_text("[storage]\ndata_dir = 5\n", encoding="utf-8")
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    monkeypatch.setattr(module, "_binding", build_binding)

    async def forbidden_login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        pytest.fail("an invalid configuration must fail before the Codex login flow")

    def forbidden_prepare(_home: Path) -> None:
        pytest.fail("an invalid configuration must fail before the dedicated home is created")

    monkeypatch.setattr(module, "codex_login", forbidden_login)
    monkeypatch.setattr(module, "prepare_codex_home", forbidden_prepare)

    with pytest.raises(ValueError, match="config_value_invalid"):
        await module.codex_subscription_setup(
            executable=tmp_path / "codex",
            codex_home=tmp_path / "dedicated-home",
            model="gpt-5.6-sol",
            reasoning_effort="high",
            login_mode="browser",
            open_browser=False,
            switch_account=False,
            config_path=target,
        )


@pytest.mark.anyio
async def test_setup_probes_the_writable_binding_target_before_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _mock_macos_arm64_host(monkeypatch)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    target = blocked / "config.toml"
    target.write_text(_data_dir_config_text(tmp_path / "state"), encoding="utf-8")
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")

    def build_binding(**_kwargs: object) -> ExternalRuntimeProfileConfig:
        return binding

    monkeypatch.setattr(module, "_binding", build_binding)

    async def forbidden_login(*_args: object, **_kwargs: object) -> CodexRuntimeStatus:
        pytest.fail("an unwritable binding target must fail before the Codex login flow")

    monkeypatch.setattr(module, "codex_login", forbidden_login)

    blocked.chmod(0o500)
    try:
        with pytest.raises(ValueError, match="config_value_invalid"):
            await module.codex_subscription_setup(
                executable=tmp_path / "codex",
                codex_home=tmp_path / "dedicated-home",
                model="gpt-5.6-sol",
                reasoning_effort="high",
                login_mode="browser",
                open_browser=False,
                switch_account=False,
                config_path=target,
            )
    finally:
        blocked.chmod(0o700)


@pytest.mark.anyio
async def test_disconnect_probes_the_removal_write_before_codex_logout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _assume_structurally_ready(monkeypatch)
    _mock_macos_arm64_host(monkeypatch)
    binding = _binding(tmp_path / "codex", tmp_path / "dedicated-home")
    target = _bound_config_file(tmp_path, binding)

    async def forbidden_logout(_profile: object) -> CodexRuntimeStatus:
        pytest.fail("an unpersistable removal must fail before Codex logs the home out")

    monkeypatch.setattr(module, "codex_logout", forbidden_logout)

    tmp_path.chmod(0o500)
    try:
        with pytest.raises(ValueError, match="config_value_invalid"):
            await module.codex_subscription_disconnect(config_path=target)
    finally:
        tmp_path.chmod(0o700)


def test_cli_status_reports_a_bounded_config_token_instead_of_internal_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 70 ``internal_error`` for a local configuration problem was the #520 defect."""

    from yoetz.cli.app import app

    target = tmp_path / "config.toml"
    target.write_text("[storage]\ndata_dir = 5\n", encoding="utf-8")
    monkeypatch.setenv("YOETZ_CONFIG", str(target))

    result = CliRunner().invoke(app, ["provider", "codex-subscription", "status", "--json"])

    assert result.exit_code == 20
    assert "codex_subscription: config_value_invalid" in result.stderr
    assert "internal_error" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_cli_status_accepts_a_valid_storage_data_dir_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from yoetz.cli.app import app

    target = tmp_path / "config.toml"
    target.write_text(_data_dir_config_text(tmp_path / "state"), encoding="utf-8")
    monkeypatch.setenv("YOETZ_CONFIG", str(target))

    result = CliRunner().invoke(app, ["provider", "codex-subscription", "status"])

    assert result.exit_code == 20
    assert "codex_subscription_not_configured" in result.stderr
    assert "internal_error" not in result.stderr


def test_cli_setup_recommends_luna_and_keeps_independent_high_effort() -> None:
    from yoetz.cli.app import provider_codex_subscription_setup

    params = inspect.signature(provider_codex_subscription_setup).parameters
    assert params["model"].default is None
    # ``None`` resolves to high for a new binding and preserves an existing binding's effort.
    assert params["reasoning_effort"].default is None
    assert params["executable"].default is None
    assert module.default_codex_subscription_reasoning_effort() == "high"


def test_default_subscription_model_recommends_luna_or_preserves_existing_binding(
    tmp_path: Path,
) -> None:
    absent = tmp_path / "absent.toml"
    assert module.default_codex_subscription_model(absent) == "gpt-6-luna"

    target = _bound_config_file(tmp_path, _binding(tmp_path / "codex", tmp_path / "home"))
    assert module.default_codex_subscription_model(target) == "gpt-5.6-sol"


# --- issue #571: routine/final budget choices survive setup -------------------------------------


def _budget_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: ExternalRuntimeProfileConfig | None,
) -> list[ExternalRuntimeProfileConfig]:
    written: list[ExternalRuntimeProfileConfig] = []
    template = _binding(tmp_path / "codex", tmp_path / "dedicated-home")

    def preview(**kwargs: object) -> dict[str, object]:
        return {
            "executable_path": template.executable_path,
            "executable_sha256": template.executable_sha256,
            "runtime_source_identity": template.source_identity,
            "app_server_schema_sha256": template.app_server_schema_sha256,
            "capability_cell_sha256": template.capability_cell_sha256,
            "isolated_config_sha256": template.isolated_config_sha256,
            "capability_profile": template.capability_profile,
            "capability_evidence_expires_at": template.capability_evidence_expires_at,
            **kwargs,
        }

    def snapshot(_path: Path) -> tuple[YoetzConfig, bytes | None]:
        if existing is None:
            return YoetzConfig(), None
        return YoetzConfig(profile="codex-subscription", external_runtime=existing), None

    def write_binding(config: YoetzConfig, **_kwargs: object) -> Path:
        assert config.external_runtime is not None
        written.append(config.external_runtime)
        return tmp_path / "config.toml"

    async def ready(_profile: object) -> CodexRuntimeStatus:
        return CodexRuntimeStatus(True, "chatgpt", "plus", True, "terminated")

    def preflight(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    def prepare(_home: Path) -> None:
        return None

    def build_profile(_binding: ExternalRuntimeProfileConfig) -> object:
        return object()

    monkeypatch.setattr(module, "codex_subscription_preview", preview)
    monkeypatch.setattr(module, "_config_snapshot", snapshot)
    monkeypatch.setattr(module, "preflight_config_write", preflight)
    monkeypatch.setattr(module, "prepare_codex_home", prepare)
    monkeypatch.setattr(module, "_profile", build_profile)
    monkeypatch.setattr(module, "codex_account_status", ready)
    monkeypatch.setattr(module, "write_config_toml_if_unchanged", write_binding)
    return written


async def _setup_with_routine(tmp_path: Path, routine: str | None) -> Mapping[str, object]:
    return await module.codex_subscription_setup(
        executable=tmp_path / "codex",
        codex_home=tmp_path / "dedicated-home",
        model="gpt-5.6-sol",
        reasoning_effort="high",
        login_mode="browser",
        open_browser=False,
        switch_account=False,
        routine_reasoning_effort=routine,
    )


@pytest.mark.anyio
async def test_new_binding_receives_the_bounded_routine_recommendation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    written = _budget_setup(monkeypatch, tmp_path, None)

    result = await _setup_with_routine(tmp_path, None)

    assert [item.routine_reasoning_effort for item in written] == ["medium"]
    assert (written[0].routine_output_limit, written[0].final_output_limit) == (4096, 8192)
    assert result["reasoning_effort"] == "high"
    assert result["review_budgets"] == {
        "routine": {
            "reasoning_effort": "medium",
            "output_limit": 4096,
            "effort_source": "configured",
        },
        "final": {"reasoning_effort": "high", "output_limit": 8192, "effort_source": "configured"},
    }


@pytest.mark.anyio
async def test_resetup_preserves_a_legacy_single_effort_and_explicit_output_limits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    legacy = _binding(tmp_path / "codex", tmp_path / "dedicated-home").model_copy(
        update={"routine_output_limit": 2048, "final_output_limit": 6000}
    )
    written = _budget_setup(monkeypatch, tmp_path, legacy)

    await _setup_with_routine(tmp_path, None)

    assert written[0].routine_reasoning_effort is None
    assert written[0].effective_routine_reasoning_effort == "high"
    assert (written[0].routine_output_limit, written[0].final_output_limit) == (2048, 6000)


@pytest.mark.anyio
async def test_explicit_routine_choice_wins_over_an_existing_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    existing = _binding(tmp_path / "codex", tmp_path / "dedicated-home").model_copy(
        update={"routine_reasoning_effort": "low"}
    )
    written = _budget_setup(monkeypatch, tmp_path, existing)

    await _setup_with_routine(tmp_path, "xhigh")

    assert written[0].routine_reasoning_effort == "xhigh"


def test_routine_default_follows_the_existing_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    assert module.default_codex_subscription_routine_effort() == "medium"
    legacy = _binding(tmp_path / "codex", tmp_path / "home")
    selected: list[ExternalRuntimeProfileConfig] = [legacy]

    def base_config(_path: Path | None = None) -> YoetzConfig:
        return YoetzConfig(profile="codex-subscription", external_runtime=selected[0])

    monkeypatch.setattr(module, "_base_config", base_config)
    assert module.default_codex_subscription_routine_effort() is None
    selected[0] = legacy.model_copy(update={"routine_reasoning_effort": "low"})
    assert module.default_codex_subscription_routine_effort() == "low"


def test_preview_rejects_an_unsupported_routine_effort(tmp_path: Path) -> None:
    native, _ = _write_codex_package_layout(tmp_path, nested=True)
    preview = module.codex_subscription_preview(
        executable=native,
        codex_home=tmp_path / "home",
        model="gpt-5.6-sol",
        reasoning_effort="high",
        routine_reasoning_effort="low",
    )
    assert (preview["reasoning_effort"], preview["routine_reasoning_effort"]) == ("high", "low")
    with pytest.raises(ValueError, match="codex_runtime_model_invalid"):
        module.codex_subscription_preview(
            executable=native,
            codex_home=tmp_path / "home",
            model="gpt-5.6-sol",
            reasoning_effort="high",
            routine_reasoning_effort="turbo",
        )
