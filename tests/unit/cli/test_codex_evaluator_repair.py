"""Evaluator runtime adoption by capability, retention, repair, and precise diagnosis.

The incidents are replayed end to end through the real configuration loader and writer and the
real retained-runtime store: a binding from the pinned-cell era whose ordinary npm path now holds a
newer Codex, a newer everyday Codex adopted by the next repair, and a newer release that fails the
capability check falling back to the previous good one. Codex processes, discovery, the capability
check's subprocesses, and package-manager downloads are stubbed; every store lives under
``tmp_path``.
"""

from __future__ import annotations

import inspect
import os
import re
import sys
import tomllib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from builders.codex_capability import LINUX, SCHEMA_SUBSET_DIGEST, plain_digest
from yoetz.adapters.providers import codex_app_server
from yoetz.adapters.providers import codex_evaluator_runtime as runtime_store
from yoetz.adapters.providers.codex_app_server import (
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_CONFIG,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CodexAppServerProfile,
    CodexRuntimeStatus,
)
from yoetz.adapters.providers.codex_capability import (
    CodexCapabilityRecord,
    CodexPlatform,
    codex_source_identity,
)
from yoetz.cli import codex_subscription as module
from yoetz.config.models import (
    ExternalRuntimeProfileConfig,
    SemanticFallbackConfig,
    StorageConfig,
    YoetzConfig,
)
from yoetz.config.write import codex_subscription_runtime, render_config_toml
from yoetz.ports.harness_mcp import HarnessBinary
from yoetz.ports.integrations import HarnessId

pytestmark = pytest.mark.anyio

_HOST_BYTES = b"codex code-mode host bytes"
_HOST_NAME = "codex-code-mode-host"
_OWNER_CHOICES = ("model", "reasoning_effort", "timeout_seconds", "max_retries", "codex_home")
# A binding written while the evaluator admitted exactly one pinned 0.157.1 build per platform.
_PINNED: dict[str, str] = {
    "runtime_version": "0.157.1",
    "source_identity": "openai-codex-npm-linux-x64-0.157.1",
    "capability_profile": "codex-evaluator/0.157.1/v2",
    "capability_cell_sha256": "sha256:fa6a65e47fb7c7f647a31ae47625a3e99e80247cd412e4fdfe1922975f2fafa3",
    "app_server_schema_sha256": (
        "sha256:2719fccd25a97a7ce355497ca5e9123a63f6dce7f9f83724a5b73fd927811f59"
    ),
}
_VERSION_IN_BYTES = re.compile(rb"codex ([0-9][0-9A-Za-z.-]*) native")


def _bytes(version: str) -> bytes:
    return f"codex {version} native bytes".encode()


@dataclass
class _Codex:
    """Recording stand-ins for every Codex app-server process entry point."""

    signed_in: bool = True
    cleanup: str = "terminated"
    # Releases whose catalog does not list the bound model for this home.
    model_missing: set[str] = field(default_factory=lambda: set[str]())
    probes: list[CodexAppServerProfile] = field(default_factory=lambda: [])
    logins: list[CodexAppServerProfile] = field(default_factory=lambda: [])
    logouts: list[CodexAppServerProfile] = field(default_factory=lambda: [])

    async def account_status(self, profile: CodexAppServerProfile) -> CodexRuntimeStatus:
        self.probes.append(profile)
        listed = self.signed_in and profile.runtime_version not in self.model_missing
        return CodexRuntimeStatus(
            True,
            "chatgpt" if self.signed_in else None,
            "pro" if self.signed_in else None,
            listed,
            self.cleanup,  # pyright: ignore[reportArgumentType]
        )

    async def login(self, profile: CodexAppServerProfile, **_kwargs: object) -> CodexRuntimeStatus:
        self.logins.append(profile)
        return CodexRuntimeStatus(True, "chatgpt", "pro", True, "terminated")

    async def logout(self, profile: CodexAppServerProfile) -> CodexRuntimeStatus:
        self.logouts.append(profile)
        return CodexRuntimeStatus(True, None, None, False, "terminated")


@dataclass
class _Env:
    tmp: Path
    platform: CodexPlatform
    bundle: Path
    config_path: Path
    codex: _Codex
    discovered: list[Path]
    downloads: list[Path | None]
    # Releases the capability check refuses, with the token it names.
    check_failures: dict[str, str]
    checked: list[str]

    def managed(self, version: str = "0.159.0") -> Path:
        return runtime_store.managed_runtime_path(
            self.bundle, codex_source_identity(self.platform, version)
        )

    def executable(
        self,
        relative: str,
        version: str = "0.159.0",
        *,
        data: bytes | None = None,
        host: bytes | None = _HOST_BYTES,
    ) -> Path:
        """A synthetic native executable reporting ``version``, its code-mode host beside it."""

        path = self.tmp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_bytes(version) if data is None else data)
        path.chmod(0o700)
        if host is not None:
            sibling = path.parent / _HOST_NAME
            sibling.write_bytes(host)
            sibling.chmod(0o700)
        return path

    def home(self) -> Path:
        home = self.tmp / "evaluator-home"
        home.mkdir(mode=0o700, exist_ok=True)
        (home / "config.toml").write_bytes(CODEX_EVALUATOR_CONFIG.encode())
        return home

    def pinned_binding(self, executable: Path, **overrides: object) -> ExternalRuntimeProfileConfig:
        """A pinned-cell binding (``codex-evaluator/0.157.1/v2``) with owner choices set."""

        binding = codex_subscription_runtime(
            executable_path=str(executable),
            executable_sha256=plain_digest(_bytes("0.157.1")),
            runtime_version=_PINNED["runtime_version"],
            source_identity=_PINNED["source_identity"],
            app_server_schema_sha256=_PINNED["app_server_schema_sha256"],
            capability_cell_sha256=_PINNED["capability_cell_sha256"],
            isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
            capability_profile=_PINNED["capability_profile"],
            capability_evidence_expires_at="2026-11-30T00:00:00Z",
            codex_home=str(self.home()),
            model="gpt-5.6-sol",
            reasoning_effort="xhigh",
            timeout_seconds=37,
            max_retries=0,
        )
        return binding.model_copy(update=overrides)

    async def checked_binding(
        self, version: str = "0.159.0", **overrides: object
    ) -> ExternalRuntimeProfileConfig:
        """Retain ``version``, commit its record, and bind it as setup would."""

        source = self.executable(f"source-{version}/codex", version)
        identity = codex_source_identity(self.platform, version)
        retained = runtime_store.retain_codex_runtime(
            source, bundle=self.bundle, source_identity=identity
        )
        record = await _fake_check(self)(
            retained, runtime_version=version, platform=self.platform, scratch_parent=self.tmp
        )
        runtime_store.commit_capability_record(self.bundle, record)
        binding = module._binding(  # pyright: ignore[reportPrivateUsage]
            record=record,
            executable=retained,
            codex_home=self.home(),
            model="gpt-5.6-sol",
            reasoning_effort="xhigh",
        )
        return binding.model_copy(update={"timeout_seconds": 37, "max_retries": 0, **overrides})

    def write_config(
        self,
        binding: ExternalRuntimeProfileConfig | None,
        *,
        fallback_behind_api: bool = False,
    ) -> YoetzConfig:
        from unit.cli.test_provider_status import _provider  # pyright: ignore[reportPrivateUsage]

        config = YoetzConfig(
            profile="strict-local" if binding is None else "codex-subscription",
            storage=StorageConfig(data_dir=self.tmp / "state"),
            external_runtime=binding,
        )
        if fallback_behind_api:
            config = config.model_copy(
                update={
                    "profile": "local-openai",
                    "provider": _provider(),
                    "semantic_fallback": SemanticFallbackConfig(primary="api_provider"),
                }
            )
        self.config_path.write_text(render_config_toml(config), encoding="utf-8")
        return config

    def written(self) -> YoetzConfig:
        return module._base_config(self.config_path)  # pyright: ignore[reportPrivateUsage]


type _Check = Callable[..., Awaitable[CodexCapabilityRecord]]


def _fake_check(env: _Env) -> _Check:
    """The capability check over synthetic bytes: the real record, a stubbed procedure."""

    async def check(
        executable: Path,
        *,
        runtime_version: str,
        platform: CodexPlatform,
        scratch_parent: Path,
        **_kwargs: object,
    ) -> CodexCapabilityRecord:
        del scratch_parent
        env.checked.append(runtime_version)
        failure = env.check_failures.get(runtime_version)
        if failure is not None:
            raise ValueError(failure)
        return CodexCapabilityRecord(
            runtime_version=runtime_version,
            source_identity=codex_source_identity(platform, runtime_version),
            platform_os=platform.os,
            platform_architecture=platform.architecture,
            executable_sha256=plain_digest(executable.read_bytes()),
            code_mode_host_sha256=plain_digest((executable.parent / _HOST_NAME).read_bytes()),
            app_server_schema_sha256=SCHEMA_SUBSET_DIGEST,
            isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
        )

    return check


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _Env:
    for name in tuple(os.environ):
        if name.startswith("YOETZ_"):
            monkeypatch.delenv(name)
    config_path = tmp_path / "config.toml"
    monkeypatch.setenv("YOETZ_CONFIG", str(config_path))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    def allow_private(_path: Path) -> None:
        return None

    monkeypatch.setattr(runtime_store, "verify_private_local_bundle", allow_private)
    monkeypatch.setattr(codex_app_server, "verify_private_local_bundle", allow_private)
    bundle = tmp_path / "bundle"

    def runtime_bundle(_config: YoetzConfig | None = None) -> Path:
        return bundle

    monkeypatch.setattr(module, "runtime_bundle", runtime_bundle)

    def cli_version(native: Path) -> str:
        match = _VERSION_IN_BYTES.match(native.read_bytes())
        if match is None:
            raise ValueError("codex_runtime_version_unknown")
        return match.group(1).decode()

    monkeypatch.setattr(module, "_codex_cli_version", cli_version)

    codex = _Codex()
    monkeypatch.setattr(module, "codex_account_status", codex.account_status)
    monkeypatch.setattr(module, "codex_login", codex.login)
    monkeypatch.setattr(module, "codex_logout", codex.logout)

    discovered: list[Path] = []
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: tuple(
            HarnessBinary(HarnessId.CODEX, str(path), None, "untested") for path in discovered
        ),
    )
    downloads: list[Path | None] = []
    environment = _Env(tmp_path, LINUX, bundle, config_path, codex, discovered, downloads, {}, [])
    monkeypatch.setattr(module, "check_codex_capability", _fake_check(environment))

    def provision(**kwargs: object) -> tuple[Path, str]:
        downloads.append(cast(Path | None, kwargs.get("npm")))
        source = environment.executable("npm-cache/codex", "0.162.1")
        identity = codex_source_identity(LINUX, "0.162.1")
        retained = runtime_store.retain_codex_runtime(
            source, bundle=cast(Path, kwargs["bundle"]), source_identity=identity
        )
        return retained, "0.162.1"

    monkeypatch.setattr(module, "provision_codex_runtime", provision)
    return environment


# -- the reproduced incidents -------------------------------------------------------------------


async def test_repair_moves_a_pinned_cell_binding_onto_the_newest_checked_codex(
    env: _Env,
) -> None:
    """A ``0.157.1/v2`` binding, everyday Codex now on 0.159.0: repair adopts it by capability."""

    ordinary_npm = env.executable("npm-prefix/codex", "0.159.0")
    env.discovered.append(ordinary_npm)
    pinned = env.pinned_binding(
        ordinary_npm,
        routine_reasoning_effort="low",
        routine_output_limit=2048,
        final_output_limit=6000,
    )
    env.write_config(pinned)

    before = module.diagnose_bound_runtime(pinned)
    assert (before.state, before.capability, before.executable) == (
        "codex_runtime_executable_changed",
        "profile_outdated",
        "changed",
    )
    assert module.binding_continuation(before.state) == "yoetz provider codex-subscription repair"

    result = await module.codex_subscription_repair(config_path=env.config_path)

    repaired = env.written().external_runtime
    assert repaired is not None
    assert repaired.executable_path == str(env.managed("0.159.0"))
    assert env.managed("0.159.0").parent.name == "openai-codex-npm-linux-x64-0.159.0"
    assert (repaired.runtime_version, repaired.capability_profile) == (
        "0.159.0",
        CODEX_EVALUATOR_CAPABILITY_PROFILE,
    )
    assert repaired.executable_sha256 == plain_digest(_bytes("0.159.0"))
    assert result["changed_fields"] == [
        "executable_path",
        "executable_sha256",
        "runtime_version",
        "source_identity",
        "app_server_schema_sha256",
        "capability_cell_sha256",
        "capability_profile",
    ]
    # Sign-in and every owner choice are kept; nothing logged in or out.
    assert (repaired.model, repaired.reasoning_effort) == ("gpt-5.6-sol", "xhigh")
    assert (repaired.timeout_seconds, repaired.max_retries) == (37, 0)
    assert repaired.codex_home == pinned.codex_home
    assert repaired.routine_reasoning_effort == "low"
    assert (repaired.routine_output_limit, repaired.final_output_limit) == (2048, 6000)
    # The same release is both bound and discovered; the binding's own install is the source.
    assert result["login_reused"] is True and result["source"] == "binding"
    assert env.codex.logins == [] and env.codex.logouts == []
    (probe,) = env.codex.probes
    assert probe.executable_path == env.managed("0.159.0")
    assert module.diagnose_bound_runtime(repaired).ready
    # The host installation is untouched; the evaluator runs Yoetz's own checked copy.
    assert ordinary_npm.read_bytes() == _bytes("0.159.0")
    assert env.managed("0.159.0").read_bytes() == _bytes("0.159.0")


async def test_a_newer_everyday_codex_is_adopted_by_the_next_repair(env: _Env) -> None:
    """Updating Codex is enough: no Yoetz release, the next repair binds the newer release."""

    env.write_config(await env.checked_binding("0.159.0"))
    assert module.diagnose_bound_runtime(
        cast(ExternalRuntimeProfileConfig, env.written().external_runtime)
    ).ready
    env.discovered.append(env.executable("npm-prefix/codex", "0.162.1"))

    result = await module.codex_subscription_repair(config_path=env.config_path)

    adopted = env.written().external_runtime
    assert adopted is not None
    assert (adopted.runtime_version, adopted.executable_path) == (
        "0.162.1",
        str(env.managed("0.162.1")),
    )
    assert result["state_before"] == "ready"
    assert module.diagnose_bound_runtime(adopted).ready
    # The previous release stays retained as a fallback until runtime remove deletes it.
    assert env.managed("0.159.0").exists()


async def test_a_newer_codex_that_fails_the_check_keeps_the_previous_good_release(
    env: _Env,
) -> None:
    env.write_config(await env.checked_binding("0.159.0"))
    env.discovered.append(env.executable("npm-prefix/codex", "0.162.1"))
    env.check_failures["0.162.1"] = "codex_runtime_protocol_incompatible"
    env.checked.clear()

    result = await module.codex_subscription_repair(config_path=env.config_path)

    kept = env.written().external_runtime
    assert kept is not None and kept.runtime_version == "0.159.0"
    assert env.checked == ["0.162.1", "0.159.0"]
    assert result["runtimes_passed_over"] == ["codex_runtime_protocol_incompatible"]
    assert result["changed_fields"] == []


async def test_a_codex_below_the_floor_is_never_a_candidate(env: _Env) -> None:
    env.write_config(None)
    env.discovered.append(env.executable("old/codex", "0.153.4"))

    assert module.select_codex_evaluator_executable(env.written()) is None
    with pytest.raises(ValueError, match="codex_runtime_version_unsupported"):
        module.resolve_codex_executable(env.tmp / "old" / "codex")
    with pytest.raises(ValueError, match="codex_evaluator_runtime_unavailable"):
        await module.codex_subscription_setup(
            executable=None,
            codex_home=env.tmp / "new-home",
            model="gpt-6.1-sol",
            reasoning_effort="max",
            login_mode="browser",
            open_browser=False,
            switch_account=False,
            config_path=env.config_path,
        )
    assert not (env.tmp / "new-home").exists()
    assert env.checked == [] and env.codex.probes == []


async def test_a_later_host_update_cannot_strand_a_retained_binding(env: _Env) -> None:
    host = env.executable("npm-prefix/codex", "0.159.0")
    env.write_config(None)

    await module.codex_subscription_setup(
        executable=host,
        codex_home=env.home(),
        model="gpt-5.6-luna",
        reasoning_effort="high",
        login_mode="browser",
        open_browser=False,
        switch_account=False,
        config_path=env.config_path,
    )
    host.write_bytes(_bytes("0.162.1"))  # an ordinary `npm install -g @openai/codex@latest`

    bound = env.written().external_runtime
    assert bound is not None and bound.executable_path == str(env.managed("0.159.0"))
    assert module.diagnose_bound_runtime(bound).ready
    assert env.codex.logins == []


async def test_repair_refuses_without_a_reusable_login_and_writes_nothing(env: _Env) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    preimage = env.config_path.read_bytes()
    env.codex.signed_in = False

    with pytest.raises(ValueError, match="codex_subscription_login_required"):
        await module.codex_subscription_repair(
            config_path=env.config_path, executable=env.executable("evaluator/codex")
        )

    assert env.config_path.read_bytes() == preimage
    assert env.codex.logins == [] and env.codex.logouts == []
    assert module.subscription_remediation("codex_subscription_login_required") is not None


async def test_repair_falls_back_when_the_newest_codex_does_not_list_the_model(
    env: _Env,
) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    env.discovered.extend(
        (env.executable("a/codex", "0.162.1"), env.executable("b/codex", "0.159.0"))
    )
    env.codex.model_missing.add("0.162.1")

    result = await module.codex_subscription_repair(config_path=env.config_path)

    assert result["runtime_version"] == "0.159.0"
    assert result["runtimes_passed_over"] == ["codex_model_unavailable"]
    env.codex.model_missing.add("0.159.0")
    with pytest.raises(ValueError, match="^codex_model_unavailable$"):
        await module.codex_subscription_repair(config_path=env.config_path)
    assert env.codex.logins == []


async def test_repair_fails_closed_when_probe_cleanup_is_unconfirmed(env: _Env) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    preimage = env.config_path.read_bytes()
    env.codex.cleanup = "failed"

    with pytest.raises(ValueError, match="codex_subscription_readiness_unproven"):
        await module.codex_subscription_repair(
            config_path=env.config_path, executable=env.executable("evaluator/codex")
        )
    assert env.config_path.read_bytes() == preimage


async def test_repair_preserves_a_concurrent_config_edit(
    env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))

    async def edit_during_probe(profile: CodexAppServerProfile) -> CodexRuntimeStatus:
        with env.config_path.open("a", encoding="utf-8") as handle:
            handle.write("\n# owner edit\n")
        return await env.codex.account_status(profile)

    monkeypatch.setattr(module, "codex_account_status", edit_during_probe)

    with pytest.raises(ValueError, match="config_preimage_mismatch"):
        await module.codex_subscription_repair(
            config_path=env.config_path, executable=env.executable("evaluator/codex")
        )
    assert "# owner edit" in env.config_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("operation", ("setup", "repair"))
async def test_runtime_removal_cannot_interrupt_a_binding_transaction(
    env: _Env, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    source = env.executable("evaluator/codex")
    attempts: list[str] = []

    async def remove_during_probe(profile: CodexAppServerProfile) -> CodexRuntimeStatus:
        assert env.managed().exists()
        with pytest.raises(ValueError, match="codex_evaluator_runtime_busy"):
            module.codex_evaluator_runtime_remove(config_path=env.config_path)
        attempts.append("refused")
        return await env.codex.account_status(profile)

    monkeypatch.setattr(module, "codex_account_status", remove_during_probe)
    if operation == "repair":
        await module.codex_subscription_repair(config_path=env.config_path, executable=source)
    else:
        await module.codex_subscription_setup(
            executable=source,
            codex_home=env.home(),
            model="gpt-5.6-sol",
            reasoning_effort="high",
            login_mode="browser",
            open_browser=False,
            switch_account=False,
            config_path=env.config_path,
        )
    assert attempts == ["refused"]
    binding = env.written().external_runtime
    assert binding is not None and module.diagnose_bound_runtime(binding).ready
    # The transaction released the lock; the binding itself now protects removal.
    with pytest.raises(ValueError, match="codex_evaluator_runtime_in_use"):
        module.codex_evaluator_runtime_remove(config_path=env.config_path)


async def test_install_contends_and_failed_mutation_releases_the_lock(env: _Env) -> None:
    env.write_config(None)
    source = env.executable("evaluator/codex")
    with runtime_store.runtime_mutation_lock(env.bundle):
        with pytest.raises(ValueError, match="codex_evaluator_runtime_busy"):
            await module.codex_evaluator_runtime_install(
                source=source, npm=None, download=False, config_path=env.config_path
            )
    env.check_failures["0.161.0"] = "codex_thread_isolation_unproven"
    with pytest.raises(ValueError, match="codex_thread_isolation_unproven"):
        await module.codex_evaluator_runtime_install(
            source=env.executable("isolation/codex", "0.161.0"),
            npm=None,
            download=False,
            config_path=env.config_path,
        )
    installed = await module.codex_evaluator_runtime_install(
        source=source, npm=None, download=False, config_path=env.config_path
    )
    assert installed["managed_runtime_state"] == "verified"
    assert installed["runtime_version"] == "0.159.0"


async def test_repair_keeps_the_fallback_role_of_a_pairing(env: _Env) -> None:
    env.write_config(
        env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")),
        fallback_behind_api=True,
    )

    result = await module.codex_subscription_repair(
        config_path=env.config_path, executable=env.executable("evaluator/codex")
    )

    written = env.written()
    assert result["endpoint_role"] == "fallback"
    assert written.semantic_fallback == SemanticFallbackConfig(primary="api_provider")
    assert written.provider is not None


@pytest.mark.parametrize(
    ("fault", "token"),
    [
        ("config_changed", "codex_runtime_config_changed"),
        ("home_missing", "codex_home_missing"),
    ],
)
async def test_hand_fix_states_are_refused_before_any_side_effect(
    env: _Env, fault: str, token: str
) -> None:
    binding = env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1"))
    home = Path(binding.codex_home)
    if fault == "config_changed":
        (home / "config.toml").write_text('approval_policy = "on-request"\n', encoding="utf-8")
    else:
        (home / "config.toml").unlink()
        home.rmdir()
    env.write_config(binding)
    preimage = env.config_path.read_bytes()

    with pytest.raises(ValueError, match=token):
        await module.codex_subscription_repair(
            config_path=env.config_path, executable=env.executable("evaluator/codex")
        )
    assert env.config_path.read_bytes() == preimage
    assert env.codex.probes == [] and env.checked == []
    assert not env.managed().exists()
    assert module.binding_continuation(token) is not None


async def test_repair_restores_a_missing_isolated_config_without_touching_login(
    env: _Env,
) -> None:
    binding = env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1"))
    (Path(binding.codex_home) / "config.toml").unlink()
    env.write_config(binding)

    await module.codex_subscription_repair(
        config_path=env.config_path, executable=env.executable("evaluator/codex")
    )

    config = Path(binding.codex_home) / "config.toml"
    assert config.read_bytes() == CODEX_EVALUATOR_CONFIG.encode()
    assert env.codex.logins == []


async def test_repair_needs_an_eligible_runtime_and_a_binding(env: _Env) -> None:
    env.write_config(None)
    with pytest.raises(ValueError, match="codex_subscription_not_configured"):
        await module.codex_subscription_repair(config_path=env.config_path)
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.150.1")))
    env.discovered.append(env.executable("other/codex", "0.153.4"))
    with pytest.raises(ValueError, match="codex_evaluator_runtime_unavailable"):
        await module.codex_subscription_repair(config_path=env.config_path)


def test_repair_plan_has_no_side_effects(env: _Env) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    env.discovered.append(env.executable("older/codex", "0.157.1"))
    preimage = env.config_path.read_bytes()

    plan = module.codex_subscription_repair_plan(config_path=env.config_path)

    assert plan["state_before"] == "codex_runtime_executable_changed"
    assert plan["capability_profile_before"] == "codex-evaluator/0.157.1/v2"
    assert plan["capability_profile_after"] == CODEX_EVALUATOR_CAPABILITY_PROFILE
    assert (plan["runtime_version_before"], plan["runtime_version_after"]) == (
        "0.157.1",
        "0.162.1",
    )
    assert [
        cast(Mapping[str, object], item)["runtime_version"]
        for item in cast(list[object], plan["candidates"])
    ] == ["0.162.1", "0.157.1"]
    assert plan["executable_path_after"] == str(env.managed("0.162.1"))
    preserved = cast(Mapping[str, object], plan["preserved"])
    assert {name: preserved[name] for name in _OWNER_CHOICES} == {
        "model": "gpt-5.6-sol",
        "reasoning_effort": "xhigh",
        "timeout_seconds": 37,
        "max_retries": 0,
        "codex_home": str(env.tmp / "evaluator-home"),
    }
    assert "executable_path" not in preserved and "capability_profile" not in preserved
    assert env.config_path.read_bytes() == preimage
    assert not env.bundle.exists()
    assert env.codex.probes == [] and env.checked == []


# -- selection and preservation -----------------------------------------------------------------


async def test_rebinding_preserves_timeout_and_retry_budgets(env: _Env) -> None:
    """The 37-second / zero-retry reproduction from #855."""

    existing = await env.checked_binding()
    record = runtime_store.read_capability_record(Path(existing.executable_path).parent)
    rebuilt = module._binding(  # pyright: ignore[reportPrivateUsage]
        record=record,
        executable=Path(existing.executable_path),
        codex_home=Path(existing.codex_home),
        model=existing.model,
        reasoning_effort=existing.reasoning_effort,
        existing=existing,
    )
    fresh = module._binding(  # pyright: ignore[reportPrivateUsage]
        record=record,
        executable=Path(existing.executable_path),
        codex_home=Path(existing.codex_home),
        model=existing.model,
        reasoning_effort=existing.reasoning_effort,
    )

    defaults = inspect.signature(codex_subscription_runtime).parameters
    assert (rebuilt.timeout_seconds, rebuilt.max_retries) == (37, 0)
    assert (fresh.timeout_seconds, fresh.max_retries) == (
        defaults["timeout_seconds"].default,
        defaults["max_retries"].default,
    )


@pytest.mark.parametrize("routine_effort", [None, "low"])
async def test_setup_rerun_preserves_budgets_and_effort_defaults(
    env: _Env, routine_effort: str | None
) -> None:
    env.write_config(
        await env.checked_binding(
            routine_reasoning_effort=routine_effort,
            routine_output_limit=2048,
            final_output_limit=6000,
        )
    )
    assert module.default_codex_subscription_reasoning_effort(env.config_path) == "xhigh"
    assert module.default_codex_subscription_model(env.config_path) == "gpt-5.6-sol"

    await module.codex_subscription_setup(
        executable=None,
        codex_home=env.home(),
        model="gpt-5.6-sol",
        reasoning_effort=module.default_codex_subscription_reasoning_effort(env.config_path),
        login_mode="browser",
        open_browser=False,
        switch_account=False,
        config_path=env.config_path,
    )

    bound = env.written().external_runtime
    assert bound is not None
    assert (bound.timeout_seconds, bound.max_retries, bound.reasoning_effort) == (37, 0, "xhigh")
    assert bound.routine_reasoning_effort == routine_effort
    assert (bound.routine_output_limit, bound.final_output_limit) == (2048, 6000)
    assert bound.executable_path == str(env.managed())


async def test_selection_is_newest_release_first_then_ownership(env: _Env) -> None:
    config = env.write_config(None)
    assert module.select_codex_evaluator_executable(config) is None

    # Lexically first, but below the floor: never offered.
    env.discovered.append(env.executable("a-first/codex", "0.153.4"))
    assert module.select_codex_evaluator_executable(config) is None
    eligible = env.executable("z-last/codex", "0.159.0")
    env.discovered.append(eligible)
    assert module.select_codex_evaluator_executable(config) == ("discovered", eligible)

    # A newer release wins regardless of where it lives.
    bound = env.executable("bound/codex", "0.162.1")
    config = env.write_config(env.pinned_binding(bound))
    assert module.select_codex_evaluator_executable(config) == ("binding", bound)

    # On an equal release, Yoetz's retained copy wins over a host installation.
    runtime_store.retain_codex_runtime(
        bound, bundle=env.bundle, source_identity=codex_source_identity(LINUX, "0.162.1")
    )
    assert module.select_codex_evaluator_executable(config) == (
        "managed",
        env.managed("0.162.1"),
    )
    assert [item.version for item in module.evaluator_candidates(config)] == [
        "0.162.1",
        "0.159.0",
    ]


async def test_setup_without_an_eligible_runtime_fails_before_any_side_effect(env: _Env) -> None:
    env.write_config(None)
    env.discovered.append(env.executable("host/codex", "0.150.1"))
    preimage = env.config_path.read_bytes()

    with pytest.raises(ValueError, match="codex_evaluator_runtime_unavailable"):
        await module.codex_subscription_setup(
            executable=None,
            codex_home=env.tmp / "new-home",
            model="gpt-5.6-luna",
            reasoning_effort="high",
            login_mode="browser",
            open_browser=False,
            switch_account=False,
            config_path=env.config_path,
        )

    assert env.config_path.read_bytes() == preimage
    assert not (env.tmp / "new-home").exists()
    assert env.codex.probes == [] and env.codex.logins == []


# -- status, disconnect, runtime commands -------------------------------------------------------


async def test_status_names_the_structural_cause_before_starting_codex(env: _Env) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))

    with pytest.raises(ValueError, match="codex_runtime_executable_changed"):
        await module.codex_subscription_status(config_path=env.config_path)
    assert env.codex.probes == []


async def test_disconnect_logs_out_a_stranded_home_through_a_checked_runtime(
    env: _Env,
) -> None:
    # The bound host install was replaced by a release below the floor: not a candidate.
    stranded = env.pinned_binding(env.executable("npm-prefix/codex", "0.150.1"))
    env.write_config(stranded)
    runtime_store.retain_codex_runtime(
        env.executable("evaluator/codex"),
        bundle=env.bundle,
        source_identity=codex_source_identity(LINUX, "0.159.0"),
    )

    result = await module.codex_subscription_disconnect(config_path=env.config_path)

    (logout,) = env.codex.logouts
    assert logout.executable_path == env.managed()
    assert logout.codex_home == Path(stranded.codex_home)
    assert result["binding_removed"] is True
    assert env.written().external_runtime is None


async def test_disconnect_without_an_eligible_runtime_keeps_the_binding(env: _Env) -> None:
    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.150.1")))
    preimage = env.config_path.read_bytes()

    with pytest.raises(ValueError, match="codex_runtime_executable_changed"):
        await module.codex_subscription_disconnect(config_path=env.config_path)
    assert env.codex.logouts == []
    assert env.config_path.read_bytes() == preimage


async def test_runtime_status_names_the_next_command_without_starting_codex(env: _Env) -> None:
    env.write_config(None)
    empty = module.codex_evaluator_runtime_status(config_path=env.config_path)
    assert empty["binding"] is None
    assert empty["next_command"] == "yoetz provider codex-subscription runtime install"
    assert (empty["login_checked"], empty["runtime_floor"]) == (False, "0.157.1")
    assert empty["retained_runtimes"] == []

    binding = await env.checked_binding()
    env.write_config(binding)
    managed = module.codex_evaluator_runtime_status(config_path=env.config_path)
    (retained,) = cast(list[Mapping[str, object]], managed["retained_runtimes"])
    assert (retained["runtime_version"], retained["state"]) == ("0.159.0", "verified")
    assert retained["code_mode_host_sha256"] == plain_digest(_HOST_BYTES)
    bound = cast(Mapping[str, object], managed["binding"])
    assert (bound["state"], bound["uses_managed_runtime"], bound["runtime_version"]) == (
        "ready",
        True,
        "0.159.0",
    )
    assert managed["next_command"] is None
    retained_host = env.managed().parent / _HOST_NAME
    assert (bound["code_mode_host"], bound["code_mode_host_path"]) == (
        "admitted",
        str(retained_host),
    )

    retained_host.chmod(0o700)
    retained_host.unlink()
    missing = module.codex_evaluator_runtime_status(config_path=env.config_path)
    (incomplete,) = cast(list[Mapping[str, object]], missing["retained_runtimes"])
    assert incomplete["state"] == "incomplete"
    assert cast(Mapping[str, object], missing["binding"])["code_mode_host"] == "missing"
    assert cast(Mapping[str, object], missing["binding"])["state"] == (
        "codex_runtime_executable_missing"
    )
    assert missing["next_command"] == "yoetz provider codex-subscription repair"
    assert env.codex.probes == []


async def test_runtime_install_checks_local_bytes_or_downloads_only_when_authorized(
    env: _Env,
) -> None:
    env.write_config(None)
    with pytest.raises(ValueError, match="codex_evaluator_runtime_unavailable"):
        module.codex_evaluator_runtime_install_plan(
            source=None, download=False, config_path=env.config_path
        )
    with pytest.raises(ValueError, match="codex_runtime_version_unsupported"):
        await module.codex_evaluator_runtime_install(
            source=env.executable("old/codex", "0.150.1"),
            npm=None,
            download=False,
            config_path=env.config_path,
        )
    assert runtime_store.retained_runtimes(env.bundle, LINUX) == ()

    plan = module.codex_evaluator_runtime_install_plan(
        source=None, download=True, config_path=env.config_path
    )
    assert plan["download"] is True and plan["source_path"] is None
    assert plan["runtime_version"] == "latest"
    installed = await module.codex_evaluator_runtime_install(
        source=None, npm=Path("/opt/npm/bin/npm"), download=True, config_path=env.config_path
    )
    assert env.downloads == [Path("/opt/npm/bin/npm")]
    assert installed["managed_runtime_path"] == str(env.managed("0.162.1"))
    assert installed["managed_runtime_state"] == "verified"
    assert installed["runtime_version"] == "0.162.1"
    assert installed["binding_changed"] is False
    assert installed["next_command"] == "yoetz provider codex-subscription setup"

    # A checked copy now satisfies later installs locally; nothing is downloaded again.
    again = await module.codex_evaluator_runtime_install(
        source=None, npm=None, download=True, config_path=env.config_path
    )
    assert again["source"] == "managed"
    assert env.downloads == [Path("/opt/npm/bin/npm")]


async def test_runtime_remove_deletes_unreferenced_releases_and_never_the_bound_one(
    env: _Env,
) -> None:
    binding = await env.checked_binding("0.162.1")
    await env.checked_binding("0.159.0")
    env.write_config(binding)

    removed = module.codex_evaluator_runtime_remove(config_path=env.config_path)

    assert removed["removed_runtimes"] == [str(env.managed("0.159.0"))]
    assert removed["kept_runtime_path"] == str(env.managed("0.162.1"))
    assert env.managed("0.162.1").exists() and not env.managed("0.159.0").exists()
    with pytest.raises(ValueError, match="codex_evaluator_runtime_in_use"):
        module.codex_evaluator_runtime_remove(config_path=env.config_path)

    module.codex_subscription_rollback(config_path=env.config_path)
    home = env.tmp / "evaluator-home"
    removed = module.codex_evaluator_runtime_remove(config_path=env.config_path)
    assert removed["removed"] is True
    assert not env.managed("0.162.1").exists()
    assert (home / "config.toml").exists()


# -- operator surfaces --------------------------------------------------------------------------


def test_failure_lines_name_the_cause_and_next_step() -> None:
    line = module.subscription_failure_line(ValueError("codex_runtime_executable_changed"))
    assert line.startswith("codex_subscription: codex_runtime_executable_changed: ")
    assert "repair" in line
    for state, command in module.BINDING_CONTINUATIONS.items():
        assert module.subscription_remediation(state) is not None, state
        assert command.startswith("yoetz "), state
    for token in (
        "codex_runtime_version_unsupported",
        "codex_runtime_protocol_incompatible",
        "codex_model_unavailable",
        "codex_app_server_predisclosure_event_forbidden",
    ):
        assert module.subscription_remediation(token) is not None, token
    assert module.binding_continuation("ready") is None


def test_cli_repair_needs_explicit_acceptance_and_recomposes_after(
    env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.cli.app import app

    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    env.discovered.append(env.executable("everyday/codex", "0.162.1"))
    restarts: list[str] = []

    async def restart() -> dict[str, object]:
        restarts.append("restart")
        return {"reachable": True, "state": "ready", "vault_mode": None}

    monkeypatch.setattr("yoetz.cli.setup.restart_service_for_semantic_composition", restart)
    runner = CliRunner()
    preimage = env.config_path.read_bytes()

    refused = runner.invoke(app, ["provider", "codex-subscription", "repair"])
    assert refused.exit_code == 20
    assert env.config_path.read_bytes() == preimage
    assert restarts == []

    accepted = runner.invoke(app, ["provider", "codex-subscription", "repair", "--accept"])
    assert accepted.exit_code == 0, accepted.output
    assert "Codex: 0.157.1 -> 0.162.1" in accepted.output
    assert restarts == ["restart"]
    rewritten = tomllib.loads(env.config_path.read_text(encoding="utf-8"))
    assert rewritten["external_runtime"]["executable_path"] == str(env.managed("0.162.1"))
    assert rewritten["external_runtime"]["runtime_version"] == "0.162.1"
    assert rewritten["external_runtime"]["timeout_seconds"] == 37


def test_cli_runtime_status_exit_code_follows_the_binding(env: _Env) -> None:
    from yoetz.cli.app import app

    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    runner = CliRunner()
    stranded = runner.invoke(app, ["provider", "codex-subscription", "runtime", "status", "--json"])
    assert stranded.exit_code == 20
    assert "codex_runtime_executable_changed" in stranded.stdout

    env.write_config(None)
    unbound = runner.invoke(app, ["provider", "codex-subscription", "runtime", "status", "--json"])
    assert unbound.exit_code == 0


def test_cli_failure_renders_the_subscription_remediation(env: _Env) -> None:
    from yoetz.cli.app import app

    env.write_config(env.pinned_binding(env.executable("npm-prefix/codex", "0.162.1")))
    result = CliRunner().invoke(app, ["provider", "codex-subscription", "status"])

    assert result.exit_code == 20
    assert "codex_subscription: codex_runtime_executable_changed: " in result.stderr
    assert "yoetz provider codex-subscription repair" in result.stderr
    assert str(env.tmp) not in result.stderr


async def test_guided_setup_offers_only_an_eligible_runtime_or_the_consented_download(
    env: _Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    env.write_config(None)
    env.discovered.append(env.executable("host/codex", "0.150.1"))
    prompts: list[tuple[str, object]] = []
    answers = {"Download the evaluator runtime now?": False}

    def prompt(message: str, **kwargs: object) -> str:
        prompts.append((message, kwargs.get("default")))
        raise KeyboardInterrupt

    def confirm(message: str, **_kwargs: object) -> bool:
        return answers[message]

    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr("typer.confirm", confirm)

    with pytest.raises(KeyboardInterrupt):
        await module._prompt_evaluator_executable()  # pyright: ignore[reportPrivateUsage]
    # The host binary below the floor is not offered; declining the download leaves no default.
    assert prompts == [("Codex evaluator executable", None)]
    assert env.downloads == []

    answers["Download the evaluator runtime now?"] = True
    prompts.clear()
    with pytest.raises(KeyboardInterrupt):
        await module._prompt_evaluator_executable()  # pyright: ignore[reportPrivateUsage]
    assert prompts == [("Codex evaluator executable", str(env.managed("0.162.1")))]
    assert len(env.downloads) == 1
