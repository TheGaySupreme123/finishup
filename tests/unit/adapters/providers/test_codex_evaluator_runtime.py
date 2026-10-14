"""Retained evaluator runtimes, the capability check, and the structural binding diagnosis.

Every case runs against synthetic bytes in ``tmp_path``. The capability check's subprocesses
(``generate-json-schema``) and its app-server probe are replaced by fakes; no real Codex, package
manager, sign-in, or data directory is involved.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from builders.codex_capability import (
    LINUX,
    MAC,
    binding_for,
    minimal_app_server_schema,
    plain_digest,
    record_for,
    retained_runtime,
    write_home,
)
from finishup.adapters.providers import codex_app_server
from finishup.adapters.providers import codex_evaluator_runtime as module
from finishup.adapters.providers.codex_app_server import (
    CODEX_EVALUATOR_CONFIG,
    CODEX_EVALUATOR_CONFIG_SHA256,
    CodexAppServerProfile,
)
from finishup.adapters.providers.codex_capability import (
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CodexCapabilityRecord,
    check_app_server_schema,
    codex_source_identity,
    read_capability_record,
)
from finishup.config.models import ExternalRuntimeProfileConfig
from finishup.config.paths import PathSafetyError

_BYTES = b"codex native bytes"
_HOST_BYTES = b"codex code-mode host bytes"
_OTHER_BYTES = b"a newer host codex that replaced the bound path"
_HOST = "codex-code-mode-host"
_ID = codex_source_identity(MAC, "0.159.0")


@pytest.fixture(autouse=True)
def _mac_host(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    """Pin the host to macOS arm64 and allow pytest's shared temp root as a private store."""

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("platform.machine", lambda: "arm64")

    def allow_private(_path: Path) -> None:
        return None

    monkeypatch.setattr(module, "verify_private_local_bundle", allow_private)
    monkeypatch.setattr(codex_app_server, "verify_private_local_bundle", allow_private)


def _executable(path: Path, data: bytes = _BYTES, host: bytes | None = _HOST_BYTES) -> Path:
    """Write a synthetic native executable and, unless ``host`` is None, its code-mode host."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o700)
    if host is not None:
        sibling = path.parent / _HOST
        sibling.write_bytes(host)
        sibling.chmod(0o700)
    return path


# -- retained runtime store ---------------------------------------------------------------------


def test_retain_copies_bytes_into_a_per_release_owner_private_store(tmp_path: Path) -> None:
    source = _executable(tmp_path / "host" / "codex")
    bundle = tmp_path / "bundle"

    retained = module.retain_codex_runtime(source, bundle=bundle, source_identity=_ID)

    assert retained == module.managed_runtime_path(bundle, _ID)
    assert retained.parent.name == "openai-codex-npm-darwin-arm64-0.159.0"
    assert retained.parent.parent == module.managed_runtime_root(bundle)
    assert retained.read_bytes() == _BYTES
    assert stat.S_IMODE(retained.stat().st_mode) == 0o500
    assert stat.S_IMODE(retained.parent.stat().st_mode) == 0o700
    assert module.managed_code_mode_host_path(bundle, _ID).read_bytes() == _HOST_BYTES
    # Retained, but not admitted until a capability check commits its record.
    assert module.inspect_managed_runtime(bundle, _ID) == "unchecked"
    assert module.is_managed_runtime_path(bundle, retained)
    assert not module.is_managed_runtime_path(bundle, source)

    module.commit_capability_record(bundle, record_for(_BYTES, _HOST_BYTES))
    assert module.inspect_managed_runtime(bundle, _ID) == "verified"
    assert sorted(entry.name for entry in retained.parent.iterdir()) == [
        "capability.json",
        "codex",
        _HOST,
    ]
    assert stat.S_IMODE((retained.parent / "capability.json").stat().st_mode) == 0o400


def test_retain_is_idempotent_and_keeps_the_record_for_unchanged_bytes(tmp_path: Path) -> None:
    source = _executable(tmp_path / "host" / "codex")
    bundle = tmp_path / "bundle"
    retained = module.retain_codex_runtime(source, bundle=bundle, source_identity=_ID)
    module.commit_capability_record(bundle, record_for(_BYTES, _HOST_BYTES))
    inode = retained.stat().st_ino

    again = module.retain_codex_runtime(source, bundle=bundle, source_identity=_ID)

    assert again == retained and retained.stat().st_ino == inode
    assert module.inspect_managed_runtime(bundle, _ID) == "verified"


def test_retaining_other_bytes_drops_the_record_before_replacing_them(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    module.retain_codex_runtime(
        _executable(tmp_path / "host" / "codex"), bundle=bundle, source_identity=_ID
    )
    module.commit_capability_record(bundle, record_for(_BYTES, _HOST_BYTES))

    module.retain_codex_runtime(
        _executable(tmp_path / "other" / "codex", _OTHER_BYTES), bundle=bundle, source_identity=_ID
    )

    # A record never vouches for bytes it did not check.
    assert module.inspect_managed_runtime(bundle, _ID) == "unchecked"
    with pytest.raises(FileNotFoundError):
        read_capability_record(module.managed_runtime_dir(bundle, _ID))


def test_a_store_without_the_code_mode_host_is_incomplete(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    retained_runtime(bundle, host=None, record=False)

    assert module.inspect_managed_runtime(bundle, _ID) == "incomplete"


def test_retain_refuses_a_missing_host_a_missing_source_and_a_symlinked_source(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    with pytest.raises(ValueError, match="codex_runtime_code_mode_host_missing"):
        module.retain_codex_runtime(
            _executable(tmp_path / "lonely" / "codex", host=None),
            bundle=bundle,
            source_identity=_ID,
        )
    with pytest.raises(ValueError, match="codex_runtime_not_found"):
        module.retain_codex_runtime(tmp_path / "absent", bundle=bundle, source_identity=_ID)
    link = tmp_path / "link"
    link.symlink_to(_executable(tmp_path / "host" / "codex"))
    with pytest.raises(ValueError, match="codex_runtime_executable_invalid"):
        module.retain_codex_runtime(link, bundle=bundle, source_identity=_ID)
    assert module.inspect_managed_runtime(bundle, _ID) == "absent"


def test_commit_refuses_a_record_for_bytes_that_changed_after_the_check(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    module.retain_codex_runtime(
        _executable(tmp_path / "host" / "codex"), bundle=bundle, source_identity=_ID
    )

    with pytest.raises(ValueError, match="codex_runtime_executable_changed"):
        module.commit_capability_record(bundle, record_for(_OTHER_BYTES, _HOST_BYTES))
    assert module.inspect_managed_runtime(bundle, _ID) == "unchecked"


def test_an_unsafe_store_is_reported_and_never_written(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    module.retain_codex_runtime(
        _executable(tmp_path / "host" / "codex"), bundle=bundle, source_identity=_ID
    )

    def unsafe(_path: Path) -> None:
        raise PathSafetyError("permissions_too_broad")

    monkeypatch.setattr(module, "verify_private_local_bundle", unsafe)

    assert module.inspect_managed_runtime(bundle, _ID) == "unsafe"
    with pytest.raises(ValueError, match="codex_evaluator_runtime_store_unsafe"):
        module.retain_codex_runtime(tmp_path / "host" / "codex", bundle=bundle, source_identity=_ID)
    with pytest.raises(ValueError, match="codex_evaluator_runtime_store_unsafe"):
        module.remove_managed_runtime(bundle, _ID)
    assert module.managed_runtime_path(bundle, _ID).exists()


def test_a_non_executable_copy_is_invalid(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    copy, _record = retained_runtime(bundle)
    copy.chmod(0o600)
    assert module.inspect_managed_runtime(bundle, _ID) == "invalid"


def test_retained_releases_are_listed_newest_first_for_the_host_platform_only(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    for version in ("0.157.1", "0.162.1", "0.159.0"):
        retained_runtime(bundle, version=version)
    retained_runtime(bundle, version="0.163.0", platform=LINUX)

    listed = module.retained_runtimes(bundle, MAC)

    assert [item.runtime_version for item in listed] == ["0.162.1", "0.159.0", "0.157.1"]
    assert all(item.path.name == "codex" for item in listed)


def test_remove_deletes_only_one_release_and_its_record(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    old, _ = retained_runtime(bundle, version="0.157.1")
    new, _ = retained_runtime(bundle, version="0.159.0")
    sibling = write_home(bundle / "external-runtimes" / "codex-0.150.1")

    assert module.remove_managed_runtime(bundle, codex_source_identity(MAC, "0.157.1")) is True
    assert not old.parent.exists()
    assert module.inspect_managed_runtime(bundle, _ID) == "verified"
    assert (sibling / "config.toml").exists()
    assert new.exists()
    assert module.remove_managed_runtime(bundle, codex_source_identity(MAC, "0.157.1")) is False


# -- package-manager provisioning ---------------------------------------------------------------


class _FakeNpm:
    """Writes the npm-prefix layout the real install produces, or fails as told."""

    def __init__(self, *, outcome: str = "ok") -> None:
        self.outcome = outcome
        self.calls: list[tuple[tuple[str, ...], Path]] = []

    def __call__(self, argv: Sequence[str], cwd: Path) -> int:
        self.calls.append((tuple(argv), cwd))
        if self.outcome == "timeout":
            raise subprocess.TimeoutExpired(tuple(argv), 1.0)
        if self.outcome == "missing":
            raise FileNotFoundError(argv[0])
        if self.outcome == "failed":
            return 1
        prefix = Path(argv[argv.index("--prefix") + 1])
        if self.outcome != "no_wrapper":
            wrapper = prefix / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("#!/usr/bin/env node\n", encoding="utf-8")
            _executable(_hoisted_native(wrapper))
        return 0


def _hoisted_native(wrapper: Path) -> Path:
    return wrapper.parents[2] / "codex-darwin-arm64" / MAC.native_executable_relative


def _resolve_hoisted(wrapper: Path) -> tuple[Path, str]:
    return _hoisted_native(wrapper), "0.162.1"


def test_provision_downloads_the_newest_release_and_retains_only_its_native_files(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    npm = _FakeNpm()

    retained, version = module.provision_codex_runtime(
        bundle=bundle,
        platform=MAC,
        npm=Path("/usr/bin/npm"),
        resolve_wrapper=_resolve_hoisted,
        runner=npm,
    )

    identity = codex_source_identity(MAC, "0.162.1")
    assert (retained, version) == (module.managed_runtime_path(bundle, identity), "0.162.1")
    assert module.inspect_managed_runtime(bundle, identity) == "unchecked"
    ((argv, cwd),) = npm.calls
    assert argv[:2] == ("/usr/bin/npm", "install")
    assert "--ignore-scripts" in argv
    assert argv[-1] == "@openai/codex@latest"
    assert cwd.parent == module.managed_runtime_root(bundle)
    assert not cwd.exists()
    assert sorted(entry.name for entry in module.managed_runtime_root(bundle).iterdir()) == [
        identity
    ]


@pytest.mark.parametrize(
    ("outcome", "token"),
    [
        ("failed", "codex_evaluator_runtime_download_failed"),
        ("timeout", "codex_evaluator_runtime_download_timeout"),
        ("missing", "codex_evaluator_runtime_package_manager_unavailable"),
        ("no_wrapper", "codex_runtime_not_found"),
    ],
)
def test_a_failed_download_leaves_no_retained_runtime_or_staging(
    tmp_path: Path, outcome: str, token: str
) -> None:
    bundle = tmp_path / "bundle"
    with pytest.raises(ValueError, match=token):
        module.provision_codex_runtime(
            bundle=bundle,
            platform=MAC,
            npm=Path("/usr/bin/npm"),
            resolve_wrapper=_resolve_hoisted,
            runner=_FakeNpm(outcome=outcome),
        )
    assert list(module.managed_runtime_root(bundle).iterdir()) == []


def test_a_relative_package_manager_is_refused_before_anything_runs(tmp_path: Path) -> None:
    npm = _FakeNpm()
    with pytest.raises(ValueError, match="codex_evaluator_runtime_package_manager_unavailable"):
        module.provision_codex_runtime(
            bundle=tmp_path / "bundle",
            platform=MAC,
            npm=Path("npm"),
            resolve_wrapper=_resolve_hoisted,
            runner=npm,
        )
    assert npm.calls == []


# -- the capability check -----------------------------------------------------------------------


class _SchemaRunner:
    """Stands in for ``codex app-server generate-json-schema`` writing one document."""

    def __init__(self, document: Mapping[str, object] | None = None, code: int = 0) -> None:
        self.document = minimal_app_server_schema() if document is None else document
        self.code = code
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[Mapping[str, str]] = []

    def __call__(self, argv: Sequence[str], cwd: Path, env: Mapping[str, str]) -> tuple[int, bytes]:
        self.calls.append(tuple(argv))
        self.environments.append(dict(env))
        out = Path(argv[argv.index("--out") + 1])
        (out / "codex_app_server_protocol.v2.schemas.json").write_text(
            json.dumps(self.document), encoding="utf-8"
        )
        return self.code, b""


class _Probe:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.profiles: list[CodexAppServerProfile] = []

    async def __call__(self, profile: CodexAppServerProfile) -> None:
        self.profiles.append(profile)
        # The probe sees the exact launch fence a review uses, against the scratch home.
        profile.verify_local_binding()
        if self.error is not None:
            raise self.error


async def _check(
    tmp_path: Path,
    *,
    version: str = "0.159.0",
    runner: _SchemaRunner | None = None,
    probe: _Probe | None = None,
    host: bytes | None = _HOST_BYTES,
) -> tuple[CodexCapabilityRecord, _SchemaRunner, _Probe, Path]:
    bundle = tmp_path / "bundle"
    executable, _record = retained_runtime(bundle, version=version, host=host, record=False)
    schema = runner or _SchemaRunner()
    checker = probe or _Probe()
    result = await module.check_codex_capability(
        executable,
        runtime_version=version,
        platform=MAC,
        scratch_parent=module.managed_runtime_root(bundle),
        probe=checker,
        runner=schema,
    )
    return result, schema, checker, bundle


@pytest.mark.anyio
@pytest.mark.parametrize("version", ["0.157.1", "0.159.0", "0.162.1"])
async def test_a_release_at_or_above_the_floor_earns_a_deterministic_record(
    tmp_path: Path, version: str
) -> None:
    record, schema, probe, bundle = await _check(tmp_path, version=version)

    assert record == CodexCapabilityRecord(
        runtime_version=version,
        source_identity=codex_source_identity(MAC, version),
        platform_os="darwin",
        platform_architecture="arm64",
        executable_sha256=plain_digest(b"retained codex native bytes"),
        code_mode_host_sha256=plain_digest(_HOST_BYTES),
        app_server_schema_sha256=check_app_server_schema(minimal_app_server_schema()),
        isolated_config_sha256=CODEX_EVALUATOR_CONFIG_SHA256,
    )
    ((argv),) = schema.calls
    assert argv[1:4] == ("app-server", "generate-json-schema", "--out")
    (env,) = schema.environments
    assert set(env) == {"CODEX_HOME", "LANG", "LC_ALL", "PATH", "RUST_LOG"}
    (profile,) = probe.profiles
    # The probe ran the retained bytes under a scratch home holding only the isolated config,
    # never a real Codex home; the scratch directory is gone afterwards.
    assert profile.capability_record is not None
    assert profile.capability_profile == CODEX_EVALUATOR_CAPABILITY_PROFILE
    assert profile.codex_home.parent.parent == module.managed_runtime_root(bundle)
    assert not profile.codex_home.exists()
    assert sorted(entry.name for entry in module.managed_runtime_root(bundle).iterdir()) == [
        codex_source_identity(MAC, version)
    ]


@pytest.mark.anyio
async def test_the_check_is_identical_for_the_same_bytes(tmp_path: Path) -> None:
    first, *_ = await _check(tmp_path / "one")
    second, *_ = await _check(tmp_path / "two")
    assert first == second


@pytest.mark.anyio
@pytest.mark.parametrize("version", ["0.153.4", "0.150.1", "0.163.0-alpha.9"])
async def test_a_release_below_the_floor_is_refused_before_anything_runs(
    tmp_path: Path, version: str
) -> None:
    schema, probe = _SchemaRunner(), _Probe()
    executable = _executable(tmp_path / "candidate" / "codex")

    with pytest.raises(ValueError, match="codex_runtime_version_unsupported"):
        await module.check_codex_capability(
            executable,
            runtime_version=version,
            platform=MAC,
            scratch_parent=tmp_path,
            probe=probe,
            runner=schema,
        )
    assert schema.calls == [] and probe.profiles == []


@pytest.mark.anyio
async def test_a_missing_code_mode_host_fails_the_check(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="codex_runtime_code_mode_host_missing"):
        await _check(tmp_path, host=None)


def _without(document: dict[str, object], name: str, prop: str) -> dict[str, object]:
    definitions = cast(dict[str, dict[str, dict[str, object]]], document["definitions"])
    del definitions[name]["properties"][prop]
    return document


@pytest.mark.anyio
async def test_a_protocol_regression_fails_the_check_before_any_app_server_session(
    tmp_path: Path,
) -> None:
    probe = _Probe()
    document = _without(minimal_app_server_schema(), "ThreadStartResponse", "sandbox")

    with pytest.raises(ValueError, match="codex_runtime_protocol_incompatible"):
        await _check(tmp_path, runner=_SchemaRunner(document), probe=probe)
    assert probe.profiles == []


@pytest.mark.anyio
async def test_a_schema_the_binary_cannot_generate_fails_the_check(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="codex_runtime_protocol_unavailable"):
        await _check(tmp_path, runner=_SchemaRunner(code=2))


@pytest.mark.anyio
@pytest.mark.parametrize(
    "token",
    [
        "codex_app_server_predisclosure_event_forbidden",
        "codex_thread_isolation_unproven",
        "codex_runtime_version_mismatch",
    ],
)
async def test_a_failed_probe_fails_the_check_with_its_token(tmp_path: Path, token: str) -> None:
    with pytest.raises(ValueError, match=token):
        await _check(tmp_path, probe=_Probe(ValueError(token)))
    # Nothing is committed: the store still holds no record for those bytes.
    identity = codex_source_identity(MAC, "0.159.0")
    assert module.inspect_managed_runtime(tmp_path / "bundle", identity) == "unchecked"


# -- structural diagnosis -----------------------------------------------------------------------


def _ready(tmp_path: Path, **overrides: object) -> tuple[Path, ExternalRuntimeProfileConfig]:
    bundle = tmp_path / "bundle"
    executable, record = retained_runtime(bundle)
    binding = binding_for(record, executable, write_home(tmp_path / "home"), **overrides)
    return executable, binding


def test_a_checked_binding_is_ready_only_when_the_launch_fence_agrees(tmp_path: Path) -> None:
    _executable_path, binding = _ready(tmp_path)

    diagnosis = module.diagnose_codex_binding(binding)

    assert (
        diagnosis.state,
        diagnosis.capability,
        diagnosis.executable,
        diagnosis.code_mode_host,
        diagnosis.home,
    ) == ("ready", "current", "admitted", "admitted", "ready")


@pytest.mark.parametrize(
    ("target", "executable_axis", "host_axis"),
    [
        ("codex", "changed", "not_checked"),
        ("codex-code-mode-host", "admitted", "changed"),
        ("capability.json", "changed", "admitted"),
    ],
)
def test_bytes_or_record_replaced_after_the_check_are_named_before_any_login(
    tmp_path: Path, target: str, executable_axis: str, host_axis: str
) -> None:
    executable, binding = _ready(tmp_path)
    changed = executable.parent / target
    changed.chmod(0o700)
    if target == "capability.json":
        changed.write_text(
            json.dumps(record_for(_OTHER_BYTES, _HOST_BYTES).to_json()), encoding="utf-8"
        )
    else:
        changed.write_bytes(_OTHER_BYTES)

    diagnosis = module.diagnose_codex_binding(binding)

    assert diagnosis.state == "codex_runtime_executable_changed"
    assert diagnosis.executable == executable_axis
    if host_axis != "not_checked":
        assert diagnosis.code_mode_host == host_axis


def test_a_missing_record_or_host_is_a_missing_runtime(tmp_path: Path) -> None:
    executable, binding = _ready(tmp_path)
    (executable.parent / "capability.json").unlink()
    missing_record = module.diagnose_codex_binding(binding)
    assert (missing_record.state, missing_record.executable) == (
        "codex_runtime_executable_missing",
        "missing",
    )

    executable, binding = _ready(tmp_path / "other")
    (executable.parent / _HOST).unlink()
    missing_host = module.diagnose_codex_binding(binding)
    assert (missing_host.state, missing_host.code_mode_host) == (
        "codex_runtime_executable_missing",
        "missing",
    )


def test_a_pinned_cell_binding_is_outdated_and_replaced_bytes_stay_visible(
    tmp_path: Path,
) -> None:
    """A ``codex-evaluator/0.157.1/v2`` binding from before capability admission."""

    home = write_home(tmp_path / "home")
    host_install = _executable(tmp_path / "npm-prefix" / "codex")
    pinned = {
        "runtime_version": "0.157.1",
        "source_identity": "openai-codex-npm-darwin-arm64-0.157.1",
        "executable_sha256": plain_digest(_BYTES),
        "capability_profile": "codex-evaluator/0.157.1/v2",
        "capability_cell_sha256": "sha256:" + "a" * 64,
        "app_server_schema_sha256": "sha256:" + "2" * 64,
    }
    legacy = binding_for(record_for(_BYTES, _HOST_BYTES), host_install, home, **pinned)

    same = module.diagnose_codex_binding(legacy)
    assert (same.state, same.capability, same.executable) == (
        "codex_runtime_profile_outdated",
        "profile_outdated",
        "admitted",
    )

    host_install.write_bytes(_OTHER_BYTES)  # an ordinary `npm install -g @openai/codex@latest`
    replaced = module.diagnose_codex_binding(legacy)
    assert (replaced.state, replaced.capability, replaced.executable) == (
        "codex_runtime_executable_changed",
        "profile_outdated",
        "changed",
    )


def test_a_binding_below_the_floor_is_its_own_state(tmp_path: Path) -> None:
    _executable_path, binding = _ready(
        tmp_path,
        runtime_version="0.153.4",
        source_identity="openai-codex-npm-darwin-arm64-0.153.4",
    )

    diagnosis = module.diagnose_codex_binding(binding)

    assert (diagnosis.state, diagnosis.capability) == (
        "codex_runtime_version_unsupported",
        "unsupported",
    )


def test_a_linux_binding_on_a_mac_host_is_capability_unsupported(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    executable, record = retained_runtime(bundle, platform=LINUX)
    binding = binding_for(record, executable, write_home(tmp_path / "home"))

    diagnosis = module.diagnose_codex_binding(binding)

    assert (diagnosis.state, diagnosis.capability) == (
        "codex_runtime_capability_unsupported",
        "unsupported",
    )


def test_home_and_isolated_config_faults_are_distinct(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    executable, record = retained_runtime(bundle)

    missing = module.diagnose_codex_binding(binding_for(record, executable, tmp_path / "absent"))
    assert (missing.state, missing.home) == ("codex_home_missing", "missing")

    empty = tmp_path / "empty"
    empty.mkdir(mode=0o700)
    config_missing = module.diagnose_codex_binding(binding_for(record, executable, empty))
    assert config_missing.state == "codex_runtime_config_missing"

    changed = tmp_path / "changed"
    changed.mkdir(mode=0o700)
    (changed / "config.toml").write_bytes(b'approval_policy = "on-request"\n')
    config_changed = module.diagnose_codex_binding(binding_for(record, executable, changed))
    assert config_changed.state == "codex_runtime_config_changed"

    def unsafe(_path: Path) -> None:
        raise PathSafetyError("permissions_too_broad")

    monkeypatch.setattr(module, "verify_private_local_bundle", unsafe)
    home_unsafe = module.diagnose_codex_binding(
        binding_for(record, executable, write_home(tmp_path / "u"))
    )
    assert (home_unsafe.state, home_unsafe.home) == ("codex_home_unsafe", "unsafe")
    assert CODEX_EVALUATOR_CONFIG.encode() == (tmp_path / "u" / "config.toml").read_bytes()


def test_expired_evidence_needs_a_timezone_aware_clock(tmp_path: Path) -> None:
    _executable_path, binding = _ready(tmp_path)

    stale = module.diagnose_codex_binding(binding, now=datetime(2026, 11, 30, tzinfo=UTC))
    assert (stale.state, stale.capability) == (
        "codex_runtime_capability_evidence_stale",
        "evidence_stale",
    )
    with pytest.raises(ValueError, match="codex_runtime_capability_time_invalid"):
        module.diagnose_codex_binding(binding, now=datetime(2026, 9, 26))


@pytest.mark.parametrize("unsafe", ("symlink", "permissions", "directory"))
def test_runtime_mutation_lock_refuses_unsafe_lock_files(tmp_path: Path, unsafe: str) -> None:
    root = module.managed_runtime_root(tmp_path / "bundle")
    root.mkdir(parents=True, mode=0o700)
    lock = root / ".mutation.lock"
    if unsafe == "symlink":
        target = tmp_path / "unrelated"
        target.write_text("preserved")
        lock.symlink_to(target)
    elif unsafe == "permissions":
        lock.write_text("")
        lock.chmod(0o644)
    else:
        lock.mkdir()
    with pytest.raises(ValueError, match="codex_evaluator_runtime_store_"):
        with module.runtime_mutation_lock(tmp_path / "bundle"):
            pytest.fail("unsafe lock must not admit a mutation")
    if unsafe == "symlink":
        assert lock.read_text() == "preserved"


def test_an_unsupported_host_platform_is_its_own_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _executable_path, binding = _ready(tmp_path)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("platform.machine", lambda: "AMD64")

    diagnosis = module.diagnose_codex_binding(binding)

    assert (diagnosis.state, diagnosis.capability, diagnosis.executable) == (
        "codex_runtime_platform_unsupported",
        "platform_unsupported",
        "not_checked",
    )


def test_relative_paths_are_an_invalid_binding(tmp_path: Path) -> None:
    # The config loader already refuses relative paths; an unvalidated copy is still refused.
    _executable_path, binding = _ready(tmp_path)
    relative = binding.model_copy(update={"executable_path": "codex", "codex_home": "home"})
    assert module.diagnose_codex_binding(relative).state == "codex_runtime_binding_invalid"


def test_diagnosis_never_starts_a_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("structural diagnosis must not spawn a process")

    _executable_path, binding = _ready(tmp_path)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden, raising=False)
    assert module.diagnose_codex_binding(binding).ready


def test_every_state_is_a_closed_token() -> None:
    for state in module.CODEX_BINDING_STATES:
        assert state.replace("_", "").isalnum() and state == state.lower()
