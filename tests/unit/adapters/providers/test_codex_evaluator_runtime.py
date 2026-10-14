"""Issue #855: the retained evaluator runtime and the structural binding diagnosis.

Every case runs against synthetic bytes. The admitted digest is substituted through the module's
own digest seams, so no real Codex executable, package manager, or data directory is involved.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from finishup.adapters.providers import codex_app_server
from finishup.adapters.providers import codex_evaluator_runtime as module
from finishup.adapters.providers.codex_app_server import (
    CODEX_EVALUATOR_CONFIG,
    CODEX_EVALUATOR_RUNTIME_VERSION,
    CodexEvaluatorCell,
    codex_evaluator_cell_for_platform,
)
from finishup.config.models import ExternalRuntimeProfileConfig
from finishup.config.paths import PathSafetyError
from finishup.config.write import codex_subscription_runtime

_ADMITTED_BYTES = b"admitted evaluator runtime bytes"
_HOST_BYTES = b"admitted code-mode host bytes"
_OTHER_BYTES = b"a newer host codex that replaced the bound path"
_HOST = "codex-code-mode-host"


def _plain_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture
def cell(monkeypatch: pytest.MonkeyPatch) -> CodexEvaluatorCell:
    """Pin the host to the Linux x86_64 cell and let the synthetic bytes stand for its digest."""

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    selected = codex_evaluator_cell_for_platform("linux", "x86_64")
    real_digest = module._digest_descriptor  # pyright: ignore[reportPrivateUsage]

    pinned = {
        _plain_digest(_ADMITTED_BYTES): selected.executable_sha256,
        _plain_digest(_HOST_BYTES): selected.code_mode_host_sha256,
    }

    def digest(descriptor: int, sink: object = None) -> str:
        value = real_digest(descriptor, sink)  # pyright: ignore[reportArgumentType]
        return pinned.get(value, value)

    def app_server_digest(path: Path) -> str:
        value = _plain_digest(path.read_bytes())
        return pinned.get(value, value)

    def allow_private(_path: Path) -> None:
        # pytest's temp root is shared temp on Linux; the owner-only gate is locked elsewhere.
        return None

    monkeypatch.setattr(module, "_digest_descriptor", digest)
    monkeypatch.setattr(codex_app_server, "_sha256_file", app_server_digest)
    monkeypatch.setattr(module, "verify_private_local_bundle", allow_private)
    monkeypatch.setattr(codex_app_server, "verify_private_local_bundle", allow_private)
    return selected


def _executable(
    path: Path, data: bytes = _ADMITTED_BYTES, host: bytes | None = _HOST_BYTES
) -> Path:
    """Write a synthetic native executable and, unless ``host`` is None, its code-mode host."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o700)
    if host is not None:
        sibling = path.parent / _HOST
        sibling.write_bytes(host)
        sibling.chmod(0o700)
    return path


def _home(path: Path, config: bytes | None = None) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    (path / "config.toml").write_bytes(
        CODEX_EVALUATOR_CONFIG.encode() if config is None else config
    )
    return path


def _binding(
    cell: CodexEvaluatorCell,
    executable: Path,
    home: Path,
    **overrides: object,
) -> ExternalRuntimeProfileConfig:
    binding = codex_subscription_runtime(
        executable_path=str(executable),
        executable_sha256=cell.executable_sha256,
        runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
        source_identity=cell.source_identity,
        app_server_schema_sha256=cell.app_server_schema_sha256,
        capability_cell_sha256=cell.capability_cell_sha256,
        isolated_config_sha256=cell.isolated_config_sha256,
        capability_profile=cell.capability_profile,
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home=str(home),
        model="gpt-5.6-luna",
        reasoning_effort="high",
    )
    return binding.model_copy(update=overrides)


# -- retained runtime store ---------------------------------------------------------------------


def test_retain_copies_admitted_bytes_into_an_owner_private_store(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    source = _executable(tmp_path / "host" / "codex")
    bundle = tmp_path / "bundle"

    retained = module.retain_codex_runtime(source, bundle=bundle, cell=cell)

    assert retained == module.managed_runtime_path(bundle, cell)
    assert retained.parent.parent == module.managed_runtime_root(bundle)
    assert retained.read_bytes() == _ADMITTED_BYTES
    assert stat.S_IMODE(retained.stat().st_mode) == 0o500
    assert stat.S_IMODE(retained.parent.stat().st_mode) == 0o700
    assert module.inspect_managed_runtime(bundle, cell) == "verified"
    assert sorted(entry.name for entry in retained.parent.iterdir()) == ["codex", _HOST]
    host = module.managed_code_mode_host_path(bundle, cell)
    assert host == retained.parent / _HOST
    assert host.read_bytes() == _HOST_BYTES
    assert stat.S_IMODE(host.stat().st_mode) == 0o500
    assert module.inspect_managed_code_mode_host(bundle, cell) == "verified"


def test_a_store_without_the_code_mode_host_is_incomplete_until_retain_completes_it(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    """A v1 store kept only ``codex``; retain adds the host and never rewrites the executable."""

    bundle = tmp_path / "bundle"
    v1_copy = _executable(module.managed_runtime_path(bundle, cell), host=None)
    v1_copy.chmod(0o500)
    v1_copy.parent.chmod(0o700)
    before = v1_copy.stat()
    assert module.inspect_managed_runtime(bundle, cell) == "incomplete"
    assert module.inspect_managed_code_mode_host(bundle, cell) == "absent"

    retained = module.retain_codex_runtime(
        _executable(tmp_path / "host" / "codex"), bundle=bundle, cell=cell
    )

    assert retained == v1_copy
    assert retained.stat().st_ino == before.st_ino
    assert module.inspect_managed_runtime(bundle, cell) == "verified"


@pytest.mark.parametrize(
    ("host", "token"),
    [
        (None, "codex_runtime_code_mode_host_missing"),
        (_OTHER_BYTES, "codex_runtime_capability_unsupported"),
    ],
)
def test_retain_refuses_a_missing_or_unadmitted_code_mode_host(
    cell: CodexEvaluatorCell, tmp_path: Path, host: bytes | None, token: str
) -> None:
    bundle = tmp_path / "bundle"
    source = _executable(tmp_path / "host" / "codex", host=host)

    with pytest.raises(ValueError, match=token):
        module.retain_codex_runtime(source, bundle=bundle, cell=cell)

    assert module.inspect_managed_runtime(bundle, cell) != "verified"
    assert module.inspect_managed_code_mode_host(bundle, cell) == "absent"
    assert not any(
        entry.name.startswith(".retain-")
        for entry in module.managed_runtime_path(bundle, cell).parent.iterdir()
    )


@pytest.mark.parametrize(("prepare", "state"), [("changed", "changed"), ("mode", "invalid")])
def test_a_retained_code_mode_host_fault_is_never_verified(
    cell: CodexEvaluatorCell, tmp_path: Path, prepare: str, state: str
) -> None:
    bundle = tmp_path / "bundle"
    module.retain_codex_runtime(_executable(tmp_path / "host" / "codex"), bundle=bundle, cell=cell)
    host = module.managed_code_mode_host_path(bundle, cell)
    host.chmod(0o700)
    if prepare == "changed":
        host.write_bytes(_OTHER_BYTES)
    else:
        host.chmod(0o600)

    assert module.inspect_managed_code_mode_host(bundle, cell) == state
    assert module.inspect_managed_runtime(bundle, cell) == state


def test_retain_is_idempotent_and_never_rewrites_a_verified_copy(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    source = _executable(tmp_path / "host" / "codex")
    bundle = tmp_path / "bundle"
    retained = module.retain_codex_runtime(source, bundle=bundle, cell=cell)
    before = retained.stat()

    # The host installation is replaced afterwards; the verified copy is reused as-is.
    _executable(source, _OTHER_BYTES)
    again = module.retain_codex_runtime(source, bundle=bundle, cell=cell)

    assert again == retained
    assert retained.stat().st_ino == before.st_ino
    assert retained.read_bytes() == _ADMITTED_BYTES


def test_retain_refuses_bytes_that_are_not_the_admitted_digest(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    source = _executable(tmp_path / "host" / "codex", _OTHER_BYTES)
    bundle = tmp_path / "bundle"

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        module.retain_codex_runtime(source, bundle=bundle, cell=cell)

    store = module.managed_runtime_path(bundle, cell).parent
    assert list(store.iterdir()) == []
    assert module.inspect_managed_runtime(bundle, cell) == "absent"


def test_retain_replaces_a_corrupted_copy_only_with_verified_bytes(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    corrupted = _executable(module.managed_runtime_path(bundle, cell), _OTHER_BYTES)
    corrupted.parent.chmod(0o700)
    assert module.inspect_managed_runtime(bundle, cell) == "changed"

    retained = module.retain_codex_runtime(
        _executable(tmp_path / "host" / "codex"), bundle=bundle, cell=cell
    )

    assert retained.read_bytes() == _ADMITTED_BYTES
    assert module.inspect_managed_runtime(bundle, cell) == "verified"


def test_retain_refuses_a_missing_source_and_a_symlinked_source(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    with pytest.raises(ValueError, match="codex_runtime_not_found"):
        module.retain_codex_runtime(tmp_path / "absent", bundle=bundle, cell=cell)
    link = tmp_path / "link"
    link.symlink_to(_executable(tmp_path / "host" / "codex"))
    with pytest.raises(ValueError, match="codex_runtime_executable_invalid"):
        module.retain_codex_runtime(link, bundle=bundle, cell=cell)
    assert module.inspect_managed_runtime(bundle, cell) == "absent"


def test_an_unsafe_store_is_reported_and_never_written(
    cell: CodexEvaluatorCell, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    module.retain_codex_runtime(_executable(tmp_path / "host" / "codex"), bundle=bundle, cell=cell)

    def unsafe(_path: Path) -> None:
        raise PathSafetyError("permissions_too_broad")

    monkeypatch.setattr(module, "verify_private_local_bundle", unsafe)

    assert module.inspect_managed_runtime(bundle, cell) == "unsafe"
    with pytest.raises(ValueError, match="codex_evaluator_runtime_store_unsafe"):
        module.retain_codex_runtime(tmp_path / "host" / "codex", bundle=bundle, cell=cell)
    with pytest.raises(ValueError, match="codex_evaluator_runtime_store_unsafe"):
        module.remove_managed_runtime(bundle, cell)
    assert module.managed_runtime_path(bundle, cell).exists()


def test_a_non_executable_copy_is_invalid(cell: CodexEvaluatorCell, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    copy = _executable(module.managed_runtime_path(bundle, cell))
    copy.chmod(0o600)
    assert module.inspect_managed_runtime(bundle, cell) == "invalid"


def test_remove_deletes_only_the_cell_store(cell: CodexEvaluatorCell, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    retained = module.retain_codex_runtime(
        _executable(tmp_path / "host" / "codex"), bundle=bundle, cell=cell
    )
    sibling = _home(bundle / "external-runtimes" / "codex-0.150.1")

    assert module.remove_managed_runtime(bundle, cell) is True
    assert not retained.parent.exists()
    assert (sibling / "config.toml").exists()
    assert (tmp_path / "host" / "codex").read_bytes() == _ADMITTED_BYTES
    assert (tmp_path / "host" / _HOST).read_bytes() == _HOST_BYTES
    assert module.remove_managed_runtime(bundle, cell) is False


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
            native = (
                prefix
                / "node_modules"
                / "@openai"
                / "codex-linux-x64"
                / "vendor"
                / "x86_64-unknown-linux-musl"
                / "bin"
                / "codex"
            )
            _executable(native)
        return 0


def _resolve_hoisted(wrapper: Path) -> Path:
    return (
        wrapper.parents[2]
        / "codex-linux-x64"
        / "vendor"
        / "x86_64-unknown-linux-musl"
        / "bin"
        / "codex"
    )


def test_provision_installs_without_scripts_retains_only_verified_bytes_and_cleans_staging(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    npm = _FakeNpm()

    retained = module.provision_codex_runtime(
        bundle=bundle,
        cell=cell,
        runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
        npm=Path("/usr/bin/npm"),
        resolve_wrapper=_resolve_hoisted,
        runner=npm,
    )

    assert retained == module.managed_runtime_path(bundle, cell)
    assert module.inspect_managed_runtime(bundle, cell) == "verified"
    ((argv, cwd),) = npm.calls
    assert argv[:2] == ("/usr/bin/npm", "install")
    assert "--ignore-scripts" in argv
    assert argv[-1] == "@openai/codex@0.157.1"
    assert cwd.parent == module.managed_runtime_root(bundle)
    assert not cwd.exists()
    assert sorted(entry.name for entry in module.managed_runtime_root(bundle).iterdir()) == [
        cell.source_identity
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
    cell: CodexEvaluatorCell, tmp_path: Path, outcome: str, token: str
) -> None:
    bundle = tmp_path / "bundle"
    with pytest.raises(ValueError, match=token):
        module.provision_codex_runtime(
            bundle=bundle,
            cell=cell,
            runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
            npm=Path("/usr/bin/npm"),
            resolve_wrapper=_resolve_hoisted,
            runner=_FakeNpm(outcome=outcome),
        )
    assert module.inspect_managed_runtime(bundle, cell) == "absent"
    assert list(module.managed_runtime_root(bundle).iterdir()) == []


def test_a_downloaded_runtime_with_other_bytes_is_never_retained(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"

    def resolve_other(wrapper: Path) -> Path:
        return _executable(_resolve_hoisted(wrapper), _OTHER_BYTES)

    with pytest.raises(ValueError, match="codex_runtime_capability_unsupported"):
        module.provision_codex_runtime(
            bundle=bundle,
            cell=cell,
            runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
            npm=Path("/usr/bin/npm"),
            resolve_wrapper=resolve_other,
            runner=_FakeNpm(),
        )
    assert module.inspect_managed_runtime(bundle, cell) == "absent"


def test_a_relative_package_manager_is_refused_before_anything_runs(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    npm = _FakeNpm()
    with pytest.raises(ValueError, match="codex_evaluator_runtime_package_manager_unavailable"):
        module.provision_codex_runtime(
            bundle=tmp_path / "bundle",
            cell=cell,
            runtime_version=CODEX_EVALUATOR_RUNTIME_VERSION,
            npm=Path("npm"),
            resolve_wrapper=_resolve_hoisted,
            runner=npm,
        )
    assert npm.calls == []


# -- structural diagnosis -----------------------------------------------------------------------


def test_a_matching_binding_is_ready_only_when_the_launch_fence_agrees(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    binding = _binding(cell, _executable(tmp_path / "codex"), _home(tmp_path / "home"))

    diagnosis = module.diagnose_codex_binding(binding, now=datetime(2026, 9, 26, tzinfo=UTC))

    assert diagnosis == module.CodexBindingDiagnosis(
        "ready", "current", "admitted", "ready", "admitted"
    )
    assert diagnosis.ready


@pytest.mark.parametrize(
    ("prepare", "state", "host_state"),
    [
        ("missing", "codex_runtime_executable_missing", "missing"),
        ("changed", "codex_runtime_executable_changed", "changed"),
        ("not_executable", "codex_runtime_executable_invalid", "invalid"),
    ],
)
def test_a_code_mode_host_fault_is_named_and_refused_by_the_launch_fence(
    cell: CodexEvaluatorCell, tmp_path: Path, prepare: str, state: str, host_state: str
) -> None:
    executable = _executable(tmp_path / "codex")
    host = tmp_path / _HOST
    if prepare == "missing":
        host.unlink()
    elif prepare == "changed":
        host.write_bytes(_OTHER_BYTES)
    else:
        host.chmod(0o600)
    binding = _binding(cell, executable, _home(tmp_path / "home"))

    diagnosis = module.diagnose_codex_binding(binding)

    assert (diagnosis.state, diagnosis.executable, diagnosis.code_mode_host) == (
        state,
        "admitted",
        host_state,
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        codex_app_server.CodexAppServerProfile.from_config(binding).verify_local_binding()


def test_replaced_executable_bytes_are_named_before_any_login(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    """The reproduced incident: the ordinary npm path now holds a newer Codex."""

    binding = _binding(cell, _executable(tmp_path / "codex", _OTHER_BYTES), _home(tmp_path / "h"))
    diagnosis = module.diagnose_codex_binding(binding)
    assert diagnosis.state == "codex_runtime_executable_changed"
    assert diagnosis.executable == "changed"


def test_an_outdated_capability_identity_does_not_hide_replaced_bytes(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    home = _home(tmp_path / "home")
    v1 = {
        "capability_profile": "codex-evaluator/0.150.1/v1",
        "capability_cell_sha256": "sha256:" + "1" * 64,
    }
    same_runtime = _binding(cell, _executable(tmp_path / "same" / "codex"), home, **v1)
    replaced = _binding(
        cell, _executable(tmp_path / "replaced" / "codex", _OTHER_BYTES), home, **v1
    )

    outdated = module.diagnose_codex_binding(same_runtime)
    assert (outdated.state, outdated.capability, outdated.executable) == (
        "codex_runtime_profile_outdated",
        "profile_outdated",
        "admitted",
    )
    both = module.diagnose_codex_binding(replaced)
    assert (both.state, both.capability, both.executable) == (
        "codex_runtime_executable_changed",
        "profile_outdated",
        "changed",
    )


def test_a_binding_naming_another_runtime_is_capability_unsupported(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    home = _home(tmp_path / "home")
    newer = _binding(
        cell,
        _executable(tmp_path / "codex", _OTHER_BYTES),
        home,
        runtime_version="0.153.4",
        executable_sha256=_plain_digest(_OTHER_BYTES),
    )
    assert module.diagnose_codex_binding(newer).state == "codex_runtime_capability_unsupported"
    macos = _binding(
        cell,
        _executable(tmp_path / "mac" / "codex"),
        home,
        source_identity=codex_evaluator_cell_for_platform("darwin", "arm64").source_identity,
    )
    assert module.diagnose_codex_binding(macos).capability == "unsupported"
    # A binding admitted under the superseded 0.150.1 Linux cell names another runtime too; its
    # continuation is repair onto the current cell, never a launch.
    superseded = _binding(
        cell,
        _executable(tmp_path / "old" / "codex", _OTHER_BYTES),
        home,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-linux-x64-0.150.1",
        executable_sha256=(
            "sha256:abf1bb1643a79f73aa78ee627e111e02d4f8c98f25813a0cf6ce277709664386"
        ),
        app_server_schema_sha256=(
            "sha256:8cdccfc35582696d7141e7f916e0d5a664ab5b5e90b732f104284d2507f369f8"
        ),
        capability_profile="codex-evaluator/0.150.1/v2",
    )
    old = module.diagnose_codex_binding(superseded)
    assert (old.state, old.capability) == ("codex_runtime_capability_unsupported", "unsupported")


@pytest.mark.parametrize(
    ("prepare", "state", "executable_state"),
    [
        ("missing", "codex_runtime_executable_missing", "missing"),
        ("not_executable", "codex_runtime_executable_invalid", "invalid"),
        ("directory", "codex_runtime_executable_invalid", "invalid"),
    ],
)
def test_executable_faults_are_distinct(
    cell: CodexEvaluatorCell, tmp_path: Path, prepare: str, state: str, executable_state: str
) -> None:
    path = tmp_path / "codex"
    if prepare == "not_executable":
        _executable(path).chmod(0o600)
    elif prepare == "directory":
        path.mkdir()
    diagnosis = module.diagnose_codex_binding(_binding(cell, path, _home(tmp_path / "home")))
    assert (diagnosis.state, diagnosis.executable) == (state, executable_state)


def test_home_and_isolated_config_faults_are_distinct(
    cell: CodexEvaluatorCell, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = _executable(tmp_path / "codex")

    missing = module.diagnose_codex_binding(_binding(cell, executable, tmp_path / "absent"))
    assert (missing.state, missing.home) == ("codex_home_missing", "missing")

    empty = tmp_path / "empty"
    empty.mkdir(mode=0o700)
    config_missing = module.diagnose_codex_binding(_binding(cell, executable, empty))
    assert config_missing.state == "codex_runtime_config_missing"

    changed = _home(tmp_path / "changed", b'approval_policy = "on-request"\n')
    config_changed = module.diagnose_codex_binding(_binding(cell, executable, changed))
    assert config_changed.state == "codex_runtime_config_changed"

    def unsafe(_path: Path) -> None:
        raise PathSafetyError("permissions_too_broad")

    monkeypatch.setattr(module, "verify_private_local_bundle", unsafe)
    home_unsafe = module.diagnose_codex_binding(_binding(cell, executable, _home(tmp_path / "u")))
    assert (home_unsafe.state, home_unsafe.home) == ("codex_home_unsafe", "unsafe")


def test_expired_evidence_needs_a_timezone_aware_clock(
    cell: CodexEvaluatorCell, tmp_path: Path
) -> None:
    binding = _binding(cell, _executable(tmp_path / "codex"), _home(tmp_path / "home"))

    stale = module.diagnose_codex_binding(binding, now=datetime(2026, 11, 30, tzinfo=UTC))
    assert (stale.state, stale.capability) == (
        "codex_runtime_capability_evidence_stale",
        "evidence_stale",
    )
    with pytest.raises(ValueError, match="codex_runtime_capability_time_invalid"):
        module.diagnose_codex_binding(binding, now=datetime(2026, 9, 26))


@pytest.mark.parametrize("unsafe", ("symlink", "permissions", "directory"))
def test_runtime_mutation_lock_refuses_unsafe_lock_files(
    cell: CodexEvaluatorCell, tmp_path: Path, unsafe: str
) -> None:
    del cell  # The fixture supplies the synthetic platform and private-path boundary.
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
    linux = codex_evaluator_cell_for_platform("linux", "x86_64")
    binding = _binding(linux, tmp_path / "codex", tmp_path / "home")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(module.platform, "machine", lambda: "AMD64")

    diagnosis = module.diagnose_codex_binding(binding)

    assert (diagnosis.state, diagnosis.capability, diagnosis.executable) == (
        "codex_runtime_platform_unsupported",
        "platform_unsupported",
        "not_checked",
    )


def test_relative_paths_are_an_invalid_binding(cell: CodexEvaluatorCell, tmp_path: Path) -> None:
    # The config loader already refuses relative paths; an unvalidated copy is still refused.
    binding = _binding(cell, tmp_path / "codex", tmp_path / "home").model_copy(
        update={"executable_path": "codex", "codex_home": "home"}
    )
    assert module.diagnose_codex_binding(binding).state == "codex_runtime_binding_invalid"


def test_diagnosis_never_starts_a_process(
    cell: CodexEvaluatorCell, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("structural diagnosis must not spawn a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden, raising=False)
    binding = _binding(cell, _executable(tmp_path / "codex"), _home(tmp_path / "home"))
    assert module.diagnose_codex_binding(binding).ready


def test_every_state_is_a_closed_token() -> None:
    for state in module.CODEX_BINDING_STATES:
        assert state.replace("_", "").isalnum() and state == state.lower()
