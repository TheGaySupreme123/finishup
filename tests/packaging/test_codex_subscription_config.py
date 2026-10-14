"""Codex-subscription lifecycle and resolver checks against a real installed artifact.

Regression slice for issue #520: a valid ``config.toml`` whose ``storage.data_dir`` is the
ordinary TOML string form crashed every ``finishup provider codex-subscription`` command with a
masked ``internal_error`` exit 70 before any command logic ran, because the subscription CLI
strict-validated raw TOML instead of loading through the canonical configuration loader.

Each case installs the built wheel into an isolated root, points ``FINISHUP_CONFIG`` at a real
hand-written TOML file whose ``storage.data_dir`` names an isolated data directory, spawns the
real console script, and requires a bounded, non-internal, path-free diagnostic or a successful
result. Issue #525 additionally exercises the installed wheel's exact npm-layout resolver against
synthetic nested and npm-prefix-hoisted package trees. No case opens a Codex login flow: ``status``
and ``rollback`` never log in, and the bound-runtime case points at an executable that does not
exist, so the runtime probe fails closed locally.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]


def _is_advertised_host() -> bool:
    if sys.platform == "darwin":
        return platform.machine() == "arm64"
    if sys.platform.startswith("linux"):
        return platform.machine() in {"x86_64", "amd64"}
    return False


pytestmark = pytest.mark.skipif(
    not _is_advertised_host(),
    reason="only the v0.1 advertised macOS arm64 / manylinux_2_28 x86-64 cells are certified",
)


@dataclass(frozen=True, slots=True)
class _BuiltDist:
    directory: Path
    wheel: Path


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> _BuiltDist:
    dist_dir = tmp_path_factory.mktemp("codex-subscription-dist")
    result = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    return _BuiltDist(dist_dir, wheels[0])


def _real_cache_dir() -> str:
    result = subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
    return result.stdout.decode("utf-8").strip()


def _tool_install(dist_dir: Path, root: Path, home: Path) -> tuple[Path, dict[str, str]]:
    import os

    tool_dir = root / "tool"
    bin_dir = root / "bin"
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1
    spec = str(wheels[0])
    env = {
        **os.environ,
        "HOME": str(home),
        "UV_TOOL_DIR": str(tool_dir),
        "UV_TOOL_BIN_DIR": str(bin_dir),
        "UV_CACHE_DIR": _real_cache_dir(),
    }

    def _install(offline: bool) -> subprocess.CompletedProcess[bytes]:
        args = ["uv", "tool", "install", "--python", "3.14.6"]
        if offline:
            args.append("--offline")
        args += ["--find-links", str(dist_dir), spec]
        return subprocess.run(args, capture_output=True, timeout=180, env=env, check=False)

    result = _install(offline=True)
    if result.returncode != 0:
        result = _install(offline=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return bin_dir / "finishup", env


def _data_dir_config(root: Path) -> tuple[Path, Path]:
    """Write the real user-shaped TOML with an explicit isolated storage.data_dir."""

    data_dir = root / "state"
    data_dir.mkdir(mode=0o700, exist_ok=True)
    config = root / "config.toml"
    config.write_text(
        f'schema_version = "1"\nprofile = "strict-local"\n\n[storage]\ndata_dir = "{data_dir}"\n',
        encoding="utf-8",
    )
    return config, data_dir


def _codex_package_layout(
    root: Path, *, nested: bool, platform_name: str = "darwin"
) -> tuple[Path, Path]:
    if platform_name == "linux":
        native_package_directory = "codex-linux-x64"
        native_package_version = "0.157.1-linux-x64"
        native_relative = Path("vendor/x86_64-unknown-linux-musl/bin/codex")
        native_os = "linux"
        native_cpu = "x64"
    else:
        native_package_directory = "codex-darwin-arm64"
        native_package_version = "0.157.1-darwin-arm64"
        native_relative = Path("vendor/aarch64-apple-darwin/bin/codex")
        native_os = "darwin"
        native_cpu = "arm64"
    wrapper_root = root / "node_modules" / "@openai" / "codex"
    wrapper = wrapper_root / "bin" / "codex.js"
    wrapper.parent.mkdir(parents=True)
    wrapper.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    (wrapper_root / "package.json").write_text(
        json.dumps(
            {
                "name": "@openai/codex",
                "version": "0.157.1",
                "bin": {"codex": "bin/codex.js"},
                "optionalDependencies": {
                    f"@openai/{native_package_directory}": f"npm:@openai/codex@{native_package_version}"
                },
            }
        ),
        encoding="utf-8",
    )
    native_root = (
        wrapper_root / "node_modules" / "@openai" / native_package_directory
        if nested
        else wrapper_root.parent / native_package_directory
    )
    native = native_root / native_relative
    native.parent.mkdir(parents=True)
    native.write_bytes(b"packaged-layout-probe")
    native.chmod(0o700)
    host = native.parent / "codex-code-mode-host"
    host.write_bytes(b"packaged-layout-host-probe")
    host.chmod(0o700)
    (native_root / "package.json").write_text(
        json.dumps(
            {
                "name": "@openai/codex",
                "version": native_package_version,
                "os": [native_os],
                "cpu": [native_cpu],
            }
        ),
        encoding="utf-8",
    )
    return wrapper, native


@pytest.mark.parametrize(
    ("platform_name", "machine", "executable_sha256", "host_sha256", "source_identity"),
    [
        (
            "darwin",
            "arm64",
            "sha256:27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d",
            "sha256:80fdf166c3da068282d5692f67a852715a327ae7dc1913abb93b8c3d3030103f",
            "openai-codex-npm-darwin-arm64-0.157.1",
        ),
        (
            "linux",
            "x86_64",
            "sha256:3e2584f3f3829a43a0495011a1cecb2facbe64a2403e2b682351fd9c2983f970",
            "sha256:67b86142bac5cead11b8420cf32d3a2bf88c8868d71733f351ed7c5d95a953e0",
            "openai-codex-npm-linux-x64-0.157.1",
        ),
    ],
)
def test_installed_wheel_resolves_nested_and_npm_prefix_codex_layouts(
    built_dist: _BuiltDist,
    tmp_path: Path,
    platform_name: str,
    machine: str,
    executable_sha256: str,
    host_sha256: str,
    source_identity: str,
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    _finishup_exe, env = _tool_install(built_dist.directory, root, home)
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    installed_python = root / "tool" / "finishup" / "bin" / "python"
    probe = (
        "import sys; from pathlib import Path; "
        "import finishup.cli.codex_subscription as m; "
        f"sys.platform={platform_name!r}; m.platform.machine=lambda: {machine!r}; "
        f"m._sha256_file=lambda path: {host_sha256!r} "
        f"if path.name == 'codex-code-mode-host' else {executable_sha256!r}; "
        "print(Path(m.__file__).resolve()); "
        "print(*m.resolve_supported_codex_executable(Path(sys.argv[1])), sep='\\n')"
    )

    for nested in (True, False):
        wrapper, native = _codex_package_layout(
            tmp_path / f"layout-{platform_name}-{nested}",
            nested=nested,
            platform_name=platform_name,
        )
        result = subprocess.run(
            [str(installed_python), "-c", probe, str(wrapper)],
            capture_output=True,
            timeout=30,
            env=env,
            cwd=root,
            check=False,
        )

        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
        lines = result.stdout.decode("utf-8").splitlines()
        assert len(lines) == 4
        assert Path(lines[0]).is_relative_to(root / "tool" / "finishup")
        assert lines[1:] == [
            str(native),
            executable_sha256,
            source_identity,
        ]
        assert str(_REPO_ROOT).encode("utf-8") not in result.stdout


def _bound_runtime_config(root: Path) -> tuple[Path, Path]:
    """Write the exact persisted subscription binding shape around an absent executable."""

    data_dir = root / "state"
    data_dir.mkdir(mode=0o700, exist_ok=True)
    digest = "sha256:" + "a" * 64
    config = root / "config.toml"
    config.write_text(
        'schema_version = "1"\n'
        'profile = "codex-subscription"\n'
        "\n"
        "[storage]\n"
        f'data_dir = "{data_dir}"\n'
        "\n"
        "[external_runtime]\n"
        'provider_id = "openai-codex"\n'
        'endpoint_profile_id = "codex-chatgpt-subscription"\n'
        'endpoint_profile_version = "1.0.0"\n'
        'credential_authority = "external_runtime_oauth"\n'
        f'executable_path = "{root / "absent-codex"}"\n'
        f'executable_sha256 = "{digest}"\n'
        'runtime_version = "0.150.1"\n'
        'source_identity = "openai-codex-npm-darwin-arm64-0.150.1"\n'
        f'app_server_schema_sha256 = "{digest}"\n'
        f'capability_cell_sha256 = "{digest}"\n'
        f'isolated_config_sha256 = "{digest}"\n'
        'capability_profile = "codex-evaluator/0.150.1/v2"\n'
        'capability_evidence_expires_at = "2026-11-30T00:00:00Z"\n'
        f'codex_home = "{root / "dedicated-home"}"\n'
        'model = "gpt-5.6-sol"\n'
        'reasoning_effort = "high"\n',
        encoding="utf-8",
    )
    return config, data_dir


def _run(
    finishup_exe: Path, env: dict[str, str], config: Path, *argv: str
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(finishup_exe), *argv],
        capture_output=True,
        timeout=30,
        env={**env, "FINISHUP_CONFIG": str(config)},
        check=False,
    )


def _assert_bounded(result: subprocess.CompletedProcess[bytes], *, config: Path) -> None:
    assert b"internal_error" not in result.stderr, result.stderr
    assert b"Traceback (most recent call last)" not in result.stderr
    assert str(config).encode("utf-8") not in result.stderr
    assert str(_REPO_ROOT).encode("utf-8") not in result.stderr


def test_status_with_valid_data_dir_config_is_bounded_not_internal_error(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)
    cfg_root = tmp_path / "cfg"
    cfg_root.mkdir(mode=0o700)
    config, _data_dir = _data_dir_config(cfg_root)

    result = _run(finishup_exe, env, config, "provider", "codex-subscription", "status", "--json")

    assert result.returncode == 20, (result.returncode, result.stderr)
    assert b"codex_subscription: codex_subscription_not_configured" in result.stderr
    _assert_bounded(result, config=config)


def test_status_with_bound_runtime_and_data_dir_probes_the_runtime_not_the_loader(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)
    cfg_root = tmp_path / "cfg"
    cfg_root.mkdir(mode=0o700)
    config, _data_dir = _bound_runtime_config(cfg_root)

    result = _run(finishup_exe, env, config, "provider", "codex-subscription", "status", "--json")

    # The valid file loads; the failure, if any, is the absent runtime — one closed token,
    # never a masked internal_error and never a config-loader crash.
    assert result.returncode == 20, (result.returncode, result.stderr)
    assert b"codex_subscription: codex_" in result.stderr
    assert b"config_value_invalid" not in result.stderr
    _assert_bounded(result, config=config)


def test_rollback_preserves_data_dir_while_removing_only_the_binding(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)
    cfg_root = tmp_path / "cfg"
    cfg_root.mkdir(mode=0o700)
    config, data_dir = _bound_runtime_config(cfg_root)

    result = _run(finishup_exe, env, config, "provider", "codex-subscription", "rollback", "--json")

    assert result.returncode == 0, (result.returncode, result.stderr)
    payload = json.loads(result.stdout)
    assert payload["binding_removed"] is True
    assert payload["codex_installation_preserved"] is True
    rewritten = tomllib.loads(config.read_text(encoding="utf-8"))
    assert "external_runtime" not in rewritten
    assert rewritten["storage"]["data_dir"] == str(data_dir)
    assert rewritten["profile"] == "strict-local"
    _assert_bounded(result, config=config)


def test_invalid_config_is_a_bounded_actionable_diagnostic(
    built_dist: _BuiltDist, tmp_path: Path
) -> None:
    root = tmp_path / "install"
    home = root / "home"
    home.mkdir(parents=True)
    finishup_exe, env = _tool_install(built_dist.directory, root, home)
    cfg_root = tmp_path / "cfg"
    cfg_root.mkdir(mode=0o700)
    config = cfg_root / "config.toml"
    config.write_text("[storage]\ndata_dir = 5\n", encoding="utf-8")

    result = _run(finishup_exe, env, config, "provider", "codex-subscription", "status", "--json")

    assert result.returncode == 20, (result.returncode, result.stderr)
    assert b"codex_subscription: config_value_invalid" in result.stderr
    # Actionable: the token carries its remediation half, not just a bare code.
    assert b"reviewed configuration model" in result.stderr
    _assert_bounded(result, config=config)
