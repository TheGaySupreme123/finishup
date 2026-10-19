"""npm launcher: public package shape and delegation-only behavior."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_LAUNCHER_DIR = Path(__file__).resolve().parents[2] / "support" / "npm-launcher"


def _package() -> dict[str, object]:
    return json.loads((_LAUNCHER_DIR / "package.json").read_text(encoding="utf-8"))


def test_package_shape_is_delegation_only() -> None:
    package = _package()
    assert package["name"] == "finishup"
    assert package["private"] is False
    assert package["bin"] == {"finishup": "./bin/finishup.js"}
    # No runtime dependencies: the launcher may never bundle or fetch code itself.
    for forbidden in ("dependencies", "devDependencies", "optionalDependencies", "scripts"):
        assert forbidden not in package, forbidden
    assert package["license"] == "Apache-2.0"
    assert package["homepage"] == "https://finishup.dev"
    assert package["repository"] == {
        "type": "git",
        "url": "git+https://github.com/TheGaySupreme123/finishup.git",
    }
    assert package["bugs"] == {"url": "https://github.com/TheGaySupreme123/finishup/issues"}
    assert package["publishConfig"] == {"access": "public"}


def test_version_stays_in_lockstep_with_the_python_distribution() -> None:
    import finishup

    assert _package()["version"] == finishup.__version__


def test_launcher_script_exists_and_is_executable() -> None:
    script = _LAUNCHER_DIR / "bin" / "finishup.js"
    assert script.is_file()
    assert os.access(script, os.X_OK)
    first_line = script.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == "#!/usr/bin/env node"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_launcher_delegates_to_pinned_uvx(tmp_path: Path) -> None:
    node = shutil.which("node")
    assert node is not None
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    record = tmp_path / "record.txt"
    uv_record = tmp_path / "uv-record.txt"
    (shim_dir / "uv").write_text(
        f'#!/bin/sh\necho "$@${{SOURCE_DATE_EPOCH:+ epoch}}" >> {uv_record}\nexit 0\n',
        encoding="utf-8",
    )
    (shim_dir / "uvx").write_text(f'#!/bin/sh\necho "$@" > {record}\nexit 7\n', encoding="utf-8")
    os.chmod(shim_dir / "uv", 0o755)
    os.chmod(shim_dir / "uvx", 0o755)

    completed = subprocess.run(
        (node, str(_LAUNCHER_DIR / "bin" / "finishup.js"), "status", "--json"),
        env={
            **{key: value for key, value in os.environ.items() if key != "SOURCE_DATE_EPOCH"},
            "PATH": str(shim_dir),
        },
        capture_output=True,
        timeout=30,
        check=False,
    )
    # Exact version-pinned passthrough and child exit-code propagation.
    assert completed.returncode == 7
    version = _package()["version"]
    # Versionless: `uvx` then runs the tool environment installed just above rather than
    # resolving a possibly cache-backed environment for the same version.
    assert record.read_text(encoding="utf-8").strip() == "finishup status --json"
    # The same exact version is made a persistent uv tool first, so host hooks and MCP
    # entries bind a launcher that survives `uv cache clean` (issue #766).
    assert uv_record.read_text(encoding="utf-8").splitlines() == [
        "--version",
        # SOURCE_DATE_EPOCH in the install child only: checked-hash bytecode the sealed
        # generation reuses instead of compiling on the first serving start.
        f"tool install --quiet --compile-bytecode --managed-python --python 3.14 finishup=={version} epoch",
    ]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_launcher_reports_a_failed_tool_install_and_never_runs_the_child(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    assert node is not None
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    record = tmp_path / "record.txt"
    (shim_dir / "uv").write_text(
        '#!/bin/sh\ncase "$1" in --version) exit 0;; esac\n'
        "echo 'error: No interpreter found for Python 3.14' >&2\nexit 2\n",
        encoding="utf-8",
    )
    (shim_dir / "uvx").write_text(f"#!/bin/sh\ntouch {record}\nexit 0\n", encoding="utf-8")
    os.chmod(shim_dir / "uv", 0o755)
    os.chmod(shim_dir / "uvx", 0o755)

    completed = subprocess.run(
        (node, str(_LAUNCHER_DIR / "bin" / "finishup.js"), "version"),
        env={**os.environ, "PATH": str(shim_dir)},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 1
    stderr = completed.stderr.decode("utf-8")
    assert "No interpreter found for Python 3.14" in stderr
    assert "could not install the Python distribution" in stderr
    assert "status 2" in stderr
    assert not record.exists()


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_launcher_fails_with_guidance_when_uv_is_absent(tmp_path: Path) -> None:
    node = shutil.which("node")
    assert node is not None
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    completed = subprocess.run(
        (node, str(_LAUNCHER_DIR / "bin" / "finishup.js")),
        env={**os.environ, "PATH": str(empty_dir)},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 1
    stderr = completed.stderr.decode("utf-8")
    assert "uv" in stderr
    assert "astral.sh/uv" in stderr


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_launcher_does_not_call_a_broken_uv_installation_missing(tmp_path: Path) -> None:
    node = shutil.which("node")
    assert node is not None
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    (shim_dir / "uv").write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    os.chmod(shim_dir / "uv", 0o755)

    completed = subprocess.run(
        (node, str(_LAUNCHER_DIR / "bin" / "finishup.js")),
        env={**os.environ, "PATH": str(shim_dir)},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 1
    stderr = completed.stderr.decode("utf-8")
    assert "could not run 'uv --version'" in stderr
    assert "status 7" in stderr
    assert "not found on PATH" not in stderr


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
@pytest.mark.parametrize(("signal", "expected"), [("INT", 130), ("PIPE", 141)])
def test_launcher_reports_signal_termination_as_the_conventional_exit_code(
    tmp_path: Path,
    signal: str,
    expected: int,
) -> None:
    """A script that checks exit codes must see the same value either entry point gives.

    `npx finishup` has to be interchangeable with the Python console script, and an
    interrupted interactive session exits 130 there.
    """

    node = shutil.which("node")
    assert node is not None
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    (shim_dir / "uv").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (shim_dir / "uvx").write_text(
        f"#!/bin/sh\nkill -{signal} $$\n",
        encoding="utf-8",
    )
    os.chmod(shim_dir / "uv", 0o755)
    os.chmod(shim_dir / "uvx", 0o755)

    completed = subprocess.run(
        (node, str(_LAUNCHER_DIR / "bin" / "finishup.js")),
        env={**os.environ, "PATH": str(shim_dir)},
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == expected


@pytest.mark.skipif(shutil.which("node") is None, reason="node is a contributor-only tool")
def test_launcher_guidance_names_the_runtime_and_a_concrete_install_command(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    assert node is not None
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    completed = subprocess.run(
        (node, str(_LAUNCHER_DIR / "bin" / "finishup.js")),
        env={**os.environ, "PATH": str(empty_dir)},
        capture_output=True,
        timeout=30,
        check=False,
    )
    stderr = completed.stderr.decode("utf-8")
    assert "Python 3.12" in stderr
    assert "astral.sh/uv/install.sh" in stderr
    assert "never installs anything itself" in stderr


def test_launcher_never_reimplements_setup_or_interface_logic() -> None:
    """The launcher stays a delegator: no TTY probing, no setup, no interface."""

    source = (_LAUNCHER_DIR / "bin" / "finishup.js").read_text(encoding="utf-8")
    for forbidden in ("isTTY", "readline", "prompt(", "createInterface", "pip install"):
        assert forbidden not in source, forbidden
    # stdio must be inherited so the child sees the real controlling terminal.
    assert 'stdio: "inherit"' in source
