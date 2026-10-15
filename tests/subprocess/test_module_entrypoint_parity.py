from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _run(arguments: list[str], *, module: bool) -> subprocess.CompletedProcess[bytes]:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.fspath(root / "src")
    launcher = (
        [sys.executable, "-m", "finishup"] if module else [os.fspath(root / ".venv/bin/finishup")]
    )
    return subprocess.run(  # noqa: S603 - both fixed in-repository launchers
        [*launcher, *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        check=False,
        timeout=10,
    )


def _normalized_help(data: bytes) -> bytes:
    return data.replace(b"python -m finishup", b"finishup")


def test_console_and_module_version_are_byte_identical() -> None:
    for arguments in (["--version"], ["version"], ["version", "--json"]):
        console = _run(list(arguments), module=False)
        module = _run(list(arguments), module=True)
        assert (console.returncode, console.stdout, console.stderr) == (
            module.returncode,
            module.stdout,
            module.stderr,
        )


def test_console_and_module_help_differ_only_by_launcher_token() -> None:
    console = _run(["--help"], module=False)
    module = _run(["--help"], module=True)
    assert console.returncode == module.returncode == 0
    assert _normalized_help(console.stdout) == _normalized_help(module.stdout)
    assert console.stderr == module.stderr == b""


def test_console_and_module_invalid_input_are_identical() -> None:
    console = _run(["start"], module=False)
    module = _run(["start"], module=True)
    assert (console.returncode, console.stdout, console.stderr) == (
        module.returncode,
        module.stdout,
        module.stderr,
    )
    assert console.returncode == 2
