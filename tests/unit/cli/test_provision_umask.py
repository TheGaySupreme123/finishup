"""The test-instance provisioner yields a runtime FinishUP accepts under any umask."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "provision_test_instance.py"


def _provisioner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("provision_test_instance_umask", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_uv_commands_run_under_umask_022(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _provisioner()
    seen: dict[str, Any] = {}

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(module.subprocess, "run", run)
    module._run(["uv", "--version"])  # noqa: SLF001
    assert seen["umask"] == 0o022


def test_runtime_install_writes_checked_hash_bytecode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _provisioner()
    seen: list[tuple[list[str], dict[str, str] | None]] = []

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.append((args, kwargs.get("env")))
        if args[:2] == ["uv", "venv"]:
            (tmp_path / "runtime/bin").mkdir(parents=True)
            (tmp_path / "runtime/bin/finishup").write_text("#!/bin/sh\n")
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(module, "_run", run)
    base = {"PATH": "/usr/bin"}
    module._install_runtime(tmp_path / "runtime", tmp_path / "w.whl", "3.14", base)  # noqa: SLF001
    install = [env for args, env in seen if args[:2] == ["uv", "pip"] and "install" in args]
    assert install and all(env and env["SOURCE_DATE_EPOCH"] for env in install)
    assert "SOURCE_DATE_EPOCH" not in base  # the caller's environment is untouched
    venv = [env for args, env in seen if args[:2] == ["uv", "venv"]]
    assert venv == [base]


def test_runtime_created_under_umask_0002_is_left_owner_writable_only(tmp_path: Path) -> None:
    module = _provisioner()
    runtime = tmp_path / "runtime"
    outside = tmp_path / "interpreter"
    previous = os.umask(0o002)
    try:
        (runtime / "bin").mkdir(parents=True)
        (runtime / "lib/site-packages/finishup").mkdir(parents=True)
        (runtime / "pyvenv.cfg").write_text("home = /x\n")
        (runtime / "lib/site-packages/finishup/__init__.py").write_text("")
        (runtime / "bin/finishup").write_text("#!/bin/sh\n")
        (runtime / "bin/finishup").chmod(0o775)
        outside.write_text("base interpreter")
        (runtime / "bin/python").symlink_to(outside)
    finally:
        os.umask(previous)
    assert outside.stat().st_mode & 0o020
    module._remove_foreign_write(runtime)  # noqa: SLF001
    for path in (runtime, *runtime.rglob("*")):
        if not path.is_symlink():
            assert path.stat().st_mode & 0o022 == 0, path
    assert (runtime / "bin/finishup").stat().st_mode & 0o777 == 0o755
    # A link is never followed: the base interpreter is the operator's to repair.
    assert outside.stat().st_mode & 0o020
