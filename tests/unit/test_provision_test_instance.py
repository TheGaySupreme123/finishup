"""Test-instance tooling drives runtimes built before and after the rename (ADR-028, ADR-048).

These cases exercise the script's launcher probe, environment scrub, and dispose bootstrap with
fake runtime trees and an intercepted subprocess runner; nothing is built, installed, or spawned.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "provision_test_instance.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("provision_test_instance", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["provision_test_instance"] = module
    spec.loader.exec_module(module)
    return module


_MODULE = _load()


def _accept_base(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``tmp_path`` sits under shared temp, which the real base check refuses by design.
    def accept(base: Path) -> Path:
        return base

    monkeypatch.setattr(_MODULE, "_validate_base", accept)


def _runtime(root: Path, *launchers: str) -> Path:
    runtime = root / "runtime"
    (runtime / "bin").mkdir(parents=True)
    for name in launchers:
        (runtime / "bin" / name).write_text("#!/bin/sh\n", encoding="ascii")
    return runtime


@pytest.mark.parametrize(
    ("launchers", "expected"),
    [
        (("finishup",), ("finishup", "finishup")),
        (("yoetz",), ("yoetz", "yoetz")),
        # A runtime that ships the deprecated alias too is still a FinishUP runtime.
        (("finishup", "yoetz"), ("finishup", "finishup")),
    ],
)
def test_the_runtime_launcher_probe_prefers_finishup_then_legacy(
    tmp_path: Path, launchers: tuple[str, ...], expected: tuple[str, str]
) -> None:
    runtime = _runtime(tmp_path, *launchers)
    launcher, package = _MODULE._runtime_launcher(runtime)
    assert (launcher.name, package) == expected
    assert launcher.parent == runtime / "bin"


def test_a_runtime_without_any_launcher_is_absent(tmp_path: Path) -> None:
    assert _MODULE._runtime_launcher(_runtime(tmp_path)) is None


def test_snapshot_commands_inherit_neither_variable_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("YOETZ_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("YOETZ_PROFILE", "test-fake")
    monkeypatch.setenv("_FINISHUP_TEST_INSTALLATION", "kept")
    env = _MODULE._clean_env(tmp_path)
    assert not any(name.startswith(("FINISHUP_", "YOETZ_")) for name in env)
    assert env["_FINISHUP_TEST_INSTALLATION"] == "kept"
    assert env["HOME"] == str(tmp_path)


def test_the_environment_export_names_both_spellings_with_one_root(tmp_path: Path) -> None:
    root = tmp_path / "state"
    assert _MODULE._environment_export(root) == (
        f"FINISHUP_ISOLATED_ROOT={root} YOETZ_ISOLATED_ROOT={root}"
    )


def test_status_drives_a_pre_rename_runtime_through_its_legacy_launcher(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _accept_base(monkeypatch)
    base = tmp_path / "base"
    layout = _MODULE._layout(base, "old")
    layout["root"].mkdir(parents=True)
    _runtime(layout["root"], "yoetz")
    layout["provenance"].write_text("{}", encoding="utf-8")
    invoked: list[Path] = []

    def snapshot(launcher: Path, args: list[str], env: dict[str, str]) -> dict[str, object]:
        invoked.append(launcher)
        return {"state": "ok"}

    monkeypatch.setattr(_MODULE, "_snapshot_command", snapshot)
    result = _MODULE.command_status(argparse.Namespace(base=str(base), tag="old"))
    assert result["state"] == "present"
    assert invoked == [layout["runtime"] / "bin" / "yoetz"]


@pytest.mark.parametrize(("launcher", "package"), [("finishup", "finishup"), ("yoetz", "yoetz")])
def test_dispose_prunes_retained_runtimes_with_the_runtime_s_own_package(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, launcher: str, package: str
) -> None:
    _accept_base(monkeypatch)
    base = tmp_path / "base"
    layout = _MODULE._layout(base, "inst")
    layout["root"].mkdir(parents=True)
    runtime = _runtime(layout["root"], launcher)
    (runtime.parent / f".{runtime.name}-releases").mkdir()
    calls: list[list[str]] = []

    def run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        stdout = json.dumps({"disposed": True} if len(calls) == 1 else [1, 0]).encode()
        return subprocess.CompletedProcess(args, 0, stdout, b"")

    monkeypatch.setattr(_MODULE, "_run", run)
    result = _MODULE.command_dispose(
        argparse.Namespace(base=str(base), tag="inst", retain_logs=None)
    )

    assert result["disposed"] is True
    assert calls[0][0] == str(runtime / "bin" / launcher)
    assert f"from {package}.adapters.release_runtime import" in calls[1][-1]
    assert not layout["root"].exists()
