"""An installed MCP process keeps its release while its carrier replaces the wheel (#820)."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import pwd
import selectors
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from finishup.protocol.canonical import canonical_digest, canonical_encode

_REPO = Path(__file__).resolve().parents[2]
_PROVISION = _REPO / "scripts/provision_test_instance.py"
_URI = "finishup://guidance/workflow.md"
_MARKER = "P822_NEXT_ARTIFACT_GUIDANCE"


@pytest.fixture
def installation() -> Generator[tuple[Path, Path, dict[str, str]]]:
    # A new pinned instance, never the user's installation or vault. This short private base
    # also satisfies the service socket limit if an unrelated startup path probes the instance.
    base_parent = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".yz-rr"
    base_parent.mkdir(mode=0o700, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="t", dir=base_parent))
    env = {key: value for key, value in os.environ.items() if not key.startswith("FINISHUP_")}
    env.pop("PYTHONPATH", None)
    command = [sys.executable, str(_PROVISION)]
    created = subprocess.run(  # noqa: S603 - fixed private test-instance provisioning
        [
            *command,
            "create",
            "--base",
            str(base),
            "--tag",
            "a",
            "--checkout",
            str(_REPO),
            "--python",
            sys.executable,
            "--lifecycle",
            "disposable",
            "--expires-in",
            "2",
            "--allow-dirty",
        ],
        env=env,
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert created.returncode == 0, created.stderr[-4096:]
    runtime = base / "a/runtime"
    try:
        yield runtime, next((base / "a/dist").glob("*.whl")), env
    finally:
        # Every bridge is closed by the test before disposal; prune never kills one to free it.
        pruned = subprocess.run(  # noqa: S603 - the exact test installation only
            [str(runtime / "bin/finishup"), "upgrade", "--prune-runtimes"],
            env=env,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert pruned.returncode == 0, pruned.stderr[-4096:]
        disposed = subprocess.run(  # noqa: S603 - exact instance disposal
            [*command, "dispose", "--base", str(base), "--tag", "a"],
            env=env,
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert disposed.returncode == 0, disposed.stderr[-4096:]
        base.rmdir()


class _Bridge:
    def __init__(self, runtime: Path, env: dict[str, str]) -> None:
        self.process = subprocess.Popen(  # noqa: S603 - exact pinned test launcher
            [str(runtime / "bin/finishup"), "mcp", "serve", "--semantic", "off"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.next_id = 0
        result = self.call(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "release-runtime-test", "version": "1"},
            },
        )
        assert "result" in result, result
        assert self.process.stdin is not None
        self.process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.process.stdin.flush()

    def call(self, method: str, params: dict[str, object]) -> dict[str, Any]:
        self.next_id += 1
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(
            (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": self.next_id,
                        "method": method,
                        "params": params,
                    }
                )
                + "\n"
            ).encode()
        )
        self.process.stdin.flush()
        deadline = time.monotonic() + 40
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                if not selector.select(max(0, deadline - time.monotonic())):
                    break
                line = self.process.stdout.readline()
                assert line, "bridge exited before response"
                value = json.loads(line)
                if value.get("id") == self.next_id:
                    return value
        raise AssertionError("bridge response deadline")

    def guidance(self) -> str:
        result = self.call("resources/read", {"uri": _URI})
        assert "result" in result, result
        return result["result"]["contents"][0]["text"]

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
        for pipe in (self.process.stdout, self.process.stderr):
            if pipe is not None:
                pipe.close()


def _replacement_wheel(source: Path, destination: Path) -> Path:
    """A different, internally consistent artifact at the same version defeats version-only keys."""

    with zipfile.ZipFile(source) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    root = "finishup/resources/"
    guidance = "guidance/workflow.md"
    members[root + guidance] += f"\n{_MARKER}\n".encode()
    manifest = json.loads(members[root + "manifest.json"])

    def refresh(name: str) -> None:
        data = members[root + name]
        entry = next(item for item in manifest["entries"] if item["logical_name"] == name)
        entry["size"] = len(data)
        entry["sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()

    refresh(guidance)
    stable = {key: value for key, value in manifest.items() if key != "resource_set_digest"}
    stable["entries"] = [
        {
            key: value
            for key, value in entry.items()
            if entry["kind"] != "runtime_support" or key not in {"sha256", "size"}
        }
        for entry in manifest["entries"]
    ]
    manifest["resource_set_digest"] = canonical_digest(stable)
    support = json.loads(members[root + "support/runtime-support.json"])
    support["resource_set_digest"] = manifest["resource_set_digest"]
    members[root + "support/runtime-support.json"] = canonical_encode(support) + b"\n"
    refresh("support/runtime-support.json")
    members[root + "manifest.json"] = canonical_encode(manifest) + b"\n"
    record = next(name for name in members if name.endswith(".dist-info/RECORD"))
    output = io.StringIO()
    writer = csv.writer(output)
    for name, data in members.items():
        if name != record:
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            writer.writerow((name, "sha256=" + digest, len(data)))
    writer.writerow((record, "", ""))
    members[record] = output.getvalue().encode()
    destination.mkdir()
    wheel = destination / source.name
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return wheel


def test_installed_bridge_keeps_old_guidance_and_new_bridge_selects_replacement(
    installation: tuple[Path, Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    runtime, wheel, env = installation
    root = runtime.parent / "state"
    identity = root / "state/instance-identity.json"
    pin = runtime / "yoetz-instance-pin.json"
    before = (identity.read_bytes(), pin.read_bytes())
    old = _Bridge(runtime, env)
    new: _Bridge | None = None
    try:
        original = old.guidance()
        # A real service is started by this retained bridge too. An uninitialized disposable
        # vault returns a bounded refusal; no credentials or user vault are used.
        started = old.call(
            "tools/call",
            {
                "name": "start",
                "arguments": {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": "req_f63bc5d6-5cac-4e08-b602-94ae6c8be9d5",
                    "mode": "create",
                    "task_title": "runtime replacement fixture",
                    "requested_view": "compact",
                    "actor": {"actor_id": "harness:fixture", "actor_type": "harness"},
                    "client": {
                        "kind": "test_client",
                        "version": "1",
                        "integration": "cooperative_mcp",
                    },
                },
            },
        )
        assert "result" in started, started
        status = subprocess.run(  # noqa: S603 - exact instance status, never an ambient launcher
            [str(runtime / "bin/finishup"), "service", "status", "--json"],
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert status.returncode == 0, status.stderr[-4096:]
        assert json.loads(status.stdout)["state"] == "locked"
        replacement = _replacement_wheel(wheel, tmp_path / "replacement")
        installed = subprocess.run(  # noqa: S603 - private instance, local fixture wheel, no deps/network
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(runtime / "bin/python"),
                "--offline",
                "--no-deps",
                "--reinstall",
                str(replacement),
            ],
            env=env,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert installed.returncode == 0, installed.stderr[-4096:]
        assert old.guidance() == original
        assert _MARKER not in original
        new = _Bridge(runtime, env)
        assert _MARKER in new.guidance()
        assert old.guidance() == original
        assert (identity.read_bytes(), pin.read_bytes()) == before
        pruned = subprocess.run(  # noqa: S603 - exact pinned runtime's bounded cleanup
            [str(runtime / "bin/finishup"), "upgrade", "--prune-runtimes"],
            env=env,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert pruned.returncode == 0, pruned.stderr[-4096:]
        assert b"kept 2 in use" in pruned.stdout
        assert old.guidance() == original and _MARKER in new.guidance()
    finally:
        old.close()
        if new is not None:
            new.close()
