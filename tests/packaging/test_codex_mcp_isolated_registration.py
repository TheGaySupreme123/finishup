"""Installed Codex 0.150.1 propagation regression for issue #561.

The test uses a fresh Codex home and a test-owned executable named ``yoetz``.  Product code
registers the exact allowlisted isolation binding, then the real Codex app-server launches that
registered child while its own parent environment deliberately lacks ``YOETZ_ISOLATED_ROOT``.
The child records the value it actually received and completes the MCP handshake.  This proves
the reviewed registration, not ambient parent inheritance, supplied the exact isolated root.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Final, cast

import anyio
import pytest

from yoetz.adapters.integrations.codex_mcp import CodexMcpAdapter
from yoetz.application.harness_mcp import HarnessMcpService, McpRegistrationConfirmation
from yoetz.config.paths import ISOLATED_ROOT_ENV
from yoetz.ports.harness_mcp import HarnessBinary, McpRegistrationState
from yoetz.ports.integrations import HarnessId

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_EXPECTED_CODEX_VERSION: Final = "codex-cli 0.150.1"
_PROBE_MARKER: Final = "codex-child-isolated-root.txt"
_PROBE_SCRIPT: Final = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

root = os.environ.get("YOETZ_ISOLATED_ROOT")
if not root:
    raise SystemExit(73)
pathlib.Path(root, "codex-child-isolated-root.txt").write_text(root, encoding="utf-8")

for raw in sys.stdin.buffer:
    try:
        request = json.loads(raw)
    except Exception:
        continue
    request_id = request.get("id")
    if request_id is None:
        continue
    method = request.get("method")
    if method == "initialize":
        params = request.get("params") or {}
        result = {
            "protocolVersion": params.get("protocolVersion", "2024-11-05"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "yoetz-isolation-probe", "version": "0.1.0"},
        }
    elif method == "tools/list":
        result = {"tools": []}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "resources/templates/list":
        result = {"resourceTemplates": []}
    elif method == "prompts/list":
        result = {"prompts": []}
    elif method == "ping":
        result = {}
    else:
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "method not found"},
        }
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        continue
    response = {"jsonrpc": "2.0", "id": request_id, "result": result}
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    sys.stdout.flush()
"""


def _is_advertised_host() -> bool:
    """Both ADR-007 certified cells run this regression; the Codex binary is the only host input.

    The fixture MCP server is a Python stub, so nothing here is macOS-specific (issue #725). The
    remaining skip below is the installed Codex 0.150.1 binary, which the runner must provide.
    """

    if sys.platform == "darwin":
        return platform.machine() == "arm64"
    if sys.platform.startswith("linux"):
        return platform.machine() in {"x86_64", "amd64"}
    return False


pytestmark = pytest.mark.skipif(
    not _is_advertised_host(),
    reason=(
        "the issue #561 regression runs on the certified macOS arm64 and Linux x86-64 cells "
        "with an installed Codex 0.150.1; this host is neither"
    ),
)


def _installed_codex_01501() -> Path:
    candidate = shutil.which("codex")
    if candidate is None:
        pytest.skip("installed Codex 0.150.1 is unavailable")
    executable = Path(candidate).resolve(strict=True)
    result = subprocess.run(
        [str(executable), "--version"],
        capture_output=True,
        timeout=15,
        check=False,
    )
    if result.returncode != 0 or result.stdout.decode("utf-8").strip() != _EXPECTED_CODEX_VERSION:
        pytest.skip("installed Codex is not the frozen 0.150.1 regression cell")
    return executable


def _short_private_root() -> Path:
    base = Path.home() / ".yz-mcp561"
    base.mkdir(mode=0o700, exist_ok=True)
    base.chmod(0o700)
    root = base / secrets.token_hex(4)
    root.mkdir(mode=0o700)
    return root


def test_installed_codex_child_receives_only_the_reviewed_isolated_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex = _installed_codex_01501()
    root = _short_private_root()
    try:
        isolated_root = root / "isolated"
        codex_home = root / "codex-home"
        probe_bin = root / "bin"
        isolated_root.mkdir(mode=0o700)
        codex_home.mkdir(mode=0o700)
        probe_bin.mkdir(mode=0o700)
        probe = probe_bin / "yoetz"
        probe.write_text(_PROBE_SCRIPT, encoding="utf-8")
        probe.chmod(0o700)

        original_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", f"{probe_bin}{os.pathsep}{original_path}")
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        monkeypatch.setenv("CODEX_TESTING_HOME", str(codex_home))
        monkeypatch.setenv(ISOLATED_ROOT_ENV, str(isolated_root))
        # This existing compatibility cell intentionally exercises the legacy PATH registration
        # with a synthetic child; issue #654's test below exercises a proven installed launcher.
        monkeypatch.setattr(
            "yoetz.adapters.integrations.codex_mcp.installed_launcher", lambda: None
        )

        binary = HarnessBinary(HarnessId.CODEX, str(codex), "0.150.1", "supported")
        service = HarnessMcpService(CodexMcpAdapter(route_profile="strict"))
        preview = anyio.run(lambda: service.preview(binary))
        assert preview.isolated_root == str(isolated_root)
        result = anyio.run(
            lambda: service.register(
                binary,
                McpRegistrationConfirmation(
                    preview.preview_digest,
                    True,
                    "noninteractive_flag",
                ),
                _state=root / "applied-route",
            )
        )
        assert result.state_after is McpRegistrationState.YOETZ_OWNED

        observed = anyio.run(lambda: service.observe(binary))
        assert observed.isolation_binding == "isolated_exact"

        # The host parent has no isolation variable. Only the reviewed Codex registration can
        # supply the value to the child that the real app-server now launches.
        monkeypatch.delenv(ISOLATED_ROOT_ENV)
        capture = root / "mcp-server-status.json"
        launched = subprocess.run(
            [
                sys.executable,
                str(_REPO_ROOT / "scripts" / "capture_codex_mcp_surface.py"),
                "--codex-binary",
                str(codex),
                "--codex-testing-home",
                str(codex_home),
                "--output",
                str(capture),
            ],
            capture_output=True,
            timeout=45,
            env=os.environ.copy(),
            check=False,
        )
        assert launched.returncode == 0, launched.stderr.decode("utf-8", errors="replace")
        document = cast(dict[str, object], json.loads(capture.read_bytes()))
        inventory = cast(dict[str, object], document["inventory"])
        result_body = cast(dict[str, object], inventory["result"])
        entries = cast(list[dict[str, object]], result_body["data"])
        assert entries[0]["serverInfo"] == {
            "description": None,
            "icons": None,
            "name": "yoetz-isolation-probe",
            "title": None,
            "version": "0.1.0",
            "websiteUrl": None,
        }
        assert (isolated_root / _PROBE_MARKER).read_text(encoding="utf-8") == str(isolated_root)

        monkeypatch.setenv(ISOLATED_ROOT_ENV, str(isolated_root))
        removal = anyio.run(lambda: service.preview_unregistration(binary))
        removed = anyio.run(
            lambda: service.unregister(
                binary,
                McpRegistrationConfirmation(
                    removal.preview_digest,
                    True,
                    "noninteractive_flag",
                ),
                _state=root / "applied-route",
            )
        )
        assert removed.state_after is McpRegistrationState.ABSENT
    finally:
        shutil.rmtree(root, ignore_errors=True)
        try:
            root.parent.rmdir()
        except OSError:
            pass


_PACKAGED_DRIVER: Final = r"""
import json
import os
import subprocess
import sys
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from yoetz.adapters.integrations.codex_mcp import CodexMcpAdapter
from yoetz.application.harness_mcp import HarnessMcpService, McpRegistrationConfirmation
from yoetz.application.applied_mcp_route import read_applied_route
from yoetz.cli.provider_status import mcp_route_observation
from yoetz.config.paths import isolated_root
from yoetz.ports.harness_mcp import HarnessBinary
from yoetz.ports.integrations import HarnessId

async def main():
    codex, stage = sys.argv[1:]
    binary = HarnessBinary(HarnessId.CODEX, codex, "0.150.1", "supported")
    service = HarnessMcpService(CodexMcpAdapter(route_profile="strict" if stage == "strict" else "policy"))
    if stage == "probe":
        registration = subprocess.run([codex, "mcp", "get", "yoetz", "--json"], capture_output=True, check=True)
        entry = json.loads(registration.stdout)["transport"]
        child_env = {**os.environ, **entry["env"]}
        isolated = subprocess.run([entry["command"], "service", "isolation", "--json"], env=child_env, capture_output=True, check=True)
        identity = json.loads(isolated.stdout)
        assert identity["mode"] == "isolated"
        assert identity["binding"] == "environment_and_pin"
        dropped = subprocess.run([entry["command"], "service", "isolation", "--json"], env=os.environ, capture_output=True, check=True)
        pinned = json.loads(dropped.stdout)
        assert pinned["binding"] == "runtime_pin"
        assert pinned["path_identity"] == identity["path_identity"]
        params = StdioServerParameters(command=entry["command"], args=entry["args"], env={**os.environ, **entry["env"]})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert len(tools.tools) == 8
                result = await client.call_tool("read_guidance", {"uri":"yoetz://guidance/workflow.md"})
                assert not result.isError
                assert any("workflow" in getattr(item, "text", "") for item in result.content)
        print(json.dumps({"tools": len(tools.tools), "guidance": "success"}))
        return
    if stage == "status":
        observation = await service.observe(binary)
        route = await mcp_route_observation(Path.cwd())
        print(json.dumps({"state": observation.state.value, "binding": observation.isolation_binding,
                          "profile": observation.route_profile, "route": route}))
        return
    removing = stage == "remove"
    preview = await (service.preview_unregistration(binary) if removing else service.preview(binary))
    confirm = McpRegistrationConfirmation(preview.preview_digest, True, "noninteractive_flag")
    result = await (service.unregister(binary, confirm) if removing else service.register(binary, confirm))
    print(json.dumps({"action": result.action.value, "after": result.state_after.value,
                      "command": preview.serve_command, "root": str(isolated_root()),
                      "record": read_applied_route()}))

anyio.run(main)
"""


def test_packaged_absolute_launcher_with_real_codex() -> None:
    """A runtime-pinned wheel is owned and usable through Codex without ambient inheritance."""

    codex = _installed_codex_01501()
    root = _short_private_root()
    script = _REPO_ROOT / "scripts" / "provision_test_instance.py"
    base = root / "instances"
    base.mkdir(mode=0o700)
    env = {name: value for name, value in os.environ.items() if not name.startswith("YOETZ_")}
    codex_home = root / "codex"
    codex_home.mkdir(mode=0o700)
    env.update(CODEX_HOME=str(codex_home), CODEX_TESTING_HOME=str(codex_home))
    try:
        created = subprocess.run(
            [
                sys.executable,
                str(script),
                "create",
                "--base",
                str(base),
                "--tag",
                "a",
                "--lifecycle",
                "disposable",
                "--allow-dirty",
                "--json",
            ],
            env=env,
            capture_output=True,
            timeout=300,
            check=False,
        )
        assert created.returncode == 0, created.stderr.decode(errors="replace")
        launcher = Path(json.loads(created.stdout)["launcher"])
        driver = root / "driver.py"
        driver.write_text(_PACKAGED_DRIVER, encoding="utf-8")

        def run(stage: str) -> dict[str, object]:
            result = subprocess.run(
                [str(launcher.parent / "python"), str(driver), str(codex), stage],
                cwd=root,
                env=env,
                capture_output=True,
                timeout=60,
                check=False,
            )
            assert result.returncode == 0, result.stderr.decode(errors="replace")
            return cast(dict[str, object], json.loads(result.stdout))

        registered = run("install")
        assert registered["action"] == "register"
        assert registered["after"] == "yoetz_owned"
        assert cast(list[str], registered["command"])[0] == str(launcher)
        assert (
            cast(dict[str, object], registered["record"])["applied_serve_command"]
            == registered["command"]
        )
        assert run("install")["action"] == "noop"
        status = run("status")
        assert status["state"] == "yoetz_owned"
        assert status["binding"] == "isolated_exact"
        route = cast(dict[str, object], status["route"])
        assert route["ownership_state"] == "external"
        assert route["registered_profile"] == "policy"
        assert run("probe") == {"tools": 8, "guidance": "success"}

        # Codex itself starts the registered wheel, with no parent isolation variable. Its
        # Inventory must expose the real MCP server, not the synthetic compatibility stub.
        capture = root / "inventory.json"
        captured = subprocess.run(
            [
                sys.executable,
                str(_REPO_ROOT / "scripts" / "capture_codex_mcp_surface.py"),
                "--codex-binary",
                str(codex),
                "--codex-testing-home",
                str(codex_home),
                "--output",
                str(capture),
            ],
            cwd=root,
            env=env,
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert captured.returncode == 0, captured.stderr.decode(errors="replace")
        entries = json.loads(capture.read_bytes())["inventory"]["result"]["data"]
        assert len(entries) == 1
        assert len(entries[0]["tools"]) == 8
        assert entries[0]["serverInfo"]["name"] == "yoetz"
        assert run("strict")["action"] == "reregister"
        assert run("status")["profile"] == "strict"
        assert run("remove")["after"] == "absent"
        assert run("remove")["action"] == "noop"
    finally:
        if (base / "a").exists():
            disposed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "dispose",
                    "--base",
                    str(base),
                    "--tag",
                    "a",
                    "--json",
                ],
                env=env,
                capture_output=True,
                timeout=60,
                check=False,
            )
            assert disposed.returncode == 0, disposed.stderr.decode(errors="replace")
        shutil.rmtree(root, ignore_errors=True)
