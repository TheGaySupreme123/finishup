"""Capability MCP requests must reach their own instance with an outer instance running."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client
from tests.capability.test_codex_six_tools import (
    _serve_parameters,  # pyright: ignore[reportPrivateUsage]
)
from tests.packaging.test_instance_lifecycle import (
    _REPO_ROOT,  # pyright: ignore[reportPrivateUsage]
    _clean_env,  # pyright: ignore[reportPrivateUsage]
    _dispose,  # pyright: ignore[reportPrivateUsage]
    _identity_snapshot,  # pyright: ignore[reportPrivateUsage]
    _json,  # pyright: ignore[reportPrivateUsage]
    _provision,  # pyright: ignore[reportPrivateUsage]
    _short_home,  # pyright: ignore[reportPrivateUsage]
    _start_service,  # pyright: ignore[reportPrivateUsage]
    _stop_process,  # pyright: ignore[reportPrivateUsage]
)


def test_capability_request_preserves_outer_holder(monkeypatch: pytest.MonkeyPatch) -> None:
    cell = _short_home("cap673")
    env = _clean_env(cell / "h")
    outer_base, child_base = cell / "i", cell / "mcp-home"
    services: list[subprocess.Popen[bytes]] = []
    try:
        outer = _provision(outer_base, "o", _REPO_ROOT, env)
        child = _provision(child_base, "finishup", _REPO_ROOT, env)
        outer_launcher = Path(cast(str, outer["launcher"]))
        child_launcher = Path(cast(str, child["launcher"]))
        services.append(_start_service(outer_launcher, env))
        services.append(_start_service(child_launcher, env))
        outer_root = outer_base / "o" / "state"
        before = (_identity_snapshot(outer_root), _identity_snapshot(outer_root / "state"))
        outer_status = _json(outer_launcher, ["service", "status"], env)
        log_root = outer_root / "log"
        logs_before = {p.name: p.read_bytes() for p in log_root.glob("*") if p.is_file()}
        monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(outer_root))

        async def request() -> None:
            parameters = _serve_parameters(cell)
            assert parameters.env is not None
            assert parameters.env["FINISHUP_ISOLATED_ROOT"] == str(
                child_base / "finishup" / "state"
            )
            async with stdio_client(parameters) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "start",
                        {
                            "protocol_version": "0.1",
                            "schema_version": "1.0.0",
                            "request_id": "req_67300000-0000-4000-8000-000000000001",
                            "mode": "create",
                            "task_title": "capability isolation probe",
                            "requested_view": "compact",
                            "actor": {"actor_id": "harness:capability", "actor_type": "harness"},
                            "client": {
                                "kind": "cooperative_agent",
                                "version": "0.1.0",
                                "integration": "cooperative_mcp",
                            },
                        },
                    )
                    # This valid workflow reaches the service, whose fresh vault refuses it.
                    wire = json.dumps(result.model_dump(mode="json"))
                    assert "vault_initialization_required" in wire
                    assert "INVALID_REQUEST" not in wire

        for candidate in (str(child_launcher.parent / "python"), ""):
            monkeypatch.setenv("FINISHUP_CANDIDATE_PYTHON", candidate)
            asyncio.run(request())
            assert services[0].poll() is None
            assert (
                _identity_snapshot(outer_root),
                _identity_snapshot(outer_root / "state"),
            ) == before
            assert (
                _json(outer_launcher, ["service", "status"], env)["service_instance_id"]
                == outer_status["service_instance_id"]
            )
            assert {
                p.name: p.read_bytes() for p in log_root.glob("*") if p.is_file()
            } == logs_before
    finally:
        for process in services:
            _stop_process(process)
        for base, tag in ((outer_base, "o"), (child_base, "finishup")):
            if (base / tag).exists():
                _dispose(base, tag, env)
        shutil.rmtree(cell)
