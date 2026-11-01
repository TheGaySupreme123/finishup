"""Real Codex connection lifecycles in a disposable, pinned FinishUP installation.

This cell uses empty Codex homes and never performs a model turn or reads login material.
It is skipped when the Codex CLI is unavailable; deterministic adapter coverage runs everywhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from finishup.adapters.integrations.codex_plugin import plugin_tree_matches_marker
from finishup.protocol.canonical import canonical_digest, canonical_encode

_REPO = Path(__file__).resolve().parents[2]
_CODEX = shutil.which("codex")
_BASE = Path.home() / ".yz-clife"


def _run(argv: list[str], *, env: dict[str, str], cwd: Path, timeout: int = 120) -> dict[str, Any]:
    result = subprocess.run(
        argv, env=env, cwd=cwd, capture_output=True, timeout=timeout, check=False
    )
    if result.returncode != 0:
        pytest.fail(
            f"{argv[1:3]} exited {result.returncode}\n"
            + result.stderr.decode(errors="replace")
            + result.stdout.decode(errors="replace"),
            pytrace=False,
        )
    return json.loads(result.stdout)


def _earlier_inventory(destination: Path) -> None:
    """Simulate a pristine earlier shipped skill using its installer-recorded inventory."""
    (destination / "references/workflow.md").write_bytes(b"# Earlier shipped workflow\n")
    marker_path = destination / ".yoetz-install.json"
    marker = json.loads(marker_path.read_bytes())
    for row in marker["managed_files"]:
        data = (destination / row["relative_path"]).read_bytes()
        row["sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
        row["size"] = len(data)
    marker.pop("marker_digest")
    marker["marker_digest"] = canonical_digest(marker)
    marker_path.write_bytes(canonical_encode(marker) + b"\n")


@pytest.mark.skipif(_CODEX is None, reason="requires the real Codex CLI, with empty isolated homes")
def test_real_codex_connect_upgrade_disconnect() -> None:
    assert _CODEX is not None
    # Capture the base before the subprocess fixture rebases HOME. A short independent
    # root keeps instance socket paths within macOS's sun_path bound (ADR-028).
    _BASE.mkdir(mode=0o700, exist_ok=True)
    work = _BASE / secrets.token_hex(3)
    work.mkdir(mode=0o700)
    base = work / "instances"
    provision = [sys.executable, str(_REPO / "scripts/provision_test_instance.py")]
    env = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_"))
    }
    created = False
    try:
        instance = _run(
            [
                *provision,
                "create",
                "--base",
                str(base),
                "--tag",
                "cl",
                "--checkout",
                str(_REPO),
                "--allow-dirty",
                "--json",
            ],
            env=env,
            cwd=work,
            timeout=300,
        )
        created = True
        launcher = str(instance["launcher"])
        for shape in ("policy", "strict", "legacy-policy", "legacy-strict"):
            project, home = work / (shape + "-project"), work / (shape + "-home")
            project.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            selected_env = {**env, "CODEX_HOME": str(home), "CODEX_TESTING_HOME": str(home)}
            route = "strict" if shape.endswith("strict") else "policy"
            common = [
                "--host",
                "codex",
                "--host-path",
                _CODEX,
                "--host-config-root",
                str(home),
                "--project",
                str(project),
                "--non-interactive",
                "--json",
            ]

            def apply(action: str) -> dict[str, Any]:
                preview = _run(
                    [launcher, "setup", action, *common, "--route-profile", route],
                    env=selected_env,
                    cwd=project,
                )
                if preview["outcome"] == "unchanged":
                    return preview
                plan = preview["plan"]
                assert plan["route_profile"] == route
                report = _run(
                    [
                        launcher,
                        "setup",
                        action,
                        *common,
                        "--route-profile",
                        route,
                        "--request-id",
                        plan["request_id"],
                        "--preview-digest",
                        plan["preview_digest"],
                        "--accept",
                    ],
                    env=selected_env,
                    cwd=project,
                )
                assert report["outcome"] == "completed", report
                return report

            apply("run")
            skill = project / ".agents/skills/finishup"
            before = (skill / "references/workflow.md").read_bytes()
            config = home / "config.toml"
            tables = tomllib.loads(config.read_text())
            assert ("finishup" in tables.get("mcp_servers", {})) is (route == "strict")
            if shape.startswith("legacy"):
                _earlier_inventory(skill)
                # 0.3 policy homes had a direct transport beside the plugin's cache transport.
                if route == "policy":
                    cache = next((home / "plugins/cache/finishup/finishup").glob("*/.mcp.json"))
                    entry = json.loads(cache.read_bytes())["mcpServers"]["finishup"]
                    add = [_CODEX, "mcp", "add", "finishup"]
                    for name, value in entry.get("env", {}).items():
                        add += ["--env", name + "=" + value]
                    result = subprocess.run(
                        [*add, "--", entry["command"], *entry["args"]],
                        cwd=project,
                        env=selected_env,
                        capture_output=True,
                        timeout=30,
                        check=False,
                    )
                    assert result.returncode == 0, result.stderr.decode()
                cache = next((home / "plugins/cache/finishup/finishup").glob("*/.mcp.json"))
                portable = project / ".agents/plugins/finishup"
                # Earlier activation copied the portable bare-command cache and its marker.
                # Pair that state with the earlier pristine project skill, so the upgrade
                # must reach the cache repair through the ordinary reconnect path.
                shutil.rmtree(cache.parent)
                shutil.copytree(portable, cache.parent)
                assert plugin_tree_matches_marker(
                    {
                        path.relative_to(cache.parent).as_posix(): path.read_bytes()
                        for path in cache.parent.rglob("*")
                        if path.is_file()
                    }
                )
                apply("run")
                rebound = json.loads(cache.read_bytes())["mcpServers"]["finishup"]
                assert rebound["command"] == launcher
                assert rebound["env"] == {
                    "FINISHUP_ISOLATED_ROOT": instance["isolated_root"],
                    "YOETZ_ISOLATED_ROOT": instance["isolated_root"],
                }
                assert (skill / "references/workflow.md").read_bytes() == before
                assert apply("run")["outcome"] == "unchanged"
            apply("disconnect")
            assert not skill.exists()
            assert not (home / "plugins/cache/finishup/finishup").exists() or not list(
                (home / "plugins/cache/finishup/finishup").iterdir()
            )
            assert not tomllib.loads(config.read_text()).get("mcp_servers", {}).get("finishup")
            listed = subprocess.run(
                [_CODEX, "mcp", "list", "--json"],
                cwd=project,
                env=selected_env,
                capture_output=True,
                timeout=30,
                check=False,
            )
            assert listed.returncode == 0, listed.stderr.decode()
            assert json.loads(listed.stdout) == []
            assert apply("disconnect")["outcome"] == "unchanged"
    finally:
        if created:
            _run(
                [*provision, "dispose", "--base", str(base), "--tag", "cl", "--json"],
                env=env,
                cwd=work,
                timeout=120,
            )
        if work.exists():
            shutil.rmtree(work)
