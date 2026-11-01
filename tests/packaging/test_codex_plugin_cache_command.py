"""The pinned Codex plugin cache launches its own runtime, not whatever ``finishup`` is on PATH.

Activation runs inside a disposable pinned instance (ADR-028). The host is scripted with the
same command protocol the marketplace unit tests use, so this cell does not need a Codex
binary. The cache ``.mcp.json`` is still the bytes that instance's activation writes.
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Final, cast

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_SCRIPT: Final = _REPO_ROOT / "scripts" / "provision_test_instance.py"
_BASE: Final = Path.home() / ".yz-plugcache"

_DRIVER: Final = r"""
import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast

from finishup import __version__
from finishup.adapters.integrations.codex_marketplace import (
    apply_activation,
    preview_activation,
)
from finishup.adapters.integrations.codex_plugin import install_plugin
from finishup.ports.integrations import IntegrationScope, IntegrationTarget


class _Host:
    def __init__(self, project: Path, home: Path) -> None:
        self.project = project
        self.home = home
        self.executable = home / "codex"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o700)

    def __call__(
        self, command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        args = tuple(command[1:])
        if args == ("--version",):
            return subprocess.CompletedProcess(
                command, 0, stdout=b"codex-cli 0.148.0-alpha.6\n", stderr=b""
            )
        if args == ("plugin", "list", "--marketplace", "finishup", "--json"):
            config = self.home / "config.toml"
            cache = self.home / f"plugins/cache/finishup/finishup/{__version__}"
            parsed = tomllib.loads(config.read_text(encoding="utf-8")) if config.is_file() else {}
            binding = cast(dict[str, object], parsed.get("marketplaces", {})).get("finishup")
            if not isinstance(binding, dict):
                body: dict[str, object] = {"installed": [], "available": []}
            else:
                installed = cache.is_dir()
                row = {
                    "pluginId": "finishup@finishup",
                    "name": "finishup",
                    "marketplaceName": "finishup",
                    "version": __version__,
                    "installed": installed,
                    "enabled": True,
                    "source": {
                        "source": "local",
                        "path": str(self.project / ".agents/plugins/finishup"),
                    },
                    "marketplaceSource": {"sourceType": "local", "source": str(self.project)},
                }
                body = {
                    "installed" if installed else "available": [row],
                    "available" if installed else "installed": [],
                }
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(body).encode(), stderr=b"")
        if args == ("plugin", "add", "finishup@finishup", "--json"):
            bound = tomllib.loads((self.home / "config.toml").read_text(encoding="utf-8"))
            source = Path(bound["marketplaces"]["finishup"]["source"]) / ".agents/plugins/finishup"
            destination = self.home / f"plugins/cache/finishup/finishup/{__version__}"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)
            body = {
                "pluginId": "finishup@finishup",
                "name": "finishup",
                "marketplaceName": "finishup",
                "version": __version__,
                "installedPath": str(destination),
            }
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(body).encode(), stderr=b"")
        raise AssertionError(command)


def main() -> None:
    project = Path(sys.argv[1])
    home = Path(sys.argv[2])
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
    install_plugin(target, allow_untested=True, codex_version="0.148.0-alpha.6")
    host = _Host(project, home)
    preview = preview_activation(
        target,
        executable_path=str(host.executable),
        codex_home=home,
        _run=host,
    )
    inspection = apply_activation(
        target,
        approved_digest=preview.preview_digest,
        executable_path=str(host.executable),
        codex_home=home,
        _run=host,
    )
    cache = home / "plugins" / "cache" / "finishup" / "finishup" / __version__
    sys.stdout.write(
        json.dumps({"state": inspection.state.value, "cache": str(cache)}) + "\n"
    )


if __name__ == "__main__":
    main()
"""


def _private(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _clean_env() -> dict[str, str]:
    return {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("FINISHUP_", "YOETZ_"))
    }


def _command_strings(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        mapping = cast(dict[str, object], value)
        command = mapping.get("command")
        if isinstance(command, str):
            found.append(command)
        for child in mapping.values():
            found.extend(_command_strings(child))
    elif isinstance(value, list):
        for child in cast(list[object], value):
            found.extend(_command_strings(child))
    return found


def test_pinned_plugin_cache_command_ignores_a_foreign_finishup_on_path() -> None:
    token = secrets.token_hex(4)
    work = _BASE / token
    base = work / "instances"
    project = work / "project"
    home = work / "codex-home"
    _BASE.mkdir(mode=0o700, exist_ok=True)
    _BASE.chmod(0o700)
    _private(work)
    _private(base)
    _private(project)
    _private(home)
    env = _clean_env()
    tag = "cache"
    try:
        created = subprocess.run(
            [
                sys.executable,
                str(_SCRIPT),
                "create",
                "--base",
                str(base),
                "--tag",
                tag,
                "--checkout",
                str(_REPO_ROOT),
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
        payload = cast(dict[str, object], json.loads(created.stdout))
        launcher = Path(cast(str, payload["launcher"]))
        isolated = cast(str, payload["isolated_root"])
        driver = work / "driver.py"
        driver.write_text(_DRIVER, encoding="utf-8")
        activated = subprocess.run(
            [str(launcher.parent / "python"), str(driver), str(project), str(home)],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert activated.returncode == 0, activated.stderr.decode(errors="replace")
        reported = cast(dict[str, object], json.loads(activated.stdout))
        assert reported["state"] == "active"
        cache = Path(cast(str, reported["cache"]))
        document = cast(dict[str, object], json.loads((cache / ".mcp.json").read_text()))
        servers = cast(dict[str, object], document["mcpServers"])
        entry = cast(dict[str, object], servers["finishup"])
        command = cast(str, entry["command"])
        args = cast(list[object], entry["args"])
        environment = cast(dict[str, object], entry["env"])
        assert Path(command).is_absolute()
        assert Path(command).resolve() == launcher.resolve()
        assert args == ["mcp", "serve", "--host", "codex"]
        assert environment == {
            "FINISHUP_ISOLATED_ROOT": isolated,
            "YOETZ_ISOLATED_ROOT": isolated,
        }

        hooks = json.loads((cache / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        commands = _command_strings(hooks)
        assert "finishup hooks session-start --workspace ." in commands
        assert all(
            item.startswith("finishup ") and not Path(item).is_absolute() for item in commands
        )
        assert all(str(launcher.resolve()) not in item for item in commands)

        sentinel_dir = work / "sentinel-bin"
        _private(sentinel_dir)
        marker = work / "sentinel-ran"
        sentinel = sentinel_dir / "finishup"
        sentinel.write_text(
            "#!/bin/sh\nprintf ran > " + shlex.quote(str(marker)) + "\nexit 41\n",
            encoding="utf-8",
        )
        sentinel.chmod(0o700)
        version_env = dict(env)
        version_env.pop("FINISHUP_ISOLATED_ROOT", None)
        version_env.pop("YOETZ_ISOLATED_ROOT", None)
        version_env["PATH"] = f"{sentinel_dir}{os.pathsep}{version_env.get('PATH', '')}"
        version = subprocess.run(
            [command, "version"],
            cwd=work,
            env=version_env,
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert version.returncode == 0, version.stderr.decode(errors="replace")
        assert version.stdout.decode(errors="replace").strip()
        assert not marker.exists()
        assert stat.S_ISREG(sentinel.stat().st_mode)
    finally:
        if (base / tag).exists():
            disposed = subprocess.run(
                [
                    sys.executable,
                    str(_SCRIPT),
                    "dispose",
                    "--base",
                    str(base),
                    "--tag",
                    tag,
                    "--json",
                ],
                env=env,
                capture_output=True,
                timeout=60,
                check=False,
            )
            assert disposed.returncode == 0, disposed.stderr.decode(errors="replace")
        shutil.rmtree(work, ignore_errors=True)
