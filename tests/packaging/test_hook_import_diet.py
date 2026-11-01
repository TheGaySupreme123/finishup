"""Import-diet regression guards for the Codex hook entry path (#242).

A hook is always a fresh process, so its import graph is paid per tool call.
Before this bound, ``finishup hooks observe`` loaded typer, pydantic, the protocol
schema catalog, and the whole ``finishup.application`` package — ~325 ms of the
measured 1.67-2.50 s hook, none of which a hook consumes.

These probes spawn a clean interpreter and only import modules; nothing here
touches the user's state directory or the repository working tree.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_PROBE_TIMEOUT: Final = 60
# Everything a hook must never pull in: the CLI framework, the wire model and
# schema catalog, the service control client, and the service-internal
# application package.
_FORBIDDEN: Final = (
    "pydantic",
    "jsonschema",
    "typer",
    "anyio",
    "finishup.protocol.models",
    "finishup.protocol.schemas",
    "finishup.service.client",
    "finishup.cli.app",
    "finishup.cli.render",
    "finishup.application.publish_work",
    "finishup.application.unit_of_work",
    "finishup.ports.ledger",
    "finishup.domain.events",
    "finishup.application.recommendations",
    "finishup.application.package_update",
)
# Drift ceiling: the measured set after the diet is well under this, so a
# future eager import shows up here even if it is not on the named list.
_MAX_MODULES: Final = 400


def _probe(source: str) -> dict[str, object]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONSTARTUP", None)
    seeded_source = f"import sys; sys.path.insert(0, {os.fspath(_REPO_ROOT / 'src')!r})\n" + source
    completed = subprocess.run(  # noqa: S603 - fixed in-repository interpreter and source
        [sys.executable, "-I", "-c", seeded_source],
        capture_output=True,
        env=environment,
        check=False,
        timeout=_PROBE_TIMEOUT,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    parsed: dict[str, object] = json.loads(completed.stdout.decode("utf-8"))
    return parsed


_REPORT: Final = (
    "import json, sys\n"
    "{statement}\n"
    "print(json.dumps({{'modules': sorted(sys.modules), 'count': len(sys.modules)}}))\n"
)


def _modules(statement: str) -> list[str]:
    report = _probe(_REPORT.format(statement=statement))
    return [str(name) for name in cast(Sequence[object], report["modules"])]


def test_hook_entry_does_not_import_named_heavy_modules() -> None:
    loaded = set(_modules("from finishup.cli import entry"))
    offenders = sorted(loaded & set(_FORBIDDEN))
    assert not offenders, (
        "the console entry shim must reach the observe hook without the full CLI "
        f"import graph; it loaded {offenders}"
    )


def test_observe_hooks_module_import_set_is_bounded() -> None:
    loaded = _modules("import finishup.cli.observe_hooks")
    offenders = sorted(set(loaded) & set(_FORBIDDEN))
    assert not offenders, f"finishup.cli.observe_hooks eagerly imported {offenders}"
    assert len(loaded) < _MAX_MODULES, (
        f"the hook import graph grew to {len(loaded)} modules; every one of them "
        "is paid on every tool call"
    )


def test_finishup_application_package_import_is_lazy() -> None:
    eager = _modules("import finishup.application")
    assert "finishup.application.publish_work" not in eager, (
        "importing the application package must not drag publish_work -> "
        "unit_of_work -> ports.ledger -> domain.events -> protocol.models"
    )
    resolved = _modules("from finishup.application import Application")
    assert "finishup.application.service" in resolved, (
        "the lazy re-export must still resolve the documented public names"
    )


def _short_private_root() -> Path:
    """Return a disposable, owner-only root accepted by the isolation gate."""

    base = Path.home() / ".yz-hook-import-diet"
    base.mkdir(mode=0o700, exist_ok=True)
    root = base / secrets.token_hex(4)
    root.mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    return root


def _run_entry_hook(
    command: Sequence[str], *, payload: bytes, isolated_root: Path
) -> tuple[dict[str, object], subprocess.CompletedProcess[bytes]]:
    """Call the real console entry function in a fresh interpreter.

    The hook's stdout is intentionally left on the child pipe so this exercises the same
    entrypoint and host response path.  The probe report goes to stderr after ``SystemExit`` so
    the two streams cannot be confused when a hook emits its normal JSON response.
    """

    argv = ["finishup", *command]
    source = (
        f"import json, sys; sys.path.insert(0, {os.fspath(_REPO_ROOT / 'src')!r})\n"
        "from finishup.cli import entry\n"
        f"sys.argv = {json.dumps(argv)}\n"
        "error = None\n"
        "try:\n"
        "    entry.main()\n"
        "except SystemExit as exc:\n"
        "    code = exc.code\n"
        "except BaseException as exc:\n"
        "    code = -1\n"
        "    error = f'{type(exc).__name__}: {exc}'\n"
        "else:\n"
        "    code = 0\n"
        "print('__FINISHUP_IMPORT_DIET__' + json.dumps({\n"
        "    'code': code,\n"
        "    'error': error,\n"
        "    'modules': sorted(sys.modules),\n"
        "}), file=sys.stderr)\n"
    )
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("FINISHUP_") and key not in {"PYTHONPATH", "PYTHONSTARTUP"}
    }
    environment.update(
        {
            "HOME": str(isolated_root / "home"),
            "PYTHONNOUSERSITE": "1",
            "FINISHUP_ISOLATED_ROOT": str(isolated_root),
        }
    )
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and in-repository source
        [sys.executable, "-I", "-c", source],
        input=payload,
        capture_output=True,
        env=environment,
        check=False,
        timeout=_PROBE_TIMEOUT,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    marker = "__FINISHUP_IMPORT_DIET__"
    reports = [
        line[len(marker) :]
        for line in completed.stderr.decode("utf-8", errors="replace").splitlines()
        if line.startswith(marker)
    ]
    assert len(reports) == 1, completed.stderr.decode("utf-8", errors="replace")
    return cast(dict[str, object], json.loads(reports[0])), completed


@pytest.mark.parametrize(
    ("command", "payload"),
    (
        (
            (
                "hooks",
                "claude-observe",
                "--event",
                "PreToolUse",
                "--observation-profile",
                "claude-code-ordinary-observation-v1",
            ),
            b'{"session_id":"hook-import-diet-claude"}',
        ),
        (
            (
                "hooks",
                "cursor-observe",
                "--event",
                "preToolUse",
                "--observation-profile",
                "cursor-ordinary-observation-v1",
            ),
            b'{"session_id":"hook-import-diet-cursor"}',
        ),
    ),
)
def test_ordinary_native_hooks_call_entry_without_loading_full_cli(
    command: tuple[str, ...], payload: bytes
) -> None:
    """Keep actual Claude/Cursor ordinary dispatch on the lightweight entry path (#616)."""

    root = _short_private_root()
    try:
        report, completed = _run_entry_hook(command, payload=payload, isolated_root=root)
        assert report["code"] == 0, report
        assert report["error"] is None, report
        loaded = set(cast(Sequence[object], report["modules"]))
        assert "finishup.cli.observe_hooks" in loaded
        assert "finishup.cli.app" not in loaded
        assert "typer" not in loaded
        assert "pydantic" not in loaded
        assert completed.stdout == (
            b'{"permission":"allow"}\n' if command[1] == "cursor-observe" else b"{}\n"
        )

        diagnostic = root / "state" / "observation" / "hook-diagnostics.jsonl"
        assert diagnostic.is_file(), (
            "the ordinary profile event should reach its host-specific handler and record the "
            "minimal rejected payload in the isolated diagnostic stream"
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.parametrize(
    ("command", "payload"),
    (
        (
            ("hooks", "startup-gate", "--host", "claude", "--event", "PreToolUse"),
            b'{"session_id":"hook-import-diet-startup","cwd":"/project","tool_name":"Read"}',
        ),
        (("hooks", "startup-context", "--host", "claude"), b""),
    ),
)
def test_required_startup_hooks_keep_the_import_diet(
    command: tuple[str, ...], payload: bytes
) -> None:
    """Startup control must stay independent of observation and the full CLI graph."""

    root = _short_private_root()
    try:
        report, completed = _run_entry_hook(command, payload=payload, isolated_root=root)
        assert report["code"] == 0, report
        assert report["error"] is None, report
        loaded = set(cast(Sequence[object], report["modules"]))
        assert "finishup.cli.observe_hooks" not in loaded
        assert "finishup.cli.app" not in loaded
        assert "typer" not in loaded
        assert "pydantic" not in loaded
        json.loads(completed.stdout.decode("utf-8"))
    finally:
        shutil.rmtree(root, ignore_errors=True)
