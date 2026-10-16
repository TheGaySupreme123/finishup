"""Executed R3 counterexamples and conservative exploration boundaries for PR #1080."""

from __future__ import annotations

import importlib
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from builders.observed_runs import ObservedLedger
from finishup.domain.events import ResultOutcome
from finishup.domain.observation_selection import command_runner_class, native_command_runner_class
from finishup.kernel.closing_review_delta import closing_review_delta
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import EDITED_AFTER_LAST_VERIFICATION_GAP, task_fact_signals
from finishup.protocol.canonical import JsonValue
from unit.kernel.test_n6_closing_review_delta import _prefix  # pyright: ignore[reportPrivateUsage]


def _material(command: str, *, write_scope: str | None = None) -> bool:
    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.run(command, ResultOutcome.SUCCESS, exit_status=0, write_scope=write_scope)
    state = replay(ledger.prefix)
    return all(closing_review_delta(row, state) for row in ledger.records[start:])


@pytest.mark.parametrize(
    "command",
    [
        "date -u",
        "date -u +%Y-%m-%dT%H:%M:%SZ",
        "sed -n '1,10p' file",
        "sed -n '$p' file",
        "sed -n '1,$p' file",
        "rg -n x file",
        "rg x file; sed -n '1,10p' file",
        "finishup status --json",
        "finishup receipt --json",
        "finishup check --await-observations --json",
        "finishup closure-prepare --session-id s --writer-id w",
        'finishup status --request \'{"text":"--output ./x"}\'',
        "env LC_ALL=C date -u",
        "nice -n 5 date -u",
        "timeout 5 date -u",
        "command date -u",
        "exec /bin/date -u",
        "/usr/bin/date -u",
    ],
)
def test_closed_audited_reads_do_not_rearm(command: str) -> None:
    assert command_runner_class({"command": command}) == "exploration"
    assert not _material(command)


@pytest.mark.parametrize("command", ["date -u", "finishup status --json", "sed -n '1p' file"])
def test_workspace_write_facts_override_exploration(command: str) -> None:
    assert _material(command, write_scope="workspace")


@pytest.mark.parametrize(
    "command",
    [
        "env PATH=/shadow date -u",
        "PATH=/shadow date -u",
        "env -i date -u",
        "env -S 'PATH=/shadow date' -u",
        "env FOO=1 date -u",
        "LD_PRELOAD=./shim.so date -u",
        "RIPGREP_CONFIG_PATH=./config rg x file",
        "nice -n 5 /shadow/bin/date -u",
        "timeout 5 /shadow/bin/date -u",
        "sudo date -u",
        "command /shadow/bin/date -u",
        "exec /shadow/bin/date -u",
        "nohup date -u",
        "/shadow/bin/env date -u",
        "/shadow/bin/date -u",
        "./date -u",
        "date -u; PATH=/shadow date -u",
        "env PATH=/shadow date -u; rg x file",
        "/shadow/bin/date -u; rg x file",
        "bash -c 'date -u'; rg x file",
        "/shadow/bin/bash -c 'date -u; date -u'",
        "bash -c 'date -u; date -u'",
        "finishup closure-prepare --session-id s --writer-id w --output ./file",
        "finishup closure-prepare --session-id=s --writer-id=w --output=./file",
        "finishup receipt --output ./file",
        "finishup status --unknown-path=./file",
        "finishup status --input",
        "finishup status ./file",
        "finishup connect codex",
        "git status --short",
        "git -C repo status --short",
        "git -c core.fsmonitor= -c core.hooksPath=/dev/null status --short",
        "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./rewrite git status",
        "sed -n '1p; w file' input",
        "sed -i '' s/x/y/ file",
        "date -s tomorrow",
        "date -u > file",
        "date -u $(touch file)",
    ],
)
def test_unproven_commands_stay_material(command: str) -> None:
    assert command_runner_class({"command": command}) != "exploration"
    assert _material(command)


@pytest.mark.parametrize(
    "argv,exploration",
    [
        (["/bin/bash", "-lc", "date -u"], True),
        (["/bin/bash", "-lc", "rg x file; sed -n '1p' file"], True),
        (["/bin/bash", "-lc", "/shadow/bin/date -u"], False),
        (["/shadow/bin/bash", "-lc", "date -u; date -u"], False),
        (["/bin/bash", "-lc", "/shadow/bin/bash -c 'date -u; date -u'"], False),
        (["/bin/bash", "-lc", "env PATH=/shadow date -u"], False),
    ],
)
def test_native_argv_does_not_erase_nested_executable_paths(
    argv: list[str], exploration: bool
) -> None:
    assert (native_command_runner_class(cast(JsonValue, argv)) == "exploration") is exploration


def test_shadow_date_mutations_are_material(tmp_path: Path) -> None:
    victim = tmp_path / "deliverable.txt"
    shadow = tmp_path / "shadow"
    (shadow / "bin").mkdir(parents=True)
    body = "#!/bin/sh\nprintf path-mutated > " + shlex.quote(str(victim)) + "\n"
    for name in (shadow / "date", shadow / "bin" / "date"):
        name.write_text(body)
        name.chmod(0o700)
    commands = [
        f"env PATH={shlex.quote(str(shadow))} date -u",
        f"{shlex.quote(str(shadow / 'bin' / 'date'))} -u",
    ]
    for command in commands:
        victim.write_text("reviewed")
        subprocess.run(["/bin/sh", "-c", command], cwd=tmp_path, check=True, capture_output=True)
        assert victim.read_text() == "path-mutated"
        assert _material(command)


@pytest.mark.skipif(os.name != "posix", reason="PTY/nohup boundary is POSIX")
def test_nohup_itself_writes_with_terminal_stdout(tmp_path: Path) -> None:
    import pty

    program = shutil.which("nohup")
    if program is None:
        pytest.skip("nohup unavailable")
    master, slave = pty.openpty()
    try:
        subprocess.run(
            [program, "/bin/date", "-u"],
            cwd=tmp_path,
            stdin=subprocess.DEVNULL,
            stdout=slave,
            stderr=slave,
            check=True,
            timeout=10,
        )
    finally:
        os.close(slave)
        os.close(master)
    assert (tmp_path / "nohup.out").is_file()
    assert _material("nohup /bin/date -u")


@pytest.mark.parametrize("filename", ["finalize.py", "fit_regression.py"])
def test_executed_generator_preserves_verification_gap(tmp_path: Path, filename: str) -> None:
    script = tmp_path / filename
    script.write_text(
        "from pathlib import Path\n"
        "Path(__file__).with_name('deliverable.txt').write_text('unverified generated output')\n"
    )
    subprocess.run([sys.executable, str(script)], cwd=tmp_path, check=True)
    assert (tmp_path / "deliverable.txt").read_text() == "unverified generated output"
    command = "python " + shlex.quote(str(script))
    assert command_runner_class({"command": command}) == "other"
    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.run(command, ResultOutcome.SUCCESS, exit_status=0, write_scope="workspace")
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


def test_real_cli_output_writer_is_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = importlib.import_module("finishup.cli.app")
    closure = importlib.import_module("finishup.cli.closure")

    class Client:
        async def status(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("Synthetic preparation must not call a service")

        async def close(self) -> None:
            pass

    async def client() -> Client:
        return Client()

    async def prepared(*args: object, **kwargs: object) -> dict[str, object]:
        return {"inventory": {}, "frontier": 1, "preparatory_only": True}

    monkeypatch.setattr(app, "build_service_client", client)
    monkeypatch.setattr(closure, "prepare_closure", prepared)
    victim = tmp_path / "deliverable.txt"
    victim.write_text("reviewed")
    args = [
        "closure-prepare",
        "--session-id",
        "ses_00000000-0000-4000-8000-000000000001",
        "--writer-id",
        "wri_00000000-0000-4000-8000-000000000001",
        "--output",
        str(victim),
    ]
    result = CliRunner().invoke(app.app, args)
    assert result.exit_code == 0, result.exception
    assert victim.read_text() != "reviewed"
    assert _material("finishup " + shlex.join(args))


def test_real_status_fsmonitor_and_clean_filter_are_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = shutil.which("git")
    if git is None:
        pytest.skip("Git unavailable")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in tuple(os.environ):
        if name.startswith(("GIT_TRACE", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")) or name in {
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_DIR",
            "GIT_WORK_TREE",
        }:
            monkeypatch.delenv(name)

    def run(*args: str) -> None:
        subprocess.run([git, *args], cwd=tmp_path, check=True, capture_output=True)

    victim = tmp_path / "tracked.txt"
    run("init", "-q")
    victim.write_text("reviewed")
    run("add", "tracked.txt")
    monitor = tmp_path / "monitor.sh"
    monitor.write_text("#!/bin/sh\nprintf fsmonitor-mutated > " + shlex.quote(str(victim)) + "\n")
    monitor.chmod(0o700)
    run("config", "core.fsmonitor", str(monitor))
    run("config", "core.fsmonitorHookVersion", "2")
    run("status", "--short")
    assert victim.read_text() == "fsmonitor-mutated"
    assert _material("git status --short")

    # Disabling fsmonitor and hooks does not disable repository-configured clean filters.
    run("config", "--unset", "core.fsmonitor")
    filter_script = tmp_path / "filter.sh"
    marker = tmp_path / "filter-ran"
    filter_script.write_text("#!/bin/sh\nprintf mutated > " + shlex.quote(str(marker)) + "\ncat\n")
    filter_script.chmod(0o700)
    run("config", "filter.rewrite.clean", str(filter_script))
    (tmp_path / ".gitattributes").write_text("tracked.txt filter=rewrite\n")
    # Equal size requires content comparison; a size change can mark it dirty without filtering.
    victim.write_text("updated!")
    run("-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null", "status", "--short")
    assert marker.read_text() == "mutated"
    assert _material("git -c core.fsmonitor= -c core.hooksPath=/dev/null status --short")
