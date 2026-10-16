"""An ``exploration`` verdict needs a host-resolved program and a proven read (PR #1080 round 4).

Each counterexample below is a command the round-3 review executed to change a deliverable while
the classifier called it a read. Every one is now conservative; the audited read-only closure
shapes stay exploration.
"""

from __future__ import annotations

import pytest

from finishup.domain.observation_selection import (
    command_is_verification,
    command_runner_class,
    git_status_read_operands,
)


def _runner(command: str) -> str | None:
    return command_runner_class({"tool_name": "exec_command", "tool_input": {"cmd": command}})


@pytest.mark.parametrize(
    "command",
    [
        "date -u",
        "date -u +%Y-%m-%dT%H:%M:%SZ",
        "sed -n '1,120p' guidance/receipt.md",
        "sed -n '$p' notes.txt",
        "rg -n closing guidance/",
        "finishup status --json",
        "finishup receipt --json",
        "finishup check --json --await-observations",
        "finishup start --task-statement-file task.txt --json",
        "finishup closure-prepare --session-id s --writer-id w",
        "yoetz status --json",
        "rg closing guidance/receipt.md; sed -n '1,120p' guidance/receipt.md",
        # Inert locale/time-zone assignments, transparent wrappers and system program paths.
        "TZ=UTC date -u",
        "env LC_ALL=C sed -n '1,10p' notes.txt",
        "timeout 5 date -u",
        "nice -n 5 rg x notes.txt",
        "/usr/bin/date -u",
        "/bin/date -u",
        "date -u; date -u",
    ],
)
def test_audited_read_shapes_stay_exploration(command: str) -> None:
    assert _runner(command) == "exploration"


@pytest.mark.parametrize(
    "command",
    [
        # Finding 5: an assignment or wrapper that changes resolution, or an agent-placed program.
        "env PATH=/agent/shadow date -u",
        "PATH=/agent/shadow date -u",
        "/agent/shadow/bin/date -u",
        "/agent/shadow/date -u",
        "./date -u",
        "env -i date -u",
        "env -S 'PATH=/agent/shadow date' -u",
        "/agent/bin/env date -u",
        "/agent/bin/timeout 5 date -u",
        "timeout 5 /agent/shadow/date -u",
        "env FOO=1 date -u",
        "LD_PRELOAD=./shim.so rg x notes.txt",
        "DYLD_INSERT_LIBRARIES=./shim.dylib cat notes.txt",
        "RIPGREP_CONFIG_PATH=./rgrc rg x notes.txt",
        "BASH_ENV=./rc bash -c 'date -u'",
        "env PATH=/agent/shadow bash -c 'date -u'",
        "sudo date -u",
        "xargs date",
        "/agent/bin/cat notes.txt",
        "/home/agent/.local/bin/finishup status --json",
        # The same layers inside a composition, where canonical words hide them.
        "env PATH=/agent/shadow date -u; rg x notes.txt",
        "PATH=/agent/shadow date -u; rg x notes.txt",
        "date -u; PATH=/agent/shadow date -u",
        "/agent/shadow/bin/date -u; rg x notes.txt",
        "! PATH=/agent/shadow date -u; rg x notes.txt",
        "date -u; ./date -u",
        "bash -c 'date -u'; rg x notes.txt",
        # Finding 2: FinishUP's own CLI with an output path, an operand or an unknown verb.
        "finishup closure-prepare --session-id s --writer-id w --output ./deliverable.txt",
        "finishup closure-prepare --session-id=s --writer-id=w --output=./deliverable.txt",
        "finishup status --json ./deliverable.txt",
        "finishup status --input",
        "finishup check-wait",
        "finishup work-close",
        "finishup read-guidance",
        "finishup connect codex",
        "finishup closure-prepare --session-id s --writer-id w --output ./d.txt; date -u",
        # Finding 4: Git's configured fsmonitor, hooks or filters can run during status.
        "git status --short",
        "git -C repo status --short",
        "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./rewrite"
        " git status --short",
        "git status --short; date -u",
    ],
)
def test_unproven_reads_are_not_exploration(command: str) -> None:
    assert _runner(command) != "exploration"


@pytest.mark.parametrize(
    "command",
    [
        "python finalize.py",
        "python fit_regression.py",
        "python /app/solution/finalize.py",
        "python -B /tmp/deepseek_stream_regression.py",
        "bash finalize.sh",
    ],
)
def test_generator_names_are_not_verification(command: str) -> None:
    """Finding 3: ``finalize`` and ``*_regression`` name generators as often as checks."""

    assert _runner(command) == "other"
    assert not command_is_verification(command)


@pytest.mark.parametrize(
    ("command", "runner"),
    [
        ("python tests/check.py", "test"),
        ("python test_solver.py", "test"),
        ("bash run_tests.sh", "test"),
        ("python verify.py", "test"),
        (".venv/bin/pytest -q", "test"),
        ("timeout 600 pytest -q", "test"),
    ],
)
def test_existing_verifier_shapes_are_unchanged(command: str, runner: str) -> None:
    assert _runner(command) == runner


@pytest.mark.parametrize(
    ("command", "directories"),
    [
        ("git status", ()),
        ("git status --short", ()),
        ("git status -sb", ()),
        ("git status --porcelain=v2 -uno -- src", ()),
        ("git -C repo status --short", ("repo",)),
        ("git -C a -C b status", ("a", "b")),
        ("/usr/bin/git status", ()),
        ("LC_ALL=C git status --short", ()),
    ],
)
def test_closed_git_status_shape(command: str, directories: tuple[str, ...]) -> None:
    assert git_status_read_operands(command) == directories


@pytest.mark.parametrize(
    "command",
    [
        "git status -v",
        "git status --verbose",
        "git -c core.fsmonitor=./rewrite status",
        "git --config-env=core.fsmonitor=X status",
        "git --no-pager status",
        "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=x git status",
        "GIT_DIR=/elsewhere git status",
        "/agent/bin/git status",
        "./git status",
        "git status; date -u",
        "git status > status.txt",
        "git status $(touch x)",
        "git diff",
        "git stash status",
    ],
)
def test_other_git_shapes_are_not_the_closed_status_read(command: str) -> None:
    assert git_status_read_operands(command) is None
