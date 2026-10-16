"""Host-boundary proofs behind read-only closure traffic (PR #1080 round 4).

``git status`` is recorded as exploration only after the hook reads the repository's effective
configuration and finds nothing Git would run for it. FinishUP's own CLI is exploration only for
verbs and options that write no file. Real repositories and the real hook handlers are used;
Git's global and system configuration are isolated from this machine's.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest
import typer

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli.app import app
from finishup.cli.observe_hooks import handle_claude_observe, handle_cursor_observe, handle_observe
from finishup.cli.runtime_facts import git_status_execution_free
from finishup.domain.observation import ObservationSource
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.observation_selection import (
    _FINISHUP_READ_VERBS,  # pyright: ignore[reportPrivateUsage]
    command_runner_class,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from fixture_loader import load_fixture_json

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

_STATUS = "git status --short"


@pytest.fixture(autouse=True)
def isolated_git(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neither this machine's global nor its system Git configuration reaches a probe."""

    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in tuple(os.environ):
        if name.startswith(("GIT_TRACE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY", "GIT_CONFIG_VALUE")):
            monkeypatch.delenv(name)
    monkeypatch.delenv("GIT_CONFIG_PARAMETERS", raising=False)
    monkeypatch.delenv("GIT_DIR", raising=False)
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    yield


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments), cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def _repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir(mode=0o700)
    _git(repo, "init", "-q")
    (repo / "tracked.txt").write_text("reviewed")
    _git(repo, "add", "tracked.txt")
    return repo


def _payload(repo: Path, command: str = _STATUS) -> dict[str, JsonValue]:
    return {"cwd": str(repo), "tool_name": "Bash", "tool_input": {"command": command}}


def test_an_ordinary_repository_proves_status_runs_only_git(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    assert git_status_execution_free(_payload(repo))
    assert git_status_execution_free(_payload(tmp_path, "git -C repo status -sb"))
    assert git_status_execution_free(_payload(repo, "/usr/bin/git status --porcelain=v2"))
    _git(repo, "config", "core.fsmonitor", "false")
    assert git_status_execution_free(_payload(repo))


def test_the_review_fsmonitor_counterexample_is_not_proven(tmp_path: Path) -> None:
    """Round-3 finding 4: ``git status`` itself ran a hook that rewrote a tracked file."""

    repo = _repo(tmp_path)
    monitor = tmp_path / "monitor.sh"
    monitor.write_text(f"#!/bin/sh\nprintf fsmonitor-mutated > {repo / 'tracked.txt'}\n")
    monitor.chmod(0o700)
    _git(repo, "config", "core.fsmonitor", str(monitor))
    _git(repo, "config", "core.fsmonitorHookVersion", "2")
    assert not git_status_execution_free(_payload(repo))
    assert command_runner_class(_payload(repo)) == "vcs"
    _git(repo, "status", "--short")
    # The reproduction holds on this host: status ran the configured program.
    assert (repo / "tracked.txt").read_text() == "fsmonitor-mutated"


_CONFIGURED_EXECUTION: Mapping[str, tuple[str, str]] = {
    "builtin-fsmonitor": ("core.fsmonitor", "true"),
    "clean-filter": ("filter.rewrite.clean", "./rewrite"),
    "process-filter": ("filter.rewrite.process", "./rewrite"),
    "pager": ("pager.status", "true"),
    "trace2": ("trace2.eventTarget", "trace.json"),
}


@pytest.mark.parametrize("case", [*_CONFIGURED_EXECUTION, "submodules", "post-index-change"])
def test_configured_execution_is_not_proven(tmp_path: Path, case: str) -> None:
    repo = _repo(tmp_path)
    if case == "submodules":
        (repo / ".gitmodules").write_text("")
    elif case == "post-index-change":
        (repo / ".git" / "hooks" / "post-index-change").write_text("#!/bin/sh\n")
    else:
        key, value = _CONFIGURED_EXECUTION[case]
        _git(repo, "config", key, value)
    assert not git_status_execution_free(_payload(repo))


def test_hooks_path_is_read_where_hooks_run(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".husky").mkdir()
    _git(repo, "config", "core.hooksPath", ".husky")
    (repo / ".husky" / "pre-commit").write_text("#!/bin/sh\n")
    assert git_status_execution_free(_payload(repo))
    (repo / ".husky" / "post-index-change").write_text("#!/bin/sh\n")
    assert not git_status_execution_free(_payload(repo))


def test_git_lfs_install_values_alone_do_not_block_the_proof(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _git(repo, "config", "filter.lfs.clean", "git-lfs clean -- %f")
    _git(repo, "config", "filter.lfs.process", "git-lfs filter-process")
    assert git_status_execution_free(_payload(repo))
    _git(repo, "config", "filter.lfs.process", "./rewrite")
    assert not git_status_execution_free(_payload(repo))


def test_environment_configuration_and_trace_targets_are_read(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    environ = dict(os.environ)
    injected = {
        **environ,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "./rewrite",
    }
    assert git_status_execution_free(_payload(repo), environ=environ)
    assert not git_status_execution_free(_payload(repo), environ=injected)
    traced = {**environ, "GIT_TRACE2_EVENT": str(repo / "trace.json")}
    assert not git_status_execution_free(_payload(repo), environ=traced)


@pytest.mark.parametrize(
    "command",
    [
        "git status -v",
        "git -c core.fsmonitor=./rewrite status",
        "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=x git status",
        "git status; date -u",
        "git -C missing status",
        "rg x tracked.txt",
    ],
)
def test_other_shapes_or_directories_are_not_proven(tmp_path: Path, command: str) -> None:
    repo = _repo(tmp_path)
    assert not git_status_execution_free(_payload(repo, command))


def test_without_a_named_working_directory_nothing_is_proven(tmp_path: Path) -> None:
    _repo(tmp_path)
    assert not git_status_execution_free({"tool_name": "Bash", "tool_input": {"command": _STATUS}})
    assert not git_status_execution_free({"cwd": "relative", "tool_input": {"command": _STATUS}})


# --- the real hook handlers -------------------------------------------------------------------

_CODEX_POST: Mapping[str, Any] = {
    "hook_event_name": "PostToolUse",
    "session_id": "019a0000-0000-7000-8000-000000001080",
    "tool_name": "Bash",
    "tool_use_id": "call-status-1080",
    "tool_input": {"command": _STATUS},
    "tool_response": "Chunk ID: 1\nWall time: 0.0100 seconds\nProcess exited with code 0\n"
    "Original token count: 1\nOutput:\n",
}


def _fixture_payload(path: str, variant: str, repo: Path) -> dict[str, Any]:
    case = cast(dict[str, Any], load_fixture_json(path))
    raw = json.dumps(case["input"]["hook"][variant]["payload"])
    raw = raw.replace('"/workspace/project"', json.dumps(str(repo.resolve())))
    raw = raw.replace('"PLACEHOLDER_COMMAND"', json.dumps(_STATUS))
    return cast(dict[str, Any], json.loads(raw))


def _host_runner_classes(tmp_path: Path, repo: Path, host: str) -> set[object]:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(repo.resolve()))
    store.grant_consent(workspace)
    if host == "codex":
        post = {**_CODEX_POST, "cwd": str(repo.resolve())}
        pre_event, post_event = "PreToolUse", "PostToolUse"
    elif host == "claude":
        post = _fixture_payload(
            "observations/claude-code-bash-outcomes.case.json", "post_tool_use_bash", repo
        )
        pre_event, post_event = "PreToolUse", "PostToolUse"
    else:
        post = _fixture_payload(
            "observations/cursor-shell-outcomes.case.json",
            "post_tool_use_shell_with_exit_code",
            repo,
        )
        pre_event, post_event = "preToolUse", "postToolUse"
    pre = {
        key: value
        for key, value in post.items()
        if key not in {"tool_response", "tool_output", "duration"}
    }
    pre["hook_event_name"] = pre_event
    for event, body in ((pre_event, pre), (post_event, post)):
        common: dict[str, Any] = {
            "event_name": event,
            "stdin_bytes": canonical_encode(cast(JsonValue, body)),
            "stdout": io.BytesIO(),
            "workspace": str(repo),
            "_state": state,
            "skip_service": True,
        }
        if host == "codex":
            code = handle_observe(**common, source=ObservationSource.CODEX_HOOK)
        elif host == "claude":
            code = handle_claude_observe(
                **common, observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
            )
        else:
            code = handle_cursor_observe(
                **common, observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
            )
        assert code == 0
    call = post["tool_use_id"]
    rows = [
        envelope
        for envelope in LocalObservationStore(_state=state).list_envelopes(workspace)
        if envelope.structural_payload.get("tool_call_id") == call
    ]
    assert rows
    return {row.structural_payload.get("runner_class") for row in rows}


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_hooks_record_proven_git_status_as_exploration(tmp_path: Path, host: str) -> None:
    repo = _repo(tmp_path)
    assert _host_runner_classes(tmp_path, repo, host) == {"exploration"}


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_hooks_keep_unproven_git_status_material(tmp_path: Path, host: str) -> None:
    repo = _repo(tmp_path)
    _git(repo, "config", "core.fsmonitor", str(tmp_path / "monitor.sh"))
    assert _host_runner_classes(tmp_path, repo, host) == {"vcs"}


# --- FinishUP's own CLI -------------------------------------------------------------------------


def test_exempt_cli_options_are_real_and_none_writes_a_file() -> None:
    """Every exempt verb/option exists on the real CLI; ``--output`` is never exempt.

    An option the table does not name stays material, so a new output option on any verb is
    conservative until it is reviewed here.
    """

    group = cast(Any, typer.main.get_command(app))

    def options_of(verb: str) -> dict[str, bool]:
        return {
            name: not bool(getattr(parameter, "is_flag", False))
            for parameter in group.commands[verb].params
            for name in getattr(parameter, "opts", ())
        }

    for verb, options in _FINISHUP_READ_VERBS.items():
        real = {**options_of(verb), "--help": False}
        for name, takes_value in options.items():
            assert name in real, (verb, name)
            assert real[name] is takes_value, (verb, name)
        assert "--output" not in options
    assert "--output" in options_of("closure-prepare")
