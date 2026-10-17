"""Rounds 3 and 4 counterexamples, judged by what the command did to the workspace (PR #1080).

Each counterexample is executed for real in a synthetic workspace between the hook's two
fingerprint snapshots (``adapters.workspace_fingerprint``), and the resulting closed token is fed
through the production closing-review predicate. A read-looking command that writes is material;
a trick spelling that writes nothing is not, because the workspace really is unchanged. Command
text is never consulted for materiality any more; the runner class kept for failure accounting is
asserted only where a counterexample used to depend on it.
"""

from __future__ import annotations

import importlib
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from builders.observed_runs import ObservedLedger
from finishup.adapters.workspace_fingerprint import WorkspaceFingerprintStore
from finishup.domain.events import ResultOutcome
from finishup.kernel.closing_review_delta import closing_review_delta
from finishup.kernel.later_material import workspace_effects
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import EDITED_AFTER_LAST_VERIFICATION_GAP, task_fact_signals
from unit.kernel.test_n6_closing_review_delta import _prefix  # pyright: ignore[reportPrivateUsage]

_KEY = b"r" * 32


def _material(command: str, effect: str | None, *, write_scope: str | None = None) -> bool:
    ledger = ObservedLedger(records=list(_prefix()))
    start = len(ledger.records)
    ledger.run(
        command,
        ResultOutcome.SUCCESS,
        exit_status=0,
        write_scope=write_scope,
        workspace_effect=effect,
    )
    state = replay(ledger.prefix)
    effects = workspace_effects(ledger.prefix, state)
    rows = ledger.records[start:]
    material = [closing_review_delta(row, state, effects=effects) for row in rows]
    assert len(set(material)) == 1, material
    return material[0]


def _effect(tmp_path: Path, root: Path, call: Callable[[], object]) -> str:
    """The token the hook records for *call*: snapshot, run, snapshot again."""

    store = WorkspaceFingerprintStore(tmp_path / "fingerprint-state", _KEY)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 30) is None
    call()
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 30, call_complete=True
    )
    return reading.effect


def _sh(root: Path, command: str) -> Callable[[], object]:
    def run() -> object:
        return subprocess.run(["/bin/sh", "-c", command], cwd=root, check=True, capture_output=True)

    return run


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "deliverable.txt").write_text("reviewed")
    (root / "input").write_text("original input\n")
    (root / "replacement").write_text("unverified replacement\n")
    return root


def _isolated_git(monkeypatch: pytest.MonkeyPatch) -> str:
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
    return git


# --- the audited false-stale shapes, executed: nothing changes, nothing re-arms -----------------


@pytest.mark.parametrize(
    "command",
    [
        "date -u",
        "date -u +%Y-%m-%dT%H:%M:%SZ",
        "sed -n '1,10p' deliverable.txt",
        "cat deliverable.txt | head -1",
        "date -u && sed -n '1p' deliverable.txt",
    ],
)
def test_executed_audited_reads_leave_the_workspace_unchanged(tmp_path: Path, command: str) -> None:
    root = _workspace(tmp_path)
    effect = _effect(tmp_path, root, _sh(root, command))
    assert effect == "unchanged"
    assert not _material(command, effect)


def test_executed_rg_and_git_status_in_a_clean_repository_are_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _isolated_git(monkeypatch)
    root = _workspace(tmp_path)
    subprocess.run([git, "init", "-q"], cwd=root, check=True)
    subprocess.run([git, "add", "deliverable.txt"], cwd=root, check=True)
    # ``git status`` refreshes the index inside ``.git``: VCS metadata is not the workspace.
    assert _effect(tmp_path, root, _sh(root, "git status --short")) == "unchanged"
    assert not _material("git status --short", "unchanged")
    if shutil.which("rg") is not None:
        assert _effect(tmp_path, root, _sh(root, "rg -n reviewed . || true")) == "unchanged"


def test_a_trick_spelling_that_writes_nothing_is_not_material(tmp_path: Path) -> None:
    """Round 3/4 bypass spellings whose program writes nothing leave the workspace unchanged."""

    root = _workspace(tmp_path)
    shadow = tmp_path / "shadow"
    (shadow / "bin").mkdir(parents=True)
    for name in (shadow / "date", shadow / "bin" / "date"):
        name.write_text("#!/bin/sh\nprintf harmless\n")
        name.chmod(0o700)
    for command in (
        f"env PATH={shlex.quote(str(shadow))} date -u",
        f"{shlex.quote(str(shadow / 'bin' / 'date'))} -u",
        "date -u; date -u",
    ):
        effect = _effect(tmp_path, root, _sh(root, command))
        assert effect == "unchanged", command
        assert not _material(command, effect)


# --- round 3 executed counterexamples --------------------------------------------------------


def test_r3_shadow_date_mutations_are_material(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    victim = root / "deliverable.txt"
    shadow = tmp_path / "shadow"
    (shadow / "bin").mkdir(parents=True)
    body = "#!/bin/sh\nprintf path-mutated > " + shlex.quote(str(victim)) + "\n"
    for name in (shadow / "date", shadow / "bin" / "date"):
        name.write_text(body)
        name.chmod(0o700)
    for command in (
        f"env PATH={shlex.quote(str(shadow))} date -u",
        f"{shlex.quote(str(shadow / 'bin' / 'date'))} -u",
    ):
        victim.write_text("reviewed")
        effect = _effect(tmp_path, root, _sh(root, command))
        assert victim.read_text() == "path-mutated"
        assert effect == "changed"
        assert _material(command, effect)


def test_r3_real_cli_output_writer_is_material(
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
    root = _workspace(tmp_path)
    victim = root / "deliverable.txt"
    args = [
        "closure-prepare",
        "--session-id",
        "ses_00000000-0000-4000-8000-000000000001",
        "--writer-id",
        "wri_00000000-0000-4000-8000-000000000001",
        "--output",
        str(victim),
    ]

    def invoke() -> None:
        result = CliRunner().invoke(app.app, args)
        assert result.exit_code == 0, result.exception

    effect = _effect(tmp_path, root, invoke)
    assert victim.read_text() != "reviewed"
    assert effect == "changed"
    assert _material("finishup " + shlex.join(args), effect)


@pytest.mark.parametrize("filename", ["finalize.py", "fit_regression.py"])
def test_r3_executed_generator_is_material_and_keeps_the_verification_gap(
    tmp_path: Path, filename: str
) -> None:
    root = _workspace(tmp_path)
    script = root / filename
    script.write_text(
        "from pathlib import Path\n"
        "Path(__file__).with_name('deliverable.txt').write_text('unverified generated output')\n"
    )
    command = "python " + shlex.quote(str(script))
    effect = _effect(
        tmp_path, root, lambda: subprocess.run([sys.executable, str(script)], cwd=root, check=True)
    )
    assert (root / "deliverable.txt").read_text() == "unverified generated output"
    assert effect == "changed"
    assert _material(command, effect)
    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    ledger.edit()
    ledger.run(
        command,
        ResultOutcome.SUCCESS,
        exit_status=0,
        write_scope="workspace",
        workspace_effect=effect,
    )
    assert (
        EDITED_AFTER_LAST_VERIFICATION_GAP
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


def test_r3_fsmonitor_status_and_env_config_are_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _isolated_git(monkeypatch)
    root = _workspace(tmp_path)
    victim = root / "deliverable.txt"
    subprocess.run([git, "init", "-q"], cwd=root, check=True)
    subprocess.run([git, "add", "deliverable.txt"], cwd=root, check=True)
    monitor = tmp_path / "monitor.sh"
    monitor.write_text("#!/bin/sh\nprintf fsmonitor-mutated > " + shlex.quote(str(victim)) + "\n")
    monitor.chmod(0o700)
    subprocess.run([git, "config", "core.fsmonitor", str(monitor)], cwd=root, check=True)
    subprocess.run([git, "config", "core.fsmonitorHookVersion", "2"], cwd=root, check=True)
    effect = _effect(tmp_path, root, _sh(root, "git status --short"))
    assert victim.read_text() == "fsmonitor-mutated"
    assert effect == "changed"
    assert _material("git status --short", effect)

    subprocess.run([git, "config", "--unset", "core.fsmonitor"], cwd=root, check=True)
    victim.write_text("reviewed")
    command = (
        "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor "
        f"GIT_CONFIG_VALUE_0={shlex.quote(str(monitor))} git status --short"
    )
    effect = _effect(tmp_path, root, _sh(root, command))
    assert victim.read_text() == "fsmonitor-mutated"
    assert effect == "changed"
    assert _material(command, effect)


# --- round 4 executed counterexamples --------------------------------------------------------


def test_r4_case_sensitive_lfs_filter_collision_is_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _isolated_git(monkeypatch)
    root = _workspace(tmp_path)
    tracked = root / "tracked"
    tracked.write_text("reviewed")
    subprocess.run([git, "init", "-q"], cwd=root, check=True)
    subprocess.run([git, "add", "tracked"], cwd=root, check=True)
    mutate = f"printf filter-mutated > {shlex.quote(str(tracked))}; cat"
    subprocess.run([git, "config", "filter.lfs.clean", mutate], cwd=root, check=True)
    subprocess.run([git, "config", "filter.LFS.clean", "git-lfs clean -- %f"], cwd=root, check=True)
    (root / ".gitattributes").write_text("tracked filter=lfs\n")
    tracked.write_text("Reviewed")  # same size, different bytes: Git must run the clean filter
    effect = _effect(tmp_path, root, _sh(root, "git status --short"))
    assert tracked.read_text() == "filter-mutated"
    assert effect == "changed"
    assert _material("git status --short", effect)


def test_r4_git_dash_c_quoted_tilde_and_parameter_paths_are_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    git = _isolated_git(monkeypatch)
    root = _workspace(tmp_path)
    for relative, marker in (("~/safe", "tilde-mutated"), ("evil", "parameter-mutated")):
        repository = root / relative
        repository.mkdir(parents=True)
        victim = repository / "tracked.txt"
        victim.write_text("reviewed")
        subprocess.run([git, "init", "-q"], cwd=repository, check=True)
        subprocess.run([git, "add", "tracked.txt"], cwd=repository, check=True)
        monitor = tmp_path / f"{marker}.sh"
        monitor.write_text(f"#!/bin/sh\nprintf {marker} > " + shlex.quote(str(victim)) + "\n")
        monitor.chmod(0o700)
        subprocess.run([git, "config", "core.fsmonitor", str(monitor)], cwd=repository, check=True)
    for command, victim in (
        ("git -C '~/safe' status --short", root / "~" / "safe" / "tracked.txt"),
        ('git -C "$PWD/evil" status --short', root / "evil" / "tracked.txt"),
    ):
        effect = _effect(tmp_path, root, _sh(root, command))
        assert victim.read_text().endswith("-mutated"), command
        assert effect == "changed", command
        assert _material(command, effect)


def test_r4_fingerprinting_runs_no_program_and_writes_no_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hook's own half executes nothing: no PATH ``git``, no configured trace target."""

    root = _workspace(tmp_path)
    marker = tmp_path / "inspector-ran"
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "git").write_text("#!/bin/sh\nprintf ran > " + shlex.quote(str(marker)) + "\n")
    (fake / "git").chmod(0o700)
    trace = tmp_path / "trace.json"
    config = tmp_path / "gitconfig"
    config.write_text(f"[trace2]\n\teventTarget = {trace}\n")
    monkeypatch.setenv("PATH", f"{fake}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    (root / ".git").mkdir()
    assert _effect(tmp_path, root, lambda: None) == "unchanged"
    assert not marker.exists()
    assert not trace.exists()


@pytest.mark.skipif(not Path("/bin/zsh").exists(), reason="zsh unavailable")
def test_r4_zsh_glob_qualifier_executing_code_is_material(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    command = "sed -n '1p' *(e:'/bin/cp replacement input':)"
    effect = _effect(
        tmp_path,
        root,
        lambda: subprocess.run(
            ["/bin/zsh", "-f", "-c", command], cwd=root, check=True, capture_output=True
        ),
    )
    assert (root / "input").read_text() == "unverified replacement\n"
    assert effect == "changed"
    assert _material(command, effect)


@pytest.mark.skipif(os.name != "posix", reason="PTY/nohup boundary is POSIX")
def test_r4_nohup_writing_nohup_out_is_material(tmp_path: Path) -> None:
    import pty

    program = shutil.which("nohup")
    if program is None:
        pytest.skip("nohup unavailable")
    root = _workspace(tmp_path)

    def run() -> None:
        master, slave = pty.openpty()
        try:
            subprocess.run(
                [program, "/bin/date", "-u"],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=slave,
                stderr=slave,
                check=True,
                timeout=10,
            )
        finally:
            os.close(slave)
            os.close(master)

    effect = _effect(tmp_path, root, run)
    assert (root / "nohup.out").is_file()
    assert effect == "changed"
    assert _material("nohup /bin/date -u", effect)


@pytest.mark.parametrize(
    "command",
    ["date -u > deliverable.txt", "sed -n '1p; w copy' input", "touch new-file"],
)
def test_harmless_looking_writes_are_material(tmp_path: Path, command: str) -> None:
    root = _workspace(tmp_path)
    effect = _effect(tmp_path, root, _sh(root, command))
    assert effect == "changed"
    assert _material(command, effect)


@pytest.mark.parametrize("effect", [None, "unavailable"])
def test_an_unestablished_fingerprint_is_material_for_any_command(effect: str | None) -> None:
    for command in ("date -u", "rg x file", "git status --short", "finishup status --json"):
        assert _material(command, effect)
