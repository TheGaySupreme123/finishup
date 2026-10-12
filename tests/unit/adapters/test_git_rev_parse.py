"""Repository identity and capture on a Git without ``rev-parse --path-format`` (#1040).

Git before 2.31 does not reject ``--path-format=absolute``: ``rev-parse`` echoes an argument it does
not recognise, so the answer gains a line and the paths after it are relative. The shim below
reproduces that exactly with the real Git by renaming the option to one no Git knows.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.adapters.git_rev_parse import absolute_rev_parse_path
from yoetz.adapters.git_subject_state import (
    GitSubjectStateAdapter,
    discover_workspace_root,
    open_local_workspace,
)
from yoetz.adapters.repository_identity import resolve_repository_privacy_context
from yoetz.ports.control import WorkspaceLocator
from yoetz.ports.subject_state import (
    SubjectStateCaptureCommand,
    SubjectStateFormat,
    SubjectStateStatus,
)

_REAL_WHICH = shutil.which


class _MacKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"installation-test-key", domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Yoetz Test",
            "-c",
            "user.email=yoetz@example.invalid",
            *arguments,
        ),
        cwd=repository,
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.defpath},
    )


def _repository(tmp_path: Path) -> Path:
    repository = (tmp_path / "repo").resolve()
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    return repository


@pytest.fixture
def pre_2_31_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    real = _REAL_WHICH("git", path=os.defpath)
    assert real is not None
    shim = tmp_path / "shim" / "git"
    shim.parent.mkdir()
    shim.write_text(
        "#!/bin/sh\n"
        'for argument; do shift; case "$argument" in\n'
        '  --path-format=*) argument="--yoetz-unknown-option${argument#--path-format}" ;;\n'
        'esac; set -- "$@" "$argument"; done\n'
        f'exec "{real}" "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(stat.S_IRWXU)

    def which(name: str, *args: object, **kwargs: object) -> str | None:
        if name == "git":
            return os.fspath(shim)
        return _REAL_WHICH(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(shutil, "which", which)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return shim


def test_shim_reproduces_the_pre_2_31_echo(pre_2_31_git: Path, tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    answer = subprocess.run(
        (
            os.fspath(pre_2_31_git),
            "-C",
            os.fspath(repository),
            "rev-parse",
            "--is-inside-work-tree",
            "--path-format=absolute",
            "--git-common-dir",
        ),
        check=True,
        capture_output=True,
    ).stdout
    assert answer.splitlines() == [b"true", b"--yoetz-unknown-option=absolute", b".git"]


def test_absolute_rev_parse_path_matches_path_format_absolute(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    (root / "real").mkdir()
    (root / "alias").symlink_to(root / "real", target_is_directory=True)

    assert absolute_rev_parse_path(b".git", root / "real") == root / "real" / ".git"
    assert absolute_rev_parse_path(b"../real", root / "real") == root / "real"
    assert absolute_rev_parse_path(os.fsencode(root / "alias"), root) == root / "real"
    for invalid in (b"", b"a\x00b", b"a\nb"):
        with pytest.raises(ValueError):
            absolute_rev_parse_path(invalid, root)
    with pytest.raises(ValueError):
        absolute_rev_parse_path(b".git", Path("relative"))


@pytest.mark.anyio
async def test_repository_identity_resolves_on_pre_2_31_git(
    pre_2_31_git: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    key = _MacKey()
    old = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(repository)), key)
    nested = repository / "nested"
    nested.mkdir()
    from_nested = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(nested)), key)
    assert old.identity_kind == from_nested.identity_kind == "git_common_root"

    monkeypatch.setattr(shutil, "which", _REAL_WHICH)
    current = await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(repository)), key)
    # The commitment input must not depend on the Git version, or a grant would stop matching.
    assert (old.commitment, old.identity_kind) == (current.commitment, current.identity_kind)


def test_workspace_root_and_subject_state_capture_on_pre_2_31_git(
    pre_2_31_git: Path, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    nested = repository / "nested"
    nested.mkdir()

    assert discover_workspace_root(nested) == repository
    result = GitSubjectStateAdapter().capture(
        SubjectStateCaptureCommand(
            open_local_workspace(repository), SubjectStateFormat.GIT_STRUCTURAL_V1
        )
    )
    assert result.status is SubjectStateStatus.CAPTURED


def test_change_capture_on_pre_2_31_git(pre_2_31_git: Path, tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)

    assert capture.tracked_files == 1
    assert b"+changed" in capture.text
