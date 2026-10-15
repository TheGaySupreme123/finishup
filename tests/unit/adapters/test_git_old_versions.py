"""FinishUP on the oldest Git it supports (2.25), and below it (#1040 and its follow-up).

Git 2.25 (Ubuntu 20.04, ``condaforge/miniforge3:24.9.2-0``) is the documented minimum. The shim
below reproduces with the real Git every way such a Git differs for the queries FinishUP makes:

- ``rev-parse`` echoes an option it does not know (``--path-format``, Git 2.31) as an extra line;
- ``rev-parse --verify`` drops ``--end-of-options`` (2.30) unread;
- ``diff --no-relative`` (2.28) and ``config --show-scope`` (2.26) exit 129;
- ``GIT_CONFIG_GLOBAL`` (2.32) is ignored, so ``$HOME/.gitconfig`` is read.

A source build of the real Git 2.25.1 behaves exactly so; the PR CI image smoke runs the real one.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.adapters.git_change_capture as capture_module
import finishup.adapters.git_subject_state as subject_state_module
from finishup.adapters import repository_identity
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.git_rev_parse import absolute_rev_parse_path
from finishup.adapters.git_subject_state import (
    GitSubjectStateAdapter,
    discover_workspace_root,
    open_local_workspace,
)
from finishup.adapters.git_version import (
    GIT_VERSION_UNSUPPORTED,
    MINIMUM_GIT_VERSION,
    git_version,
    git_version_supported,
    parse_git_version,
)
from finishup.adapters.repository_identity import (
    RepositoryIdentityError,
    resolve_repository_privacy_context,
)
from finishup.cli.exits import remediation_message
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_REASONS,
    check_time_change_unavailable_reason_gap,
)
from finishup.kernel.gap_effect import PROOF_TOLERATED_GAPS
from finishup.ports.change_capture import ChangeCaptureUnavailable
from finishup.ports.control import WorkspaceLocator
from finishup.ports.keys import REPOSITORY_PRIVACY_MAC_DOMAIN
from finishup.ports.subject_state import (
    SubjectStateCaptureCommand,
    SubjectStateFormat,
    SubjectStateStatus,
)

_REAL_WHICH = shutil.which
_SHIM = """#!/bin/sh
# Git {version} as FinishUP meets it, reproduced with the real Git.
unset GIT_CONFIG_GLOBAL
for argument; do shift; case "$argument" in
  --version) echo "git version {version}"; exit 0 ;;
  --path-format=*) argument="--yoetz-unknown-option${{argument#--path-format}}" ;;
  --end-of-options) continue ;;
  --no-relative|--show-scope) echo "error: unknown option" >&2; exit 129 ;;
esac; set -- "$@" "$argument"; done
exec "{real}" "$@"
"""


class _MacKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"installation-test-key", domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


def _real_git() -> str:
    real = _REAL_WHICH("git", path=os.defpath)
    assert real is not None
    return real


def _git(repository: Path, *arguments: str) -> bytes:
    return subprocess.run(
        (
            _real_git(),
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=yoetz@example.invalid",
            *arguments,
        ),
        cwd=repository,
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.devnull,
            "PATH": os.defpath,
        },
    ).stdout


def _repository(tmp_path: Path, name: str = "repo") -> Path:
    repository = (tmp_path / name).resolve()
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    return repository


type _InstallShim = Callable[[str], Path]


@pytest.fixture
def install_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _InstallShim:
    """Make every adapter's ``shutil.which("git")`` return a shim reporting ``version``."""

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)

    def install(version: str) -> Path:
        shim = tmp_path / f"shim-{version}" / "git"
        shim.parent.mkdir()
        shim.write_text(_SHIM.format(version=version, real=_real_git()), encoding="utf-8")
        shim.chmod(stat.S_IRWXU)

        def which(name: str, *args: object, **kwargs: object) -> str | None:
            if name == "git":
                return os.fspath(shim)
            return _REAL_WHICH(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(shutil, "which", which)
        return shim

    return install


@pytest.fixture
def git_2_25(install_git: _InstallShim) -> Path:
    return install_git("2.25.1")


def _run(shim: Path, cwd: Path, *arguments: str, **env: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        (os.fspath(shim), *arguments),
        cwd=cwd,
        capture_output=True,
        check=False,
        env={"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", **env},
    )


# --- the shim is Git 2.25 --------------------------------------------------------------------


def test_shim_reproduces_git_2_25(git_2_25: Path, tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    echoed = _run(
        git_2_25,
        repository,
        "rev-parse",
        "--is-inside-work-tree",
        "--path-format=absolute",
        "--git-common-dir",
    )
    assert echoed.stdout.splitlines() == [b"true", b"--yoetz-unknown-option=absolute", b".git"]
    assert _run(git_2_25, repository, "diff", "--no-relative").returncode == 129
    assert _run(git_2_25, repository, "config", "--list", "--show-scope").returncode == 129
    assert parse_git_version(_run(git_2_25, repository, "--version").stdout) == (2, 25, 1)
    home = tmp_path / "home-with-config"
    home.mkdir()
    (home / ".gitconfig").write_text("[yoetz]\n\tprobe = read\n", encoding="utf-8")
    ignored = _run(
        git_2_25,
        repository,
        "config",
        "--get",
        "yoetz.probe",
        HOME=os.fspath(home),
        GIT_CONFIG_GLOBAL=os.devnull,
    )
    assert ignored.stdout == b"read\n"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"git version 2.25.1\n", (2, 25, 1)),
        (b"git version 2.39.3 (Apple Git-146)\n", (2, 39, 3)),
        (b"git version 2.45.1.windows.1\n", (2, 45, 1)),
        (b"git version 2.30\n", (2, 30, 0)),
        (b"hub version 2.14.2\n", None),
        (b"", None),
    ],
)
def test_git_version_parsing(raw: bytes, expected: tuple[int, int, int] | None) -> None:
    assert parse_git_version(raw) == expected


def test_only_a_known_version_below_the_minimum_is_unsupported() -> None:
    assert MINIMUM_GIT_VERSION == (2, 25, 0)
    assert git_version_supported((2, 25, 0))
    assert git_version_supported((3, 0, 0))
    assert not git_version_supported((2, 24, 4))
    # An unreadable version is not refused; every later Git call still fails closed on output it
    # does not expect.
    assert git_version_supported(None)
    assert git_version(os.devnull + "/missing-git") is None


def test_no_adapter_passes_an_argument_newer_than_the_minimum() -> None:
    """A ratchet: none of these options or settings may come back into an argv."""

    forbidden = ("--path-format", "--end-of-options", "--no-relative", "--show-scope")
    for module in (capture_module, subject_state_module, repository_identity):
        source = Path(module.__file__ or "").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                assert not value.startswith(forbidden), (module.__name__, value)
                assert value != "core.fsmonitor=false", (module.__name__, value)
    prefix = subject_state_module._GIT_SAFE_PREFIX  # pyright: ignore[reportPrivateUsage]
    assert "core.fsmonitor=" in prefix


# --- rev-parse paths -------------------------------------------------------------------------


def test_absolute_rev_parse_path_matches_path_format_absolute(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    (root / "real").mkdir()
    (root / "alias").symlink_to(root / "real", target_is_directory=True)

    assert absolute_rev_parse_path(b".git", root / "real") == root / "real" / ".git"
    assert absolute_rev_parse_path(b"../real", root / "real") == root / "real"
    assert absolute_rev_parse_path(b".", root / "real") == root / "real"
    assert absolute_rev_parse_path(os.fsencode(root / "alias"), root) == root / "real"
    for invalid in (b"", b"a\x00b", b"a\nb", b"a\rb", b"--path-format=absolute"):
        with pytest.raises(ValueError):
            absolute_rev_parse_path(invalid, root)
    with pytest.raises(ValueError):
        absolute_rev_parse_path(b".git", Path("relative"))


def _layouts(tmp_path: Path) -> dict[str, tuple[Path, str]]:
    repository = _repository(tmp_path)
    nested = repository / "nested" / "deeper"
    nested.mkdir(parents=True)
    linked = tmp_path / "linked"
    _git(repository, "branch", "other")
    _git(repository, "worktree", "add", "--quiet", os.fspath(linked), "other")
    linked_nested = linked / "nested"
    linked_nested.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(nested, target_is_directory=True)
    bare = (tmp_path / "bare.git").resolve()
    _git(tmp_path, "init", "--quiet", "--bare", os.fspath(bare))
    plain = tmp_path / "plain"
    plain.mkdir()
    return {
        "root": (repository, "git_common_root"),
        "subdirectory": (nested, "git_common_root"),
        "linked_worktree": (linked, "git_common_root"),
        "linked_worktree_subdirectory": (linked_nested, "git_common_root"),
        "symlinked_subdirectory": (alias, "git_common_root"),
        "bare": (bare, "git_common_root"),
        "bare_subdirectory": (bare / "refs" / "heads", "git_common_root"),
        "not_git": (plain, "directory"),
    }


def _path_format_commitment(directory: Path) -> str | None:
    """The commitment the pre-#1040 resolver derived with ``--path-format=absolute``."""

    version = parse_git_version(_git(directory, "--version"))
    if version is None or version < (2, 31, 0):
        return None
    common = _git(directory, "rev-parse", "--path-format=absolute", "--git-common-dir")
    canonical = Path(os.fsdecode(common.rstrip(b"\n"))).resolve(strict=True)
    message = b"git_common_root\x00" + os.fsencode(canonical)
    return _MacKey().mac(REPOSITORY_PRIVACY_MAC_DOMAIN, message)


@pytest.mark.anyio
async def test_repository_identity_is_the_same_on_every_git(
    install_git: _InstallShim, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layouts = _layouts(tmp_path)
    key = _MacKey()
    install_git("2.25.1")
    old = {
        name: await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(path)), key)
        for name, (path, _kind) in layouts.items()
    }
    monkeypatch.setattr(shutil, "which", _REAL_WHICH)
    current = {
        name: await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(path)), key)
        for name, (path, _kind) in layouts.items()
    }

    for name, (path, kind) in layouts.items():
        assert old[name].identity_kind == current[name].identity_kind == kind, name
        # The commitment must not depend on the Git version, or a grant would stop matching.
        assert old[name].commitment == current[name].commitment, name
        if kind == "git_common_root" and not name.startswith("bare"):
            assert old[name].commitment == old["root"].commitment, name
        expected = _path_format_commitment(path) if kind == "git_common_root" else None
        if expected is not None:
            assert current[name].commitment == expected, name
    # A directory inside a bare repository commits the bare repository itself.
    assert old["bare_subdirectory"].commitment == old["bare"].commitment


@pytest.mark.anyio
async def test_repository_identity_inside_the_git_directory_stays_refused(
    git_2_25: Path, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(RepositoryIdentityError) as refused:
        await resolve_repository_privacy_context(
            WorkspaceLocator(os.fspath(repository / ".git")), _MacKey()
        )
    assert refused.value.reason == "repository_identity_unavailable"


# --- subject state and change capture ---------------------------------------------------------


def test_workspace_root_and_subject_state_capture_on_git_2_25(
    git_2_25: Path, tmp_path: Path
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


@pytest.mark.parametrize("shimmed", [True, False])
def test_a_linked_worktree_is_still_refused_as_a_capture_root(
    install_git: _InstallShim, tmp_path: Path, shimmed: bool
) -> None:
    repository = _repository(tmp_path)
    linked = tmp_path / "linked"
    _git(repository, "worktree", "add", "--quiet", "--detach", os.fspath(linked))
    if shimmed:
        install_git("2.25.1")
    with pytest.raises(ValueError, match="unsafe_root"):
        discover_workspace_root(linked)
    with pytest.raises(ChangeCaptureUnavailable) as refused:
        GitChangeCaptureAdapter().read_task_base(os.fspath(linked))
    assert refused.value.reason == "unsafe_root"


def test_change_capture_on_git_2_25(git_2_25: Path, tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    # A repository asking for relative diffs does not move any path out of the root's frame.
    _git(repository, "config", "diff.relative", "true")
    (repository / "nested").mkdir()
    (repository / "nested" / "inner.txt").write_text("inner\n", encoding="utf-8")
    _git(repository, "add", "nested/inner.txt")
    _git(repository, "commit", "--quiet", "-m", "nested")
    head = _git(repository, "rev-parse", "HEAD").strip().decode("ascii")
    adapter = GitChangeCaptureAdapter()

    base = adapter.read_task_base(os.fspath(repository / "nested"))
    # ``rev-parse --verify`` found HEAD: the base is the commit, never the empty tree that would
    # make the whole repository look like the task's change.
    assert base.commit == head
    (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")
    (repository / "nested" / "inner.txt").write_text("inner changed\n", encoding="utf-8")
    (repository / "added.txt").write_text("added\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)

    assert capture.tracked_files == 2
    assert b"+changed" in capture.text
    assert b"+++ b/nested/inner.txt" in capture.text
    assert b"added.txt" in capture.text


def test_a_repository_gitconfig_never_configures_a_git_that_ignores_git_config_global(
    git_2_25: Path, tmp_path: Path
) -> None:
    """Git before 2.32 reads ``$HOME/.gitconfig`` whatever ``GIT_CONFIG_GLOBAL`` says.

    The hardened runner once set ``HOME`` to the workspace root, so a ``.gitconfig`` committed to
    the repository became Git's global configuration and its filter driver ran on ``git diff``.
    """

    repository = _repository(tmp_path)
    marker = tmp_path / "filter-ran"
    (repository / ".gitattributes").write_text("*.txt filter=planted\n", encoding="utf-8")
    (repository / ".gitconfig").write_text(
        f'[filter "planted"]\n\tclean = touch {marker}; cat\n', encoding="utf-8"
    )
    _git(repository, "add", ".gitattributes", ".gitconfig")
    _git(repository, "commit", "--quiet", "-m", "planted")
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    (repository / "tracked.txt").write_text("changed again\n", encoding="utf-8")

    result = GitSubjectStateAdapter().capture(
        SubjectStateCaptureCommand(
            open_local_workspace(repository), SubjectStateFormat.GIT_STRUCTURAL_V1
        )
    )
    assert result.status is SubjectStateStatus.CAPTURED
    assert not marker.exists()
    # Nor is the planted driver part of the effective configuration the capture vets.
    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), base)
    assert b"+changed again" in capture.text
    assert not marker.exists()


def test_a_repository_fsmonitor_hook_never_runs(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    marker = tmp_path / "fsmonitor-ran"
    hook = tmp_path / "fsmonitor-hook"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
    hook.chmod(stat.S_IRWXU)
    _git(repository, "config", "core.fsmonitor", os.fspath(hook))
    (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")

    result = GitSubjectStateAdapter().capture(
        SubjectStateCaptureCommand(
            open_local_workspace(repository), SubjectStateFormat.GIT_STRUCTURAL_V1
        )
    )

    assert result.status is SubjectStateStatus.CAPTURED
    assert not marker.exists()


def test_capture_never_hands_rev_parse_an_option_shaped_revision() -> None:
    rev = GitChangeCaptureAdapter()._rev  # pyright: ignore[reportPrivateUsage]
    for spec in ("-x", "--all", ""):
        with pytest.raises(ChangeCaptureUnavailable) as refused:
            # Refused before any workspace is touched, so none is needed.
            rev(cast(Any, None), spec, 0.0)
        assert refused.value.reason == "git_failed"


# --- below the minimum ------------------------------------------------------------------------


@pytest.mark.anyio
async def test_git_below_the_minimum_is_named_everywhere_git_is_needed(
    install_git: _InstallShim, tmp_path: Path
) -> None:
    repository = _repository(tmp_path)
    plain = tmp_path / "plain"
    plain.mkdir()
    # Names a bare repository has, around a HEAD that is not one: still a plain directory.
    lookalike = tmp_path / "lookalike"
    (lookalike / "objects").mkdir(parents=True)
    (lookalike / "refs").mkdir()
    (lookalike / "HEAD").write_text("not a ref\n", encoding="utf-8")
    bare = (tmp_path / "bare.git").resolve()
    _git(tmp_path, "init", "--quiet", "--bare", os.fspath(bare))
    install_git("2.24.4")

    # A worktree, a bare repository's root and a directory inside one are all repositories Git
    # would find: each is refused, never silently committed as a plain directory (whose
    # commitment would differ from the one a supported Git gives the same locator).
    for located in (repository, repository / ".git", bare, bare / "refs" / "heads"):
        with pytest.raises(RepositoryIdentityError) as identity:
            await resolve_repository_privacy_context(
                WorkspaceLocator(os.fspath(located)), _MacKey()
            )
        assert identity.value.reason == GIT_VERSION_UNSUPPORTED, located
    # A directory with no Git marker keeps its directory identity, as on a machine without Git.
    for unmarked in (plain, lookalike):
        directory = await resolve_repository_privacy_context(
            WorkspaceLocator(os.fspath(unmarked)), _MacKey()
        )
        assert directory.identity_kind == "directory", unmarked

    for read in (
        lambda: GitChangeCaptureAdapter().read_task_base(os.fspath(repository)),
        lambda: GitChangeCaptureAdapter().capture(os.fspath(repository), None),
    ):
        with pytest.raises(ChangeCaptureUnavailable) as capture:
            read()
        assert capture.value.reason == GIT_VERSION_UNSUPPORTED
    for open_workspace in (
        lambda: discover_workspace_root(repository),
        lambda: open_local_workspace(repository),
    ):
        with pytest.raises(ValueError, match=GIT_VERSION_UNSUPPORTED):
            open_workspace()


def _bare_with_head(
    tmp_path: Path, name: str, head: str | None, *, link: str | None = None
) -> Path:
    bare = (tmp_path / name).resolve()
    _git(tmp_path, "init", "--quiet", "--bare", os.fspath(bare))
    (bare / "HEAD").unlink()
    if link is not None:
        (bare / "HEAD").symlink_to(link)
    else:
        assert head is not None
        (bare / "HEAD").write_text(head, encoding="utf-8")
    return bare


@pytest.mark.anyio
async def test_every_head_form_git_accepts_is_refused_below_the_minimum(
    install_git: _InstallShim, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Git's ``validate_headref`` forms, not just the one ``git init`` writes (#1040 review)."""

    bares = {
        "symlinked_head_to_unborn_branch": _bare_with_head(
            tmp_path, "link.git", None, link="refs/heads/unborn"
        ),
        "uppercase_detached_head": _bare_with_head(tmp_path, "upper.git", "ABCDEF0123" * 4 + "\n"),
        "tab_after_ref": _bare_with_head(tmp_path, "tab.git", "ref:\trefs/heads/unborn\n"),
        "no_space_after_ref": _bare_with_head(tmp_path, "tight.git", "ref:refs/heads/unborn"),
    }
    key = _MacKey()
    # The premise: a supported Git finds each of them as a repository.
    for name, bare in bares.items():
        for located in (bare, bare / "refs" / "heads"):
            context = await resolve_repository_privacy_context(
                WorkspaceLocator(os.fspath(located)), key
            )
            assert context.identity_kind == "git_common_root", (name, located)
    install_git("2.24.4")
    for name, bare in bares.items():
        for located in (bare, bare / "refs" / "heads"):
            with pytest.raises(RepositoryIdentityError) as refused:
                await resolve_repository_privacy_context(WorkspaceLocator(os.fspath(located)), key)
            assert refused.value.reason == GIT_VERSION_UNSUPPORTED, (name, located)
    # Forms Git rejects stay plain directories.
    for name, head, link in (
        ("not_a_ref", "ref: heads/main\n", None),
        ("short_hex", "abcdef0123\n", None),
        ("link_outside_refs", None, "heads/main"),
    ):
        lookalike = tmp_path / name
        (lookalike / "objects").mkdir(parents=True)
        (lookalike / "refs").mkdir()
        if link is not None:
            (lookalike / "HEAD").symlink_to(link)
        else:
            assert head is not None
            (lookalike / "HEAD").write_text(head, encoding="utf-8")
        context = await resolve_repository_privacy_context(
            WorkspaceLocator(os.fspath(lookalike)), key
        )
        assert context.identity_kind == "directory", name
    directory_head = tmp_path / "directory_head"
    for child in ("objects", "refs", "HEAD"):
        (directory_head / child).mkdir(parents=True)
    context = await resolve_repository_privacy_context(
        WorkspaceLocator(os.fspath(directory_head)), key
    )
    assert context.identity_kind == "directory"


def _bare_with_commondir(tmp_path: Path, name: str, kind: str) -> Path:
    """A bare repository (valid HEAD, objects, refs) with one shape of ``commondir`` pointer."""

    bare = (tmp_path / name).resolve()
    _git(tmp_path, "init", "--quiet", "--bare", os.fspath(bare))
    pointer = bare / "commondir"
    if kind == "regular":
        pointer.write_bytes(b".\n")
    elif kind == "symlinked":
        (tmp_path / f"{name}-target").write_bytes(b".\n")
        pointer.symlink_to(tmp_path / f"{name}-target")
    elif kind == "fifo":
        os.mkfifo(pointer)
    elif kind == "nul":
        pointer.write_bytes(b".\x00ignored\n")
    elif kind == "empty":
        pointer.write_bytes(b"")
    elif kind == "dangling":
        pointer.symlink_to(tmp_path / f"{name}-missing")
    else:
        raise AssertionError(kind)
    return bare


@pytest.mark.anyio
@pytest.mark.parametrize("kind", ["regular", "symlinked", "fifo", "nul", "empty", "dangling"])
async def test_a_commondir_the_detector_cannot_decide_is_refused_below_the_minimum(
    install_git: _InstallShim, tmp_path: Path, kind: str
) -> None:
    """#1040 review round 3: a valid HEAD beside an undecidable pointer never becomes a directory.

    Git follows a linked ``commondir``, blocks on a FIFO, stops at a NUL and fails on an empty
    one; the detector reads none of those. Whatever a supported Git would make of the pointer, it
    never commits the locator as a plain directory, so below the minimum the locator is refused,
    at the bare root and inside it, and the detector never blocks.
    """

    import threading

    from finishup.adapters import repository_identity as identity_module

    bare = _bare_with_commondir(tmp_path, f"{kind}.git", kind)
    nested = bare / "refs" / "heads"
    detected: dict[str, bool] = {}

    def detect() -> None:
        marker = identity_module._has_git_marker  # pyright: ignore[reportPrivateUsage]
        detected["root"] = marker(bare)
        detected["nested"] = marker(nested)

    worker = threading.Thread(target=detect, daemon=True)
    worker.start()
    worker.join(timeout=5.0)
    assert not worker.is_alive(), "the commondir probe blocked"
    assert detected == {"root": True, "nested": True}
    install_git("2.24.4")
    for located in (bare, nested):
        with pytest.raises(RepositoryIdentityError) as refused:
            await resolve_repository_privacy_context(
                WorkspaceLocator(os.fspath(located)), _MacKey()
            )
        assert refused.value.reason == GIT_VERSION_UNSUPPORTED, (kind, located)


def test_an_invalid_head_beside_any_commondir_is_still_not_a_git_directory(tmp_path: Path) -> None:
    """Git checks HEAD first: without a valid one, no pointer makes a Git directory."""

    from finishup.adapters import repository_identity as identity_module

    for kind in ("regular", "symlinked", "nul", "empty"):
        lookalike = tmp_path / f"lookalike-{kind}"
        (lookalike / "objects").mkdir(parents=True)
        (lookalike / "refs").mkdir()
        (lookalike / "HEAD").write_text("not a ref\n", encoding="utf-8")
        pointer = lookalike / "commondir"
        if kind == "symlinked":
            (tmp_path / f"target-{kind}").write_bytes(b".\n")
            pointer.symlink_to(tmp_path / f"target-{kind}")
        else:
            pointer.write_bytes({"regular": b".\n", "nul": b".\x00x\n", "empty": b""}[kind])
        is_git_directory = identity_module._is_git_directory  # pyright: ignore[reportPrivateUsage]
        assert is_git_directory(lookalike) is False, kind


def test_a_special_file_head_never_blocks_the_detector(tmp_path: Path) -> None:
    """A FIFO named HEAD is never opened for a blocking read (#1040 review)."""

    import threading

    from finishup.adapters import repository_identity as identity_module

    fifo_repository = tmp_path / "fifo"
    (fifo_repository / "objects").mkdir(parents=True)
    (fifo_repository / "refs").mkdir()
    os.mkfifo(fifo_repository / "HEAD")
    lone_fifo = tmp_path / "lone"
    lone_fifo.mkdir()
    os.mkfifo(lone_fifo / "HEAD")
    results: dict[str, bool] = {}

    def detect() -> None:
        marker = identity_module._has_git_marker  # pyright: ignore[reportPrivateUsage]
        results["fifo"] = marker(fifo_repository)
        results["lone"] = marker(lone_fifo)

    worker = threading.Thread(target=detect, daemon=True)
    worker.start()
    worker.join(timeout=5.0)
    assert not worker.is_alive(), "the HEAD probe blocked on a FIFO"
    # Beside objects and refs it cannot be resolved by Git either: refused, never a plain
    # directory. Alone it is not a Git directory at all.
    assert results == {"fifo": True, "lone": False}


def test_git_below_the_minimum_reads_as_one_fixed_sentence_and_remedy() -> None:
    sentence = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS[GIT_VERSION_UNSUPPORTED]
    assert "2.25" in sentence
    assert check_time_change_unavailable_reason_gap(GIT_VERSION_UNSUPPORTED) in (
        PROOF_TOLERATED_GAPS
    )
    remedy = remediation_message(GIT_VERSION_UNSUPPORTED)
    assert remedy is not None and "2.25" in remedy
