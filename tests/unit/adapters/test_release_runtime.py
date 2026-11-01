"""Runtime copies survive replacement; lease and publication races fail closed."""

from __future__ import annotations

import errno
import fcntl
import os
import shutil
import sys
from collections.abc import Callable, Generator
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters import release_runtime as runtimes


@pytest.fixture
def prefix(tmp_path: Path) -> Generator[Path]:
    root = tmp_path / "tool"
    packages = root / "lib/python3.14/site-packages"
    (root / "bin").mkdir(parents=True)
    (root / "bin/python").write_bytes(b"interpreter fixture")
    (root / "bin/python").chmod(0o700)
    (root / "pyvenv.cfg").write_text("home = /python\n")
    (packages / "finishup-0.3.0.dist-info").mkdir(parents=True)
    (packages / "finishup-0.3.0.dist-info/RECORD").write_text("release one\n")
    (packages / "dependency").mkdir()
    (packages / "dependency/lazy.py").write_text("VALUE = 'old dependency'\n")
    (packages / "finishup/resources").mkdir(parents=True)
    (packages / "finishup/resources/guidance.md").write_text("old guidance\n")
    # Independent of the runner's umask (0002 on Ubuntu/Fedora accounts): tests opt in to g+w.
    for path in (root, *root.rglob("*")):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & ~0o022)
    try:
        yield root
    finally:
        manager = root.parent / f".{root.name}-releases"
        if manager.exists():
            # This fixture owns every byte here, including intentionally invalid test markers.
            runtimes._remove_copy(manager)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_copied_code_and_resources_survive_in_place_replacement(prefix: Path) -> None:
    old = runtimes.prepare_release_runtime(prefix)
    packages = Path("lib/python3.14/site-packages")
    for relative, new in (
        (packages / "dependency/lazy.py", "VALUE = 'new dependency'\n"),
        (packages / "finishup/resources/guidance.md", "new guidance\n"),
        (packages / "finishup-0.3.0.dist-info/RECORD", "release two\n"),
    ):
        (prefix / relative).write_text(new)
    new = runtimes.prepare_release_runtime(prefix)
    assert old != new
    assert (old / packages / "dependency/lazy.py").read_text() == "VALUE = 'old dependency'\n"
    assert (old / packages / "finishup/resources/guidance.md").read_text() == "old guidance\n"
    assert (new / packages / "finishup/resources/guidance.md").read_text() == "new guidance\n"
    assert runtimes.prepare_release_runtime(prefix) == new


def test_snapshot_does_not_share_package_manager_hardlinks(prefix: Path) -> None:
    old = runtimes.prepare_release_runtime(prefix)
    path = Path("lib/python3.14/site-packages/dependency/lazy.py")
    assert (prefix / path).stat().st_ino != (old / path).stat().st_ino


def test_snapshot_preserves_instance_root_pin_without_copying_state(prefix: Path) -> None:
    (prefix / "yoetz-instance-pin.json").write_text('{"fixture": "same-root"}')
    (prefix / "unrelated-secret").write_text("must not be copied")
    old = runtimes.prepare_release_runtime(prefix)
    assert (old / "yoetz-instance-pin.json").read_bytes() == (
        prefix / "yoetz-instance-pin.json"
    ).read_bytes()
    assert not (old / "unrelated-secret").exists()


def test_external_package_symlink_is_refused(prefix: Path, tmp_path: Path) -> None:
    outside = tmp_path / "mutable.py"
    outside.write_text("VALUE = 1")
    (prefix / "lib/external.py").symlink_to(outside)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_external_link"):
        runtimes.prepare_release_runtime(prefix)


def test_external_pth_is_refused(prefix: Path, tmp_path: Path) -> None:
    (prefix / "lib/external.pth").write_text(str(tmp_path))
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_external_link"):
        runtimes.prepare_release_runtime(prefix)


def test_interpreter_links_target_the_base_not_the_replaceable_installation(
    prefix: Path, tmp_path: Path
) -> None:
    binary = tmp_path / "python"
    binary.write_bytes(b"original interpreter")
    binary.chmod(0o700)
    interpreter = prefix / "bin/python"
    interpreter.unlink()
    interpreter.symlink_to(binary)
    target = runtimes.prepare_release_runtime(prefix)
    assert (target / "bin/python").resolve() == binary
    interpreter.unlink()
    assert (target / "bin/python").read_bytes() == b"original interpreter"


def test_source_change_during_copy_never_publishes_a_generation(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copyfile = runtimes.shutil.copyfile
    changed = False

    def copy(source: Path, destination: Path, *, follow_symlinks: bool) -> str:
        nonlocal changed
        result = copyfile(source, destination, follow_symlinks=follow_symlinks)
        if not changed:
            changed = True
            (prefix / "pyvenv.cfg").write_text("home = /changed-python\n")
        return str(result)

    monkeypatch.setattr(runtimes.shutil, "copyfile", copy)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_changed_retry"):
        runtimes.prepare_release_runtime(prefix)
    with runtimes.release_update_lock(prefix) as root:
        assert [p.name for p in root.iterdir()] == [".lock"]


def test_prune_retains_a_running_generation_until_lease_released(prefix: Path) -> None:
    target = runtimes.prepare_release_runtime(prefix)
    with (target / ".in-use").open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_SH)
        assert runtimes.prune_release_runtimes(prefix) == (0, 1)
        assert target.is_dir()
    assert runtimes.prune_release_runtimes(prefix) == (1, 0)
    assert not target.exists()
    assert runtimes.prune_release_runtimes(prefix) == (0, 0)


def test_foreign_or_linked_generation_is_never_reused_or_removed(prefix: Path) -> None:
    target = runtimes.prepare_release_runtime(prefix)
    (target / "yoetz-release-runtime.json").chmod(0o600)
    (target / "yoetz-release-runtime.json").write_text("{}")
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_invalid"):
        runtimes.prepare_release_runtime(prefix)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_invalid"):
        runtimes.prune_release_runtimes(prefix)
    assert target.exists()


def test_manager_lock_refuses_a_second_writer_with_bounded_wait(prefix: Path) -> None:
    with runtimes.release_update_lock(prefix):
        with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_busy"):
            with runtimes.release_update_lock(prefix, timeout=0):
                pytest.fail("second writer entered")


def _group_is_private(monkeypatch: pytest.MonkeyPatch, private: bool) -> None:
    from finishup.config import foreign_write

    monkeypatch.setattr(foreign_write, "owner_private_group", _private_group_is(private))


def test_world_writable_runtime_is_refused_with_its_own_token(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _group_is_private(monkeypatch, True)
    (prefix / "pyvenv.cfg").chmod(0o666)
    with pytest.raises(
        runtimes.ReleaseRuntimeError, match="release_runtime_world_writable"
    ) as error:
        runtimes.prepare_release_runtime(prefix)
    assert error.value.area == "environment"


@pytest.mark.parametrize("member", ["pyvenv.cfg", "lib/python3.14/site-packages/dependency"])
def test_shared_group_writable_runtime_is_refused(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, member: str
) -> None:
    _group_is_private(monkeypatch, False)
    (prefix / member).chmod(0o775 if (prefix / member).is_dir() else 0o664)
    with pytest.raises(
        runtimes.ReleaseRuntimeError, match="release_runtime_group_writable"
    ) as error:
        runtimes.prepare_release_runtime(prefix)
    assert error.value.area == "environment"


def test_shared_group_writable_prefix_itself_is_refused(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Whoever can write the prefix can swap bin/ or lib/ for a tree of their own.
    _group_is_private(monkeypatch, False)
    prefix.chmod(0o775)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_group_writable"):
        runtimes.prepare_release_runtime(prefix)


def test_umask_0002_runtime_of_a_user_private_group_is_accepted_and_sealed(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Ubuntu/Fedora default: every file is g+w for a group of one; FinishUP must run."""

    _group_is_private(monkeypatch, True)
    base = tmp_path / "cpython-3.14.6"
    (base / "bin").mkdir(parents=True)
    binary = base / "bin/python3.14"
    binary.write_bytes(b"managed interpreter")
    for path in (base, base / "bin"):
        path.chmod(0o775)
    binary.chmod(0o775)
    (prefix / "bin/python").unlink()
    (prefix / "bin/python").symlink_to(binary)
    for path in (prefix, *prefix.rglob("*")):
        if not path.is_symlink():
            path.chmod(0o775 if path.is_dir() else 0o664)
    target = runtimes.prepare_release_runtime(prefix)
    assert target.stat().st_mode & 0o077 == 0
    for path in target.rglob("*"):
        if not path.is_symlink():
            assert path.stat().st_mode & 0o022 == 0


@pytest.mark.parametrize("writable", ["binary", "bin", "root"])
def test_shared_group_writable_interpreter_chain_is_refused(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, writable: str
) -> None:
    _group_is_private(monkeypatch, False)
    base = tmp_path / "cpython"
    (base / "bin").mkdir(parents=True)
    binary = base / "bin/python3.14"
    binary.write_bytes(b"interpreter")
    for path in (base, base / "bin", binary):
        path.chmod(0o755)
    (prefix / "bin/python").unlink()
    (prefix / "bin/python").symlink_to(binary)
    {"binary": binary, "bin": base / "bin", "root": base}[writable].chmod(0o775)
    with pytest.raises(
        runtimes.ReleaseRuntimeError, match="release_runtime_group_writable"
    ) as error:
        runtimes.prepare_release_runtime(prefix)
    assert error.value.area == "interpreter"


def test_unrelated_completed_runtime_directory_is_not_removed(prefix: Path) -> None:
    with runtimes.release_update_lock(prefix) as root:
        unrelated = root / "user-file"
        unrelated.write_text("keep")
    runtimes.prune_release_runtimes(prefix)
    assert unrelated.read_text() == "keep"


def test_generation_is_private(prefix: Path) -> None:
    target = runtimes.prepare_release_runtime(prefix)
    assert target.stat().st_mode & 0o077 == 0
    assert target.stat().st_uid == os.geteuid()


def test_retry_reclaims_only_marked_abandoned_copies(prefix: Path) -> None:
    import json

    with runtimes.release_update_lock(prefix) as root:
        abandoned = root / ".creating-abcd1234"
        abandoned.mkdir(mode=0o700)
        (abandoned / ".creation.json").write_text(
            json.dumps(
                {
                    "schema": "yoetz.release-runtime/1",
                    "origin": str(prefix),
                    "key": "f" * 64,
                }
            )
        )
        (abandoned / ".creation.json").chmod(0o600)
        (abandoned / "partial-package").write_text("partial")
        unknown = root / ".creating-unknown1"
        unknown.mkdir(mode=0o700)
        (unknown / "user-file").write_text("keep")
    runtimes.prepare_release_runtime(prefix)
    assert not abandoned.exists()
    assert (unknown / "user-file").read_text() == "keep"


def test_disposal_waits_for_the_observed_process_lease_to_close(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = runtimes.prepare_release_runtime(prefix)
    observed: list[float] = []
    with (target / ".in-use").open("rb") as lease:
        fcntl.flock(lease, fcntl.LOCK_SH)

        def finish_shutdown(delay: float) -> None:
            # Advance only after cleanup actually observes the still-held process lease.
            observed.append(delay)
            fcntl.flock(lease, fcntl.LOCK_UN)

        monkeypatch.setattr(runtimes.time, "sleep", finish_shutdown)
        assert runtimes.prune_release_runtimes(prefix, wait_seconds=1.0) == (1, 0)
    assert len(observed) == 1
    assert not target.exists()


def test_snapshot_publication_supports_filesystems_requiring_writable_rename_source(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rename = Path.rename

    def require_writable(path: Path, target: str | Path) -> Path:
        if path.name.startswith(".creating-"):
            assert path.stat().st_mode & 0o200, "macOS rename requires a writable staging root"
            # Only the private root remains writable; payloads are already sealed.
            assert not (path / "pyvenv.cfg").stat().st_mode & 0o222
        return rename(path, target)

    monkeypatch.setattr(Path, "rename", require_writable)
    target = runtimes.prepare_release_runtime(prefix)
    assert not target.stat().st_mode & 0o222
    assert runtimes.prepare_release_runtime(prefix) == target


def test_failed_root_seal_removes_only_new_generation_and_can_retry(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    chmod = Path.chmod
    failed = False

    def fail_once(path: Path, mode: int, *, follow_symlinks: bool = True) -> None:
        nonlocal failed
        if not failed and len(path.name) == 64 and mode == 0o500:
            failed = True
            raise PermissionError(13, "synthetic seal refusal")
        chmod(path, mode, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "chmod", fail_once)
    with pytest.raises(runtimes.ReleaseRuntimeIOError) as caught:
        runtimes.prepare_release_runtime(prefix)
    assert caught.value.phase == "snapshot_publish"
    manager = prefix.parent / f".{prefix.name}-releases"
    assert sorted(p.name for p in manager.iterdir()) == [".lock"]
    assert (prefix / "pyvenv.cfg").is_file()
    target = runtimes.prepare_release_runtime(prefix)
    assert not target.stat().st_mode & 0o222


def test_writable_published_root_is_not_reused_as_a_sealed_generation(prefix: Path) -> None:
    target = runtimes.prepare_release_runtime(prefix)
    target.chmod(0o700)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_incomplete"):
        runtimes.prepare_release_runtime(prefix)
    # Supported pruning can remove the unleased, owned incomplete generation before retry.
    assert runtimes.prune_release_runtimes(prefix) == (1, 0)
    repaired = runtimes.prepare_release_runtime(prefix)
    assert not repaired.stat().st_mode & 0o222


def _fixed_marker(marker: dict[str, str]) -> Callable[[Path], dict[str, str]]:
    def read(_prefix: Path) -> dict[str, str]:
        return marker

    return read


@pytest.mark.parametrize("module", ["finishup", "yoetz"])
def test_module_registration_keeps_its_spelling_across_the_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: str
) -> None:
    """``python -m yoetz`` host entries from before the rename keep comparing equal (ADR-048)."""

    origin = tmp_path / "tool"
    interpreter = origin / "bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"interpreter fixture")
    marker = {"schema": "yoetz.release-runtime/1", "origin": str(origin), "key": "0" * 64}
    monkeypatch.setattr(runtimes, "_marker", _fixed_marker(marker))
    monkeypatch.setattr(runtimes, "_original_interpreter", str(interpreter))
    main = origin / "lib/python3.14/site-packages" / module / "__main__.py"

    assert runtimes.original_module_launcher(main) == (str(interpreter.resolve()), "-m", module)


@pytest.mark.parametrize(
    "relative", ["lib/python3.14/site-packages/other/__main__.py", "lib/yoetz/entry.py"]
)
def test_module_registration_ignores_other_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str
) -> None:
    origin = tmp_path / "tool"
    marker = {"schema": "yoetz.release-runtime/1", "origin": str(origin), "key": "0" * 64}
    monkeypatch.setattr(runtimes, "_marker", _fixed_marker(marker))
    monkeypatch.setattr(runtimes, "_original_interpreter", "/usr/bin/python3")

    assert runtimes.original_module_launcher(origin / relative) is None
    outside = tmp_path / "elsewhere/lib/python3.14/site-packages/yoetz/__main__.py"
    assert runtimes.original_module_launcher(outside) is None


def _private_group_is(value: bool) -> Callable[[int, int], bool]:
    def answer(_uid: int, _gid: int) -> bool:
        return value

    return answer


def _as_installed(monkeypatch: pytest.MonkeyPatch, prefix: Path) -> None:
    package = prefix / "lib/python3.14/site-packages/finishup/adapters/release_runtime.py"
    package.parent.mkdir(parents=True, exist_ok=True)
    package.write_text("")
    for path in (prefix, *prefix.rglob("*")):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & ~0o022)
    monkeypatch.setattr(runtimes.sys, "prefix", str(prefix))
    monkeypatch.setattr(runtimes.sys, "base_prefix", "/base")
    monkeypatch.setattr(runtimes, "__file__", str(package))


def test_installed_runtime_probe_reports_foreign_write_without_creating_a_copy(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _as_installed(monkeypatch, prefix)
    _group_is_private(monkeypatch, False)
    assert runtimes.installed_runtime_refusal() is None
    (prefix / "pyvenv.cfg").chmod(0o664)
    refusal = runtimes.installed_runtime_refusal()
    assert refusal is not None and str(refusal) == "release_runtime_group_writable"
    assert not (prefix.parent / f".{prefix.name}-releases").exists()
    (prefix / "pyvenv.cfg").chmod(0o666)
    refusal = runtimes.installed_runtime_refusal()
    assert refusal is not None and str(refusal) == "release_runtime_world_writable"


def test_installed_runtime_probe_ignores_other_refusals(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _as_installed(monkeypatch, prefix)
    (prefix / "lib/external.pth").write_text(str(tmp_path))
    (prefix / "lib/external.pth").chmod(0o644)
    assert runtimes.installed_runtime_refusal() is None


# A runtime another account installed (root, in a container image) run by this account. The test
# runner owns every file here, so "this account" is played by a different effective uid: every
# file the runner made then belongs to another account, exactly as a root install does.
def _as_another_account(monkeypatch: pytest.MonkeyPatch) -> None:
    other = os.geteuid() + 4242
    monkeypatch.setattr(runtimes.os, "geteuid", lambda: other)


def _refuse_mkdir_beneath(monkeypatch: pytest.MonkeyPatch, parent: Path) -> None:
    """The kernel's answer to a non-owner creating an entry in a 0755 directory."""

    real_mkdir = os.mkdir

    def refusing_mkdir(path: str | os.PathLike[str], mode: int = 0o777, **kwargs: object) -> None:
        if Path(path).parent == parent:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES))
        real_mkdir(path, mode, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(runtimes.os, "mkdir", refusing_mkdir)


def test_a_retained_runtime_directory_another_account_owns_is_refused_by_name(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Root served first and made the directory; a non-root user is told why, not "unsafe"."""

    manager = prefix.parent / f".{prefix.name}-releases"
    manager.mkdir(mode=0o700)
    _as_another_account(monkeypatch)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_not_owned"):
        runtimes.prepare_release_runtime(prefix)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_not_owned"):
        runtimes.prune_release_runtimes(prefix)
    assert list(manager.iterdir()) == []


def test_a_retained_runtime_directory_this_account_cannot_create_is_refused_by_name(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No directory yet, and the installation's parent belongs to another account."""

    _as_another_account(monkeypatch)
    _refuse_mkdir_beneath(monkeypatch, prefix.parent)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_not_owned"):
        runtimes.prepare_release_runtime(prefix)
    assert not (prefix.parent / f".{prefix.name}-releases").exists()


def test_an_unwritable_parent_this_account_owns_stays_an_os_failure(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The token names another account's ownership only; the account's own read-only directory
    keeps its bounded OS reason."""

    _refuse_mkdir_beneath(monkeypatch, prefix.parent)
    with pytest.raises(PermissionError):
        runtimes.prepare_release_runtime(prefix)


def test_installed_runtime_probe_reports_another_accounts_runtime_without_creating(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _as_installed(monkeypatch, prefix)
    _as_another_account(monkeypatch)
    manager = prefix.parent / f".{prefix.name}-releases"
    # Absent, in a directory this account may still write (sticky, or its own): no refusal.
    assert runtimes.installed_runtime_refusal() is None

    def no_write_access(path: object, mode: int, **_kwargs: object) -> bool:
        return Path(cast(str, path)) != prefix.parent

    monkeypatch.setattr(runtimes.os, "access", no_write_access)
    refusal = runtimes.installed_runtime_refusal()
    assert refusal is not None and str(refusal) == "release_runtime_not_owned"
    assert not manager.exists()

    def write_access(_path: object, _mode: int, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(runtimes.os, "access", write_access)
    manager.mkdir(mode=0o700)
    refusal = runtimes.installed_runtime_refusal()
    assert refusal is not None and str(refusal) == "release_runtime_not_owned"
    assert list(manager.iterdir()) == []


@pytest.mark.parametrize("change", ["group_shared", "world_writable", "directory_shared"])
def test_reused_generation_revalidates_its_interpreter(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, change: str
) -> None:
    """A generation made while the interpreter was private is not reused once it is not."""

    _group_is_private(monkeypatch, True)
    base = tmp_path / "cpython"
    (base / "bin").mkdir(parents=True)
    binary = base / "bin/python3.14"
    binary.write_bytes(b"interpreter")
    for path in (base, base / "bin", binary):
        path.chmod(0o775)
    (prefix / "bin/python").unlink()
    (prefix / "bin/python").symlink_to(binary)
    target = runtimes.prepare_release_runtime(prefix)
    assert runtimes.prepare_release_runtime(prefix) == target
    if change == "group_shared":
        # Bob joins the interpreter's group after the generation was made.
        _group_is_private(monkeypatch, False)
        token = "release_runtime_group_writable"
    elif change == "world_writable":
        binary.chmod(0o777)
        token = "release_runtime_world_writable"
    else:
        _group_is_private(monkeypatch, False)
        binary.chmod(0o755)
        token = "release_runtime_group_writable"
    with pytest.raises(runtimes.ReleaseRuntimeError, match=token) as error:
        runtimes.prepare_release_runtime(prefix)
    assert error.value.area == "interpreter"


def test_process_inside_a_generation_revalidates_before_serving(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _group_is_private(monkeypatch, True)
    base = tmp_path / "cpython"
    (base / "bin").mkdir(parents=True)
    binary = base / "bin/python3.14"
    binary.write_bytes(b"interpreter")
    for path in (base, base / "bin", binary):
        path.chmod(0o755)
    (prefix / "bin/python").unlink()
    (prefix / "bin/python").symlink_to(binary)
    target = runtimes.prepare_release_runtime(prefix)
    monkeypatch.setattr(runtimes.sys, "prefix", str(target))
    binary.chmod(0o757)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_world_writable"):
        runtimes.enter_release_runtime([])


_TAG = sys.implementation.cache_tag


def _pyc(generation: Path, relative: str) -> Path:
    source = generation / relative
    return source.parent / "__pycache__" / f"{source.stem}.{_TAG}.pyc"


def test_generation_ships_unchecked_hash_bytecode_for_every_module(prefix: Path) -> None:
    """A sealed copy cannot cache bytecode, so it must already hold it (WSL: 12 s vs 6 s)."""

    import importlib.util

    target = runtimes.prepare_release_runtime(prefix)
    sources = sorted((target / "lib").rglob("*.py"))
    assert sources
    for source in sources:
        cached = source.parent / "__pycache__" / f"{source.stem}.{_TAG}.pyc"
        data = cached.read_bytes()
        assert data[:4] == importlib.util.MAGIC_NUMBER
        assert int.from_bytes(data[4:8], "little") == 0b1  # hash-based, never re-checked
        assert data[8:16] == importlib.util.source_hash(source.read_bytes())
        assert cached.stat().st_mode & 0o777 == 0o400
        assert cached.parent.stat().st_mode & 0o777 == 0o500


def test_sealed_generation_imports_from_its_bytecode(prefix: Path) -> None:
    import subprocess

    target = runtimes.prepare_release_runtime(prefix)
    packages = target / "lib/python3.14/site-packages"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-v",
            "-c",
            f"import sys; sys.path.insert(0, {str(packages)!r}); "
            "import dependency.lazy as m; print(m.__file__)",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert (
        f"code object from '{_pyc(target, 'lib/python3.14/site-packages/dependency/lazy.py')}'"
        in (result.stderr)
    )
    assert result.stdout.strip() == str(packages / "dependency/lazy.py")


def _spy_compiles(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    compiled: list[str] = []
    original = runtimes.py_compile.compile

    def spy(file: str, *args: object, **kwargs: object) -> object:
        compiled.append(Path(file).name)
        return original(file, *args, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(runtimes.py_compile, "compile", spy)
    return compiled


def _installed_pyc(
    prefix: Path,
    mode: str = "unchecked-hash",
) -> Path:
    import py_compile

    modes = {
        "timestamp": py_compile.PycInvalidationMode.TIMESTAMP,
        "checked-hash": py_compile.PycInvalidationMode.CHECKED_HASH,
        "unchecked-hash": py_compile.PycInvalidationMode.UNCHECKED_HASH,
    }
    source = prefix / "lib/python3.14/site-packages/dependency/lazy.py"
    cached = source.parent / "__pycache__" / f"lazy.{_TAG}.pyc"
    py_compile.compile(str(source), cfile=str(cached), doraise=True, invalidation_mode=modes[mode])
    for path in (cached, cached.parent):
        path.chmod(path.stat().st_mode & ~0o022)
    return cached


def _sealed_value(generation: Path) -> object:
    import marshal

    data = _pyc(generation, "lib/python3.14/site-packages/dependency/lazy.py").read_bytes()
    namespace: dict[str, object] = {}
    exec(marshal.loads(data[16:]), namespace)  # noqa: S102 - bytecode this test compiled
    return namespace["VALUE"]


@pytest.mark.parametrize("mode", ["checked-hash", "unchecked-hash"])
def test_valid_installed_hash_bytecode_is_reused_not_recompiled(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    installed = _installed_pyc(prefix, mode)
    compiled = _spy_compiles(monkeypatch)
    target = runtimes.prepare_release_runtime(prefix)
    assert "lazy.py" not in compiled
    reused = _pyc(target, "lib/python3.14/site-packages/dependency/lazy.py").read_bytes()
    assert int.from_bytes(reused[4:8], "little") == 0b1
    assert reused[16:] == installed.read_bytes()[16:]


def test_timestamp_bytecode_is_compiled_fresh(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timestamp pyc proves only a whole-second mtime and a size, never the source bytes."""

    _installed_pyc(prefix, "timestamp")
    compiled = _spy_compiles(monkeypatch)
    runtimes.prepare_release_runtime(prefix)
    assert "lazy.py" in compiled


def test_same_second_equal_size_edit_never_seals_stale_bytecode(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib.util

    source = prefix / "lib/python3.14/site-packages/dependency/lazy.py"
    _installed_pyc(prefix, "timestamp")
    stamp = source.stat().st_mtime_ns
    new_source = "VALUE = 'NEW dependency'\n"
    assert len(new_source) == len(source.read_text())
    source.write_text(new_source)
    os.utime(source, ns=(stamp, stamp))  # same second, same size: the header still matches
    target = runtimes.prepare_release_runtime(prefix)
    sealed = _pyc(target, "lib/python3.14/site-packages/dependency/lazy.py").read_bytes()
    assert sealed[8:16] == importlib.util.source_hash(new_source.encode())
    assert _sealed_value(target) == "NEW dependency"


@pytest.mark.parametrize("problem", ["stale_hash", "foreign_writable", "wrong_magic", "flags"])
def test_untrustworthy_installed_bytecode_is_compiled_instead(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    installed = _installed_pyc(prefix, "checked-hash")
    source = prefix / "lib/python3.14/site-packages/dependency/lazy.py"
    if problem == "stale_hash":
        source.write_text("VALUE = 'changed dependency'\n")
        source.chmod(0o644)
    elif problem == "foreign_writable":
        installed.chmod(0o666)
    else:
        data = bytearray(installed.read_bytes())
        if problem == "wrong_magic":
            data[0] ^= 0xFF
        else:
            data[4] |= 0b100
        installed.write_bytes(bytes(data))
    compiled = _spy_compiles(monkeypatch)
    target = runtimes.prepare_release_runtime(prefix)
    assert "lazy.py" in compiled
    if problem == "stale_hash":
        assert _sealed_value(target) == "changed dependency"


@pytest.mark.parametrize("payload", ["header_only", "invalid_marshal", "not_code"])
def test_matching_header_without_valid_code_is_compiled_instead(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    """A matching source hash is freshness evidence for the header, not for the payload."""

    import marshal

    installed = _installed_pyc(prefix, "checked-hash")
    header = installed.read_bytes()[:16]
    body = {
        "header_only": b"",
        "invalid_marshal": b"\xff\x00garbage",
        "not_code": marshal.dumps(42),
    }
    installed.write_bytes(header + body[payload])
    compiled = _spy_compiles(monkeypatch)
    target = runtimes.prepare_release_runtime(prefix)
    assert "lazy.py" in compiled
    assert _sealed_value(target) == "old dependency"


def test_generation_from_an_earlier_layout_is_never_reused(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A generation sealed before bytecode was shipped must not satisfy a newer start.
    monkeypatch.setattr(runtimes, "_LAYOUT", b"")
    older = runtimes.prepare_release_runtime(prefix)
    monkeypatch.undo()
    newer = runtimes.prepare_release_runtime(prefix)
    assert newer != older
    assert _pyc(newer, "lib/python3.14/site-packages/dependency/lazy.py").exists()


def _tiny_wheel(directory: Path) -> Path:
    import base64
    import hashlib
    import zipfile

    files = {
        "hashdep_mod.py": b"VALUE = 'installed by an owned path'\n",
        "hashdep-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: hashdep\nVersion: 1.0\n",
        "hashdep-1.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record: list[str] = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{name},sha256={digest},{len(data)}")
    record.append("hashdep-1.0.dist-info/RECORD,,")
    wheel = directory / "hashdep-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("hashdep-1.0.dist-info/RECORD", "\n".join(record) + "\n")
    return wheel


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is the supported installer")
def test_owned_install_environment_yields_reused_checked_hash_bytecode(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`finishup upgrade`, `npx finishup` and the provisioner install with checked-hash bytecode.

    uv's ``--compile-bytecode`` writes timestamp pycs, which a sealed generation never reuses;
    the owned install paths set ``SOURCE_DATE_EPOCH`` in the child so the generation reuses
    the installed bytecode instead of compiling the package on the first serving start.
    """

    import subprocess

    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    site = prefix / "lib/python3.14/site-packages"
    environment = runtimes.hash_bytecode_environment(os.environ)
    assert "SOURCE_DATE_EPOCH" not in os.environ  # the child's environment only
    subprocess.run(
        [
            "uv", "pip", "install", "--offline", "--no-deps", "--compile-bytecode",
            "--python", sys.executable, "--target", str(site), str(_tiny_wheel(tmp_path)),
        ],
        env=environment,
        umask=0o022,
        check=True,
        capture_output=True,
        timeout=120,
    )  # fmt: skip
    installed = site / "__pycache__" / f"hashdep_mod.{_TAG}.pyc"
    assert int.from_bytes(installed.read_bytes()[4:8], "little") == 0b11  # checked hash
    for path in (prefix, *prefix.rglob("*")):
        if not path.is_symlink():
            path.chmod(path.stat().st_mode & ~0o022)
    compiled = _spy_compiles(monkeypatch)
    target = runtimes.prepare_release_runtime(prefix)
    assert "hashdep_mod.py" not in compiled
    assert "lazy.py" in compiled  # the fixture's module has no installed bytecode
    sealed = _pyc(target, "lib/python3.14/site-packages/hashdep_mod.py").read_bytes()
    assert sealed[16:] == installed.read_bytes()[16:]


def test_hash_bytecode_environment_keeps_an_explicit_epoch() -> None:
    assert runtimes.hash_bytecode_environment({"PATH": "/bin"}) == {
        "PATH": "/bin",
        "SOURCE_DATE_EPOCH": runtimes.HASH_BYTECODE_EPOCH,
    }
    kept = runtimes.hash_bytecode_environment({"SOURCE_DATE_EPOCH": "1700000000"})
    assert kept == {"SOURCE_DATE_EPOCH": "1700000000"}


_PROBE_BACKEND = """
import base64, hashlib, os, zipfile

def _write(directory, epoch):
    name = "epochprobe-1.0-py3-none-any.whl"
    files = {
        "epochprobe_mod.py": ("EPOCH = %r\\n" % epoch).encode(),
        "epochprobe-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\\nName: epochprobe\\nVersion: 1.0\\n",
        "epochprobe-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\\nGenerator: t\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
    }
    record = []
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append("%s,sha256=%s,%d" % (path, digest, len(data)))
    record.append("epochprobe-1.0.dist-info/RECORD,,")
    with zipfile.ZipFile(os.path.join(directory, name), "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
        archive.writestr("epochprobe-1.0.dist-info/RECORD", "\\n".join(record) + "\\n")
    return name

def get_requires_for_build_wheel(config_settings=None):
    return []

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return _write(wheel_directory, os.environ.get("SOURCE_DATE_EPOCH"))
"""


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is the supported installer")
@pytest.mark.parametrize("owned", [True, False])
def test_install_epoch_reaches_only_the_install_and_its_build_backends(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, owned: bool
) -> None:
    """The owned epoch is scoped to the install child, which includes an sdist's backend.

    ADR-007 documents this: a dependency built from source sees the epoch, unlike a plain
    install; nothing outside the install child does.
    """

    import subprocess

    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    project = tmp_path / "epochprobe"
    project.mkdir()
    (project / "backend.py").write_text(_PROBE_BACKEND)
    (project / "pyproject.toml").write_text(
        '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n'
        '[project]\nname = "epochprobe"\nversion = "1.0"\n'
    )
    site = tmp_path / "site"
    environment = runtimes.hash_bytecode_environment(os.environ) if owned else dict(os.environ)
    subprocess.run(
        [
            "uv", "pip", "install", "--offline", "--no-deps", "--no-cache", "--compile-bytecode",
            "--python", sys.executable, "--target", str(site), str(project),
        ],
        env=environment,
        umask=0o022,
        check=True,
        capture_output=True,
        timeout=120,
    )  # fmt: skip
    expected = runtimes.HASH_BYTECODE_EPOCH if owned else None
    assert (site / "epochprobe_mod.py").read_text() == f"EPOCH = {expected!r}\n"
    pyc = site / "__pycache__" / f"epochprobe_mod.{_TAG}.pyc"
    assert int.from_bytes(pyc.read_bytes()[4:8], "little") == (0b11 if owned else 0)
    assert "SOURCE_DATE_EPOCH" not in os.environ
