"""Runtime copies survive replacement; lease and publication races fail closed."""

from __future__ import annotations

import fcntl
import os
import sys
from collections.abc import Callable, Generator
from pathlib import Path

import pytest

from yoetz.adapters import release_runtime as runtimes


@pytest.fixture
def prefix(tmp_path: Path) -> Generator[Path]:
    root = tmp_path / "tool"
    packages = root / "lib/python3.14/site-packages"
    (root / "bin").mkdir(parents=True)
    (root / "bin/python").write_bytes(b"interpreter fixture")
    (root / "bin/python").chmod(0o700)
    (root / "pyvenv.cfg").write_text("home = /python\n")
    (packages / "yoetz-0.3.0.dist-info").mkdir(parents=True)
    (packages / "yoetz-0.3.0.dist-info/RECORD").write_text("release one\n")
    (packages / "dependency").mkdir()
    (packages / "dependency/lazy.py").write_text("VALUE = 'old dependency'\n")
    (packages / "yoetz/resources").mkdir(parents=True)
    (packages / "yoetz/resources/guidance.md").write_text("old guidance\n")
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
        (packages / "yoetz/resources/guidance.md", "new guidance\n"),
        (packages / "yoetz-0.3.0.dist-info/RECORD", "release two\n"),
    ):
        (prefix / relative).write_text(new)
    new = runtimes.prepare_release_runtime(prefix)
    assert old != new
    assert (old / packages / "dependency/lazy.py").read_text() == "VALUE = 'old dependency'\n"
    assert (old / packages / "yoetz/resources/guidance.md").read_text() == "old guidance\n"
    assert (new / packages / "yoetz/resources/guidance.md").read_text() == "new guidance\n"
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
    from yoetz.config import foreign_write

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
    """Ubuntu/Fedora default: every file is g+w for a group of one; Yoetz must run."""

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


def _private_group_is(value: bool) -> Callable[[int, int], bool]:
    def answer(_uid: int, _gid: int) -> bool:
        return value

    return answer


def _as_installed(monkeypatch: pytest.MonkeyPatch, prefix: Path) -> None:
    package = prefix / "lib/python3.14/site-packages/yoetz/adapters/release_runtime.py"
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


def _installed_pyc(prefix: Path) -> Path:
    import py_compile

    source = prefix / "lib/python3.14/site-packages/dependency/lazy.py"
    cached = source.parent / "__pycache__" / f"lazy.{_TAG}.pyc"
    py_compile.compile(str(source), cfile=str(cached), doraise=True)
    for path in (cached, cached.parent):
        path.chmod(path.stat().st_mode & ~0o022)
    return cached


def test_valid_installed_bytecode_is_reused_not_recompiled(
    prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installed = _installed_pyc(prefix)
    compiled = _spy_compiles(monkeypatch)
    target = runtimes.prepare_release_runtime(prefix)
    assert "lazy.py" not in compiled
    reused = _pyc(target, "lib/python3.14/site-packages/dependency/lazy.py").read_bytes()
    assert int.from_bytes(reused[4:8], "little") == 0b1
    assert reused[16:] == installed.read_bytes()[16:]


@pytest.mark.parametrize("problem", ["stale", "foreign_writable", "wrong_magic"])
def test_untrustworthy_installed_bytecode_is_compiled_instead(
    prefix: Path, monkeypatch: pytest.MonkeyPatch, problem: str
) -> None:
    installed = _installed_pyc(prefix)
    source = prefix / "lib/python3.14/site-packages/dependency/lazy.py"
    if problem == "stale":
        stamp = source.stat().st_mtime + 10
        os.utime(source, (stamp, stamp))
    elif problem == "foreign_writable":
        installed.chmod(0o666)
    else:
        data = bytearray(installed.read_bytes())
        data[0] ^= 0xFF
        installed.write_bytes(bytes(data))
    compiled = _spy_compiles(monkeypatch)
    runtimes.prepare_release_runtime(prefix)
    assert "lazy.py" in compiled


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
