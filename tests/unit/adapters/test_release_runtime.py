"""Runtime copies survive replacement; lease and publication races fail closed."""

from __future__ import annotations

import fcntl
import os
from collections.abc import Callable, Generator
from pathlib import Path

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


def test_group_writable_runtime_is_refused(prefix: Path) -> None:
    (prefix / "pyvenv.cfg").chmod(0o666)
    with pytest.raises(runtimes.ReleaseRuntimeError, match="release_runtime_unsafe"):
        runtimes.prepare_release_runtime(prefix)


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
