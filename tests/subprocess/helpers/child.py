"""Bounded, isolated child-process harness for subprocess acceptance tests."""

from __future__ import annotations

import hashlib
import json
import os
import signal as signal_module
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Final, Literal, Protocol, cast

__all__ = [
    "ChildHandle",
    "ChildLimits",
    "ChildResult",
    "ChildSpec",
    "assert_no_owned_children",
    "assert_no_source_import",
    "close_stdin",
    "communicate_bounded",
    "signal_child",
    "spawn_installed",
    "terminate_owned_group",
]

_READ_CHUNK: Final = 65_536
_OWNER_MARKER: Final = ".finishup-child-owner.json"


@dataclass(frozen=True, slots=True)
class ChildLimits:
    wall_time_seconds: float = 15.0
    max_output_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if type(self.wall_time_seconds) is not float or not 0.1 <= self.wall_time_seconds <= 600.0:
            raise ValueError("child_wall_limit_invalid")
        if type(self.max_output_bytes) is not int or not 1 <= self.max_output_bytes <= 16_777_216:
            raise ValueError("child_output_limit_invalid")


def _empty_env() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ChildSpec:
    executable: Path
    argv: tuple[str, ...] = ()
    env_overlay: Mapping[str, str] = field(default_factory=_empty_env)
    cwd: Path | None = None
    limits: ChildLimits = field(default_factory=ChildLimits)

    def __post_init__(self) -> None:
        executable = Path(os.path.abspath(self.executable))
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("child_executable_invalid")
        if type(self.argv) is not tuple or any(
            type(arg) is not str or "\x00" in arg for arg in self.argv
        ):
            raise ValueError("child_argv_invalid")
        copied: dict[str, str] = {}
        for key, value in self.env_overlay.items():
            if (
                type(key) is not str
                or type(value) is not str
                or not key
                or "\x00" in key
                or "=" in key
                or "\x00" in value
            ):
                raise ValueError("child_env_invalid")
            copied[key] = value
        if self.cwd is not None and not self.cwd.resolve(strict=True).is_dir():
            raise ValueError("child_cwd_invalid")
        object.__setattr__(self, "executable", executable)
        object.__setattr__(self, "env_overlay", MappingProxyType(copied))


@dataclass(slots=True)
class ChildHandle:
    process: subprocess.Popen[bytes] = field(repr=False)
    process_id: int
    process_group: int
    start_monotonic: float
    temp_root: Path
    limits: ChildLimits


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...

    def hexdigest(self) -> str: ...


def _new_digest() -> _Digest:
    return hashlib.sha256()


def _empty_chunks() -> list[bytes]:
    return []


@dataclass(frozen=True, slots=True)
class ChildResult:
    stdout: bytes
    stderr: bytes
    stdout_digest: str
    stderr_digest: str
    exit_code: int | None
    signal: int | None
    duration_seconds: float
    limit_verdict: Literal["passed", "wall_time_exceeded", "output_limit_exceeded"]
    process_group: int
    temp_root: Path


@dataclass(slots=True)
class _Drain:
    limit: int
    chunks: list[bytes] = field(default_factory=_empty_chunks)
    digest: _Digest = field(default_factory=_new_digest)
    captured: int = 0
    exceeded: bool = False

    def add(self, chunk: bytes) -> None:
        self.digest.update(chunk)
        remaining = self.limit - self.captured
        if remaining > 0:
            kept = chunk[:remaining]
            self.chunks.append(kept)
            self.captured += len(kept)
        if len(chunk) > remaining:
            self.exceeded = True

    def value(self) -> bytes:
        return b"".join(self.chunks)

    def hexdigest(self) -> str:
        return f"sha256:{self.digest.hexdigest()}"


def _minimal_environment(temp_root: Path, artifact_env: Mapping[str, str]) -> dict[str, str]:
    environment = {
        "HOME": str(temp_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": artifact_env.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TMPDIR": str(temp_root / "tmp"),
        "TZ": "UTC",
        "XDG_CACHE_HOME": str(temp_root / "cache"),
        "XDG_CONFIG_HOME": str(temp_root / "config"),
        "XDG_DATA_HOME": str(temp_root / "data"),
        "XDG_RUNTIME_DIR": str(temp_root / "runtime"),
        "FINISHUP_TEST_MARKER": temp_root.name,
    }
    for key in ("VIRTUAL_ENV", "SYSTEMROOT"):
        value = artifact_env.get(key)
        if value is not None:
            environment[key] = value
    return environment


def spawn_installed(
    spec: ChildSpec,
    artifact_env: Mapping[str, str],
    *,
    _inherited_fds: tuple[int, ...] = (),
) -> ChildHandle:
    """Spawn one isolated binary child in a new owned process group."""

    if type(_inherited_fds) is not tuple or any(
        type(descriptor) is not int or descriptor < 3 for descriptor in _inherited_fds
    ):
        raise ValueError("child_inherited_descriptor_invalid")
    if len(set(_inherited_fds)) != len(_inherited_fds):
        raise ValueError("child_inherited_descriptor_invalid")

    temp_root = Path(tempfile.mkdtemp(prefix="finishup-subprocess-"))
    temp_root.chmod(0o700)
    for name in ("home", "tmp", "cache", "config", "data", "runtime"):
        directory = temp_root / name
        directory.mkdir(mode=0o700)
    environment = _minimal_environment(temp_root, artifact_env)
    environment.update(spec.env_overlay)
    checkout_root = artifact_env.get("FINISHUP_CHECKOUT_ROOT")
    if checkout_root is not None and spec.executable.is_relative_to(Path(checkout_root).resolve()):
        raise ValueError("child_executable_from_checkout")
    process = subprocess.Popen(
        (str(spec.executable), *spec.argv),
        cwd=spec.cwd or temp_root,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        close_fds=True,
        pass_fds=_inherited_fds,
        start_new_session=True,
    )
    marker = {"pid": process.pid, "pgid": process.pid, "token": temp_root.name}
    (temp_root / _OWNER_MARKER).write_text(json.dumps(marker, sort_keys=True), encoding="ascii")
    return ChildHandle(
        process=process,
        process_id=process.pid,
        process_group=process.pid,
        start_monotonic=time.monotonic(),
        temp_root=temp_root,
        limits=spec.limits,
    )


def _drain_pipe(stream: BinaryIO, drain: _Drain) -> None:
    while True:
        try:
            chunk = stream.read(_READ_CHUNK)
        except OSError:
            return
        if not chunk:
            return
        drain.add(chunk)


def communicate_bounded(handle: ChildHandle, input_bytes: bytes = b"") -> ChildResult:
    """Send exact bytes, concurrently drain both streams, and enforce hard wall/output caps."""

    if type(input_bytes) is not bytes:
        raise TypeError("child_input_not_bytes")
    process = handle.process
    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        raise RuntimeError("child_pipe_missing")
    stdout = _Drain(handle.limits.max_output_bytes)
    stderr = _Drain(handle.limits.max_output_bytes)
    threads = (
        threading.Thread(target=_drain_pipe, args=(stdout_pipe, stdout), daemon=True),
        threading.Thread(target=_drain_pipe, args=(stderr_pipe, stderr), daemon=True),
    )
    for thread in threads:
        thread.start()
    if process.stdin is not None:
        try:
            process.stdin.write(input_bytes)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
    deadline = handle.start_monotonic + handle.limits.wall_time_seconds
    verdict: Literal["passed", "wall_time_exceeded", "output_limit_exceeded"] = "passed"
    while process.poll() is None:
        if stdout.exceeded or stderr.exceeded:
            verdict = "output_limit_exceeded"
            terminate_owned_group(handle)
            break
        if time.monotonic() >= deadline:
            verdict = "wall_time_exceeded"
            terminate_owned_group(handle)
            break
        time.sleep(0.005)
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        terminate_owned_group(handle)
        process.wait(timeout=1.0)
    for thread in threads:
        thread.join(timeout=1.0)
    duration = time.monotonic() - handle.start_monotonic
    return_code = process.returncode
    return ChildResult(
        stdout=stdout.value(),
        stderr=stderr.value(),
        stdout_digest=stdout.hexdigest(),
        stderr_digest=stderr.hexdigest(),
        exit_code=return_code if return_code is not None and return_code >= 0 else None,
        signal=-return_code if return_code is not None and return_code < 0 else None,
        duration_seconds=duration,
        limit_verdict=verdict,
        process_group=handle.process_group,
        temp_root=handle.temp_root,
    )


def _verify_owned_group(handle: ChildHandle) -> None:
    marker_path = handle.temp_root / _OWNER_MARKER
    try:
        decoded = json.loads(marker_path.read_text(encoding="ascii"))
        actual_group = os.getpgid(handle.process_id)
    except (FileNotFoundError, ProcessLookupError, json.JSONDecodeError) as exc:
        raise RuntimeError("child_ownership_unverified") from exc
    marker = cast(dict[str, object], decoded) if type(decoded) is dict else {}
    if (
        marker.get("pid") != handle.process_id
        or marker.get("pgid") != handle.process_group
        or marker.get("token") != handle.temp_root.name
        or actual_group != handle.process_group
    ):
        raise RuntimeError("child_ownership_unverified")


def signal_child(handle: ChildHandle, signal: int) -> None:
    # signal.SIGKILL and friends are IntEnum members, so an exact `type(...) is int` check
    # rejects every real signal; validate the value domain instead.
    if isinstance(signal, bool) or signal <= 0:
        raise TypeError("child_signal_invalid")
    _verify_owned_group(handle)
    os.killpg(handle.process_group, signal)


def close_stdin(handle: ChildHandle) -> None:
    stream = handle.process.stdin
    if stream is not None and not stream.closed:
        stream.close()


def terminate_owned_group(handle: ChildHandle) -> None:
    if handle.process.poll() is not None:
        return
    _verify_owned_group(handle)
    os.killpg(handle.process_group, signal_module.SIGTERM)
    try:
        handle.process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        _verify_owned_group(handle)
        os.killpg(handle.process_group, signal_module.SIGKILL)


def assert_no_source_import(result: ChildResult, checkout_root: Path) -> None:
    marker = str(checkout_root.resolve()).encode("utf-8")
    if marker in result.stdout or marker in result.stderr:
        raise AssertionError("checkout_path_observed")


def assert_no_owned_children(temp_root: Path) -> None:
    marker_path = temp_root / _OWNER_MARKER
    if not marker_path.exists():
        return
    marker = json.loads(marker_path.read_text(encoding="ascii"))
    process_group = marker.get("pgid")
    if type(process_group) is not int:
        raise AssertionError("child_marker_invalid")
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        marker_path.unlink(missing_ok=True)
        return
    except PermissionError as exc:
        raise AssertionError("owned_child_unverifiable") from exc
    raise AssertionError("owned_child_survived")
