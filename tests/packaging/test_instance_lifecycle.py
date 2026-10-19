"""One permanent install plus concurrent pinned test snapshots from two revisions (issue #604).

Proves the documented contributor workflow end to end against real installed launchers: a
synthetic everyday (ambient) installation and two disposable snapshots provisioned by
``scripts/provision_test_instance.py`` from two different source revisions run at the same time,
each with its own runtime, service singleton, endpoint, and state; a snapshot launched without
``FINISHUP_ISOLATED_ROOT`` resolves its own root through the runtime pin and never the ambient
install; a conflicting environment fails closed; a re-pointed pin refuses to serve; restarting one
snapshot leaves the others untouched; disposing one snapshot stops only its service and leaves the
other instances' identity records byte-identical and their services reachable; and disposal is
safe to repeat.

The vault of a fresh instance is uninitialized, so the six operations answer with their bounded
documented refusals here, as in ``test_clean_install.py``; an unlocked flow needs the trusted
console ceremony and is not fabricated. Like the rest of ``tests/packaging``, this spawns real
CLIs against install roots under ``~/.yz-*`` and must not run concurrently with another pytest
run.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_SCRIPT: Final = _REPO_ROOT / "scripts" / "provision_test_instance.py"
_BOUNDED_EXIT_CODES: Final = frozenset({0, 2, 10, 11, 20, 30, 40, 70, 130})
_IDENTITY_RECORDS: Final = ("service.lock", "service-generation.json", "instance-identity.json")


def _is_advertised_host() -> bool:
    if sys.platform == "darwin":
        return platform.machine() == "arm64"
    if sys.platform.startswith("linux"):
        return platform.machine() in {"x86_64", "amd64"}
    return False


pytestmark = pytest.mark.skipif(
    not _is_advertised_host(),
    reason="only the v0.1 advertised macOS arm64 / manylinux_2_28 x86-64 cells are certified",
)


def _real_cache_dir() -> str:
    result = subprocess.run(["uv", "cache", "dir"], capture_output=True, timeout=15, check=False)
    return result.stdout.decode("utf-8").strip()


def _short_home(tag: str) -> Path:
    # AF_UNIX socket paths beneath every root must stay well under the sockaddr_un limit, contain
    # no symlink component, and avoid shared temp; the real home is the one such place. Disposable.
    base = Path.home() / f".yz-{tag}"
    base.mkdir(mode=0o700, exist_ok=True)
    root = base / secrets.token_hex(3)
    root.mkdir(mode=0o700)
    (root / "h").mkdir(mode=0o700)
    return root


def _clean_env(home: Path) -> dict[str, str]:
    env = {name: value for name, value in os.environ.items() if not name.startswith("FINISHUP_")}
    env["HOME"] = str(home)
    env["UV_CACHE_DIR"] = _real_cache_dir()
    env["UV_PYTHON_DOWNLOADS"] = "never"
    return env


def _tool_install(dist_dir: Path, root: Path, home: Path) -> tuple[Path, dict[str, str]]:
    tool_dir = root / "tool"
    bin_dir = root / "bin"
    env = {**_clean_env(home), "UV_TOOL_DIR": str(tool_dir), "UV_TOOL_BIN_DIR": str(bin_dir)}

    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1

    def _install(offline: bool) -> subprocess.CompletedProcess[bytes]:
        args = ["uv", "tool", "install", "--python", sys.executable]
        if offline:
            args.append("--offline")
        args += ["--find-links", str(dist_dir), str(wheels[0])]
        return subprocess.run(args, capture_output=True, timeout=180, env=env, check=False)

    result = _install(offline=True)
    if result.returncode != 0:
        result = _install(offline=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return bin_dir / "finishup", env


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dist_dir = tmp_path_factory.mktemp("instance-lifecycle-dist")
    result = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert len(sorted(dist_dir.glob("*.whl"))) == 1
    return dist_dir


def _second_revision(destination: Path) -> str:
    """A genuinely different commit carrying this working tree plus one extra README line."""

    listed = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "ls-files", "-co", "--exclude-standard", "-z"],
        capture_output=True,
        timeout=60,
        check=True,
    )
    destination.mkdir(mode=0o700)
    for relative in listed.stdout.decode("utf-8").split("\0"):
        if not relative:
            continue
        source = _REPO_ROOT / relative
        if not source.is_file() or source.is_symlink():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    with (destination / "README.md").open("a", encoding="utf-8") as readme:
        readme.write("\n<!-- issue 604 second-revision marker -->\n")
    git = [
        "git",
        "-C",
        str(destination),
        "-c",
        "user.name=finishup-test",
        "-c",
        "user.email=t@e.invalid",
    ]
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "test: second revision"]):
        subprocess.run([*git, *args], capture_output=True, timeout=120, check=True)
    head = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, timeout=30, check=True)
    return head.stdout.decode("ascii").strip()


def _provision(base: Path, tag: str, checkout: Path, env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "create",
            "--base",
            str(base),
            "--tag",
            tag,
            "--checkout",
            str(checkout),
            "--python",
            sys.executable,
            "--lifecycle",
            "disposable",
            "--expires-in",
            "2",
            "--allow-dirty",
            "--json",
        ],
        capture_output=True,
        timeout=600,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return cast(dict[str, object], json.loads(result.stdout))


def _dispose(base: Path, tag: str, env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "dispose", "--base", str(base), "--tag", tag, "--json"],
        capture_output=True,
        timeout=120,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return cast(dict[str, object], json.loads(result.stdout))


def _cli(
    launcher: Path, args: list[str], env: dict[str, str]
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(launcher), *args], capture_output=True, timeout=30, env=env, check=False
    )


def _json(launcher: Path, args: list[str], env: dict[str, str]) -> dict[str, object]:
    result = _cli(launcher, [*args, "--json"], env)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return cast(dict[str, object], json.loads(result.stdout))


def _start_service(launcher: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(
        [str(launcher), "service", "run"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"service exited during startup with {proc.returncode}")
        if _cli(launcher, ["service", "status", "--json"], env).returncode == 0:
            return proc
        time.sleep(0.2)
    proc.terminate()
    raise AssertionError("service did not become reachable in time")


def _stop_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _identity_snapshot(state: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for name in _IDENTITY_RECORDS:
        path = state / name
        if path.is_file():
            snapshot[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _bounded_six_operation_probe(launcher: Path, env: dict[str, str]) -> None:
    request = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": f"req_{uuid.uuid4()}",
        "mode": "create",
        "task_title": "instance lifecycle probe",
        "actor": {"actor_id": "packaging.instance-lifecycle", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
        "requested_view": "compact",
    }
    result = _cli(launcher, ["start", "--request", json.dumps(request), "--json"], env)
    assert result.returncode in _BOUNDED_EXIT_CODES
    assert b"Traceback (most recent call last)" not in result.stderr


def test_permanent_install_and_two_pinned_snapshots_coexist_and_dispose_independently(
    built_dist: Path,
) -> None:
    cell = _short_home("inst604")
    services: list[subprocess.Popen[bytes]] = []
    base = cell / "i"
    try:
        home = cell / "h"
        env = _clean_env(home)
        permanent_exe, permanent_env = _tool_install(built_dist, cell, home)
        second_sha = _second_revision(cell / "rev2")
        first_sha = (
            subprocess.run(
                ["git", "-C", str(_REPO_ROOT), "rev-parse", "HEAD"], capture_output=True, check=True
            )
            .stdout.decode("ascii")
            .strip()
        )
        assert first_sha != second_sha

        a = _provision(base, "a", _REPO_ROOT, env)
        b = _provision(base, "b", cell / "rev2", env)
        a_exe, b_exe = Path(cast(str, a["launcher"])), Path(cast(str, b["launcher"]))
        a_state, b_state = base / "a" / "state", base / "b" / "state"
        assert a["source_ref"] == first_sha and b["source_ref"] == second_sha
        assert a["package_digest"] != b["package_digest"]
        assert a["installation_id"] != b["installation_id"]
        assert (base / "a" / "runtime" / "yoetz-instance-pin.json").is_file()

        # Snapshots run WITHOUT the variable: the pin alone must select their root.
        services.append(_start_service(permanent_exe, permanent_env))
        services.append(_start_service(a_exe, env))
        services.append(_start_service(b_exe, env))

        reports = {
            "permanent": _json(permanent_exe, ["service", "isolation"], permanent_env),
            "a": _json(a_exe, ["service", "isolation"], env),
            "b": _json(b_exe, ["service", "isolation"], env),
        }
        assert reports["permanent"]["mode"] == "ambient"
        assert reports["permanent"]["binding"] == "ambient"
        assert reports["permanent"]["lifecycle"] == "permanent"
        for name in ("a", "b"):
            assert reports[name]["mode"] == "isolated"
            assert reports[name]["binding"] == "runtime_pin"
            assert reports[name]["lifecycle"] == "disposable"
        digests = {
            name: cast(dict[str, str], report["path_identity"]) for name, report in reports.items()
        }
        for key in (
            "state_path_digest",
            "endpoint_path_digest",
            "storage_path_digest",
            "executable_path_digest",
        ):
            assert len({digest[key] for digest in digests.values()}) == 3, key
        for state in (a_state, b_state):
            assert (state / "state" / "service.lock").is_file()
            assert (state / "run" / "control.sock").is_socket()
        assert (
            home / "Library" / "Caches" / "TemporaryItems" / "finishup" / "control.sock"
        ).is_socket() or (sys.platform.startswith("linux"))
        stamp = json.loads((a_state / "state" / "service.lock").read_bytes())
        assert stamp["instance_lifecycle"] == "disposable"
        assert stamp["source_ref"] == first_sha

        status_a = _json(a_exe, ["instance", "status"], env)
        assert status_a["binding"] == "runtime_pin"
        assert status_a["source_ref"] == first_sha
        assert status_a["runtime_provenance"] == "matched"
        assert status_a["expired"] is False
        assert (
            cast(dict[str, object], status_a["service_holder"])["instance_lifecycle"]
            == "disposable"
        )
        assert str(a_state) not in json.dumps(status_a)
        status_b = _json(b_exe, ["instance", "status"], env)
        assert status_b["source_ref"] == second_sha
        assert status_b["installation_id"] != status_a["installation_id"]

        # A conflicting environment fails closed: snapshot a's runtime never serves b's root.
        conflict = _cli(
            a_exe,
            ["service", "isolation", "--json"],
            {**env, "FINISHUP_ISOLATED_ROOT": str(b_state)},
        )
        assert conflict.returncode == 2
        assert b"isolation_invalid: isolation_root_conflict" in conflict.stderr

        # Each instance answers the workflow honestly from its own record (vault uninitialized).
        for launcher, launch_env in ((permanent_exe, permanent_env), (a_exe, env), (b_exe, env)):
            _bounded_six_operation_probe(launcher, launch_env)

        before = {
            "permanent": _json(permanent_exe, ["service", "status"], permanent_env),
            "a": _json(a_exe, ["service", "status"], env),
            "b": _json(b_exe, ["service", "status"], env),
        }
        assert len({cast(str, status["service_instance_id"]) for status in before.values()}) == 3

        # Restart b: stop its foreground service, prove a re-pointed pin refuses to serve, restore
        # the pin, then restart through b's own runtime; a and the permanent install stay put.
        _stop_process(services.pop())
        pin_path = base / "b" / "runtime" / "yoetz-instance-pin.json"
        original_pin = pin_path.read_bytes()
        forged = json.loads(original_pin)
        forged["installation_id"] = f"ins_{uuid.uuid4()}"
        pin_path.write_bytes(
            json.dumps(forged, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        refused = _cli(b_exe, ["service", "run"], env)
        assert refused.returncode == 20
        # Startup diagnostics may precede the typed CLI refusal (#1040).
        assert any(
            line.startswith(b"installation_identity_mismatch:")
            for line in refused.stderr.splitlines()
        )
        assert b"Traceback" not in refused.stderr
        pin_path.write_bytes(original_pin)
        restarted = _json(b_exe, ["service", "restart"], env)
        assert int(cast(str, restarted["service_generation"])) > int(
            cast(str, before["b"]["service_generation"])
        )
        for name, launcher, launch_env in (
            ("permanent", permanent_exe, permanent_env),
            ("a", a_exe, env),
        ):
            after = _json(launcher, ["service", "status"], launch_env)
            assert after["service_instance_id"] == before[name]["service_instance_id"]
            assert after["service_generation"] == before[name]["service_generation"]

        # Dispose a: only a's service stops, only a's tree disappears, only a's pin goes.
        permanent_state = home / "Library" / "Application Support" / "finishup"
        if sys.platform.startswith("linux"):
            permanent_state = home / ".local" / "state" / "finishup"
        permanent_before = _identity_snapshot(permanent_state)
        b_before = _identity_snapshot(b_state / "state")
        a_service = services.pop()
        disposed = _dispose(base, "a", env)
        assert disposed["state"] == "removed"
        instance_outcome = cast(dict[str, object], disposed["instance"])
        assert instance_outcome["service_stopped"] is True
        assert instance_outcome["runtime_pin_removed"] is True
        assert a_service.wait(timeout=40) is not None
        assert not (base / "a").exists()
        assert _identity_snapshot(permanent_state) == permanent_before
        assert _identity_snapshot(b_state / "state") == b_before
        assert (
            _json(permanent_exe, ["service", "status"], permanent_env)["service_instance_id"]
            == (before["permanent"]["service_instance_id"])
        )
        assert (
            _json(b_exe, ["service", "status"], env)["service_instance_id"]
            == (restarted["service_instance_id"])
        )

        again = _dispose(base, "a", env)
        assert again == {"tag": "a", "state": "absent", "disposed": False}

        # b's restarted service is detached; its own runtime stops it before disposal.
        stopped = _cli(b_exe, ["service", "stop"], env)
        assert stopped.returncode in _BOUNDED_EXIT_CODES
        assert _dispose(base, "b", env)["state"] == "removed"
        assert not (base / "b").exists()
        assert _json(permanent_exe, ["service", "status"], permanent_env)["state"] in {
            "locked",
            "ready",
        }
    finally:
        for proc in services:
            _stop_process(proc)
        for tag in ("a", "b"):
            if (base / tag).exists():
                subprocess.run(
                    [sys.executable, str(_SCRIPT), "dispose", "--base", str(base), "--tag", tag],
                    capture_output=True,
                    timeout=120,
                    env={
                        name: value
                        for name, value in os.environ.items()
                        if not name.startswith("FINISHUP_")
                    },
                    check=False,
                )
        shutil.rmtree(cell.parent, ignore_errors=True)
