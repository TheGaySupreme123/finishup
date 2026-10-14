"""Artifact/runtime/SQLite support enforcement gate.

Installs the real built wheel and proves that ``finishup version --json`` reports the exact certified
Python/APSW/SQLite identity frozen by ADR-007's implementation lock, that the shipped APSW/SQLite
build actually performs real WAL writes/checkpoints/backups/reopens, and that a corrupted installed
resource is refused rather than silently accepted.

Scope notes (documented rather than silently narrowed):

* The suite runs on whichever ADR-007 advertised cell hosts it — macOS arm64
  (``macosx_11_0_arm64``) or glibc Linux x86-64 (``manylinux_2_28_x86_64``) — and proves only that
  cell (issue #725). The complementary advertised cell and every negative Python-patch/OS/ABI/
  filesystem mutation cell require a second real runner or fixture build that one host does not
  have (per this file's own spec: "cannot monkeypatch only reported strings; test uses real
  alternate fixture builds ... whose production denial is proven"). Those cells are skipped with an
  explicit reason rather than asserted against a fabricated environment, consistent with "Unknown
  future patch/platform is untested, not presumed compatible."
* The negative "unsafe/unknown identity fails before durable mutation" invariant is instead proven
  for real via resource-integrity corruption: flipping one byte of an installed schema resource
  after a real install makes the installed package's own manifest-verification path fail, which is
  the same mechanism ``version --json``/startup diagnostics rely on.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_PINNED_APSW_VERSION: Final = "3.53.3.1"
_PINNED_SQLITE_VERSION: Final = "3.53.3"
_PINNED_SQLITE_SOURCE_ID: Final = (
    "2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62"
)
_PINNED_PYTHON_VERSION: Final = "3.14.6"


def _is_advertised_host() -> bool:
    if sys.platform == "darwin":
        return platform.machine() == "arm64"
    if sys.platform.startswith("linux"):
        return platform.machine() in {"x86_64", "amd64"}
    return False


@dataclass(frozen=True, slots=True)
class _Installed:
    python: Path
    finishup: Path


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> _Installed:
    dist_dir = tmp_path_factory.mktemp("sqlite-gate-dist")
    build = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert build.returncode == 0, build.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist_dir.glob("*.whl"))
    assert len(wheels) == 1

    venv_dir = tmp_path_factory.mktemp("sqlite-gate-venv") / "venv"
    create = subprocess.run(
        ["uv", "venv", "--python", "3.14", str(venv_dir)],
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert create.returncode == 0, create.stderr.decode("utf-8", errors="replace")
    python_path = venv_dir / "bin" / "python"

    install = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python_path),
            "--find-links",
            str(dist_dir),
            f"finishup=={_wheel_version(wheels[0])}",
        ],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert install.returncode == 0, install.stderr.decode("utf-8", errors="replace")
    return _Installed(python=python_path, finishup=venv_dir / "bin" / "finishup")


def _wheel_version(wheel: Path) -> str:
    # finishup-0.1.0-py3-none-any.whl -> "0.1.0"
    return wheel.name.split("-")[1]


def _version_json(installed: _Installed) -> Mapping[str, object]:
    result = subprocess.run(
        [str(installed.finishup), "version", "--json"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return cast(Mapping[str, object], json.loads(result.stdout))


# ---------------------------------------------------------------------------
# Positive cell: this host
# ---------------------------------------------------------------------------


def test_this_host_is_one_of_the_two_advertised_platform_cells() -> None:
    assert _is_advertised_host(), (sys.platform, platform.machine())


def test_installed_artifact_reports_the_exact_pinned_runtime_identity(
    installed: _Installed,
) -> None:
    manifest = _version_json(installed)
    assert manifest["python_version"] == _PINNED_PYTHON_VERSION
    apsw = cast(Mapping[str, str], manifest["apsw_version"])
    sqlite = cast(Mapping[str, str], manifest["sqlite_version"])
    source_id = cast(Mapping[str, str], manifest["sqlite_source_id"])
    assert apsw["status"] == "present"
    assert apsw["version"] == _PINNED_APSW_VERSION
    assert sqlite["status"] == "present"
    assert sqlite["version"] == _PINNED_SQLITE_VERSION
    assert source_id["status"] == "present"
    assert source_id["source_id"] == _PINNED_SQLITE_SOURCE_ID


def test_installed_artifact_platform_tag_matches_the_running_host(installed: _Installed) -> None:
    manifest = _version_json(installed)
    platform_tag = cast(str, manifest["platform_tag"])
    if sys.platform == "darwin":
        assert platform_tag.startswith("macosx_")
        assert platform_tag.endswith("_arm64")
    elif sys.platform.startswith("linux"):
        assert "linux" in platform_tag


def test_sqlite_compile_options_digest_is_present_and_well_formed(installed: _Installed) -> None:
    manifest = _version_json(installed)
    digest = cast(Mapping[str, str], manifest["sqlite_compile_options_digest"])
    assert digest["status"] == "present"
    value = digest["digest"]
    assert value.startswith("sha256:")
    assert len(value) == len("sha256:") + 64


def test_version_manifest_is_internally_stable_across_two_invocations(
    installed: _Installed,
) -> None:
    first = _version_json(installed)
    second = _version_json(installed)
    assert first == second


# ---------------------------------------------------------------------------
# Positive cell: real writable SQLite/APSW behavior for the exact shipped build
# ---------------------------------------------------------------------------


def test_shipped_apsw_sqlite_build_writes_checkpoints_backs_up_and_reopens(
    installed: _Installed, tmp_path: Path
) -> None:
    probe = (
        "import apsw, pathlib, sys\n"
        "root = pathlib.Path(sys.argv[1])\n"
        "db_path = root / 'probe.sqlite3'\n"
        "conn = apsw.Connection(str(db_path))\n"
        "conn.pragma('journal_mode', 'wal')\n"
        "assert conn.pragma('journal_mode') == 'wal'\n"
        "conn.execute('create table t(id integer primary key, v text)')\n"
        "with conn:\n"
        "    for i in range(50):\n"
        "        conn.execute('insert into t(v) values (?)', (f'row-{i}',))\n"
        "conn.pragma('wal_checkpoint', 'full')\n"
        "backup_path = root / 'backup.sqlite3'\n"
        "backup_conn = apsw.Connection(str(backup_path))\n"
        "with backup_conn.backup('main', conn, 'main') as backup:\n"
        "    backup.step()\n"
        "backup_conn.close()\n"
        "conn.close()\n"
        "reopened = apsw.Connection(str(backup_path))\n"
        "count = reopened.execute('select count(*) from t').fetchall()[0][0]\n"
        "assert count == 50, count\n"
        "reopened.close()\n"
        "print('write-checkpoint-backup-reopen-ok')\n"
    )
    result = subprocess.run(
        [str(installed.python), "-c", probe, str(tmp_path)],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert b"write-checkpoint-backup-reopen-ok" in result.stdout


def test_shipped_apsw_reports_the_same_pinned_identity_directly(installed: _Installed) -> None:
    probe = (
        "import apsw, json\n"
        "print(json.dumps({\n"
        "    'apsw_version': apsw.apsw_version(),\n"
        "    'sqlite_version': apsw.sqlitelibversion(),\n"
        "    'source_id': apsw.sqlite3_sourceid(),\n"
        "}))\n"
    )
    result = subprocess.run(
        [str(installed.python), "-c", probe],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["apsw_version"] == _PINNED_APSW_VERSION
    assert payload["sqlite_version"] == _PINNED_SQLITE_VERSION
    assert payload["source_id"] == _PINNED_SQLITE_SOURCE_ID


def test_shared_network_filesystem_style_path_is_rejected_by_bundle_safety(
    installed: _Installed,
) -> None:
    # A real, exact reuse of the shipped config.paths safety gate: a path directly under the
    # process's own TMPDIR is refused as an unsafe bundle location, proving unsafe/unknown
    # locations fail before durable mutation rather than silently writing there.
    probe = (
        "from finishup.config.paths import verify_private_local_bundle, PathSafetyError\n"
        "import pathlib, os, sys\n"
        "shared = pathlib.Path(os.environ['TMPDIR']) / 'finishup-unsafe-probe'\n"
        "shared.mkdir(parents=True, exist_ok=True)\n"
        "try:\n"
        "    verify_private_local_bundle(shared)\n"
        "except PathSafetyError as exc:\n"
        "    print('rejected:' + exc.reason_code)\n"
        "    sys.exit(0)\n"
        "print('accepted')\n"
        "sys.exit(1)\n"
    )
    env = dict(os.environ)
    env["TMPDIR"] = env.get("TMPDIR", "/tmp")
    result = subprocess.run(
        [str(installed.python), "-c", probe],
        capture_output=True,
        timeout=30,
        env=env,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().startswith(b"rejected:")


# ---------------------------------------------------------------------------
# Negative cell: corrupted installed resource fails before durable mutation
# ---------------------------------------------------------------------------


def test_one_byte_resource_corruption_fails_deep_resource_verification(
    installed: _Installed, tmp_path_factory: pytest.TempPathFactory
) -> None:
    # version --json itself only re-validates the resource *manifest's* own self-consistency
    # (cheap, every invocation); the deep per-resource digest re-check that startup diagnostics
    # run is finishup.version.verify_resource_manifest / read_verified_resource. Prove that path
    # fails closed on a real one-byte corruption of a real installed resource, using a throwaway
    # copy of the already-installed venv so other tests are unaffected.
    corrupt_root = tmp_path_factory.mktemp("sqlite-gate-corrupt")
    corrupt_venv = corrupt_root / "venv"
    shutil.copytree(installed.python.parent.parent, corrupt_venv, symlinks=True)

    site_packages = next((corrupt_venv / "lib").glob("python3.14/site-packages"))
    target = (
        site_packages
        / "finishup"
        / "resources"
        / "schemas"
        / "common"
        / "frontier-1.0.0.schema.json"
    )
    assert target.is_file()
    original = target.read_bytes()
    mutated = bytearray(original)
    mutated[len(mutated) // 2] ^= 0xFF
    target.write_bytes(bytes(mutated))

    probe = (
        "from finishup.version import build_version_manifest, verify_resource_manifest\n"
        "manifest = build_version_manifest()\n"
        "results = verify_resource_manifest(manifest)\n"
        "outcomes = {r.outcome.value for r in results}\n"
        "print('outcomes:' + ','.join(sorted(outcomes)))\n"
    )
    result = subprocess.run(
        [str(corrupt_venv / "bin" / "python"), "-c", probe],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert b"outcomes:blocked" in result.stdout

    # And the same corrupted resource, read through the verified accessor directly, raises.
    direct_probe = (
        "from finishup.version import read_verified_resource, ResourceIntegrityError\n"
        "try:\n"
        "    read_verified_resource('schemas/common/frontier-1.0.0.schema.json')\n"
        "except ResourceIntegrityError as exc:\n"
        "    print('raised:' + str(exc))\n"
        "else:\n"
        "    print('accepted-corrupted-resource')\n"
    )
    direct_result = subprocess.run(
        [str(corrupt_venv / "bin" / "python"), "-c", direct_probe],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert direct_result.returncode == 0, direct_result.stderr
    assert direct_result.stdout.startswith(b"raised:")
    shutil.rmtree(corrupt_root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Negative cells requiring infrastructure unavailable to this single-host session
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _is_advertised_host(),
    reason="only meaningful as the complementary matrix cell from an advertised-cell runner",
)
@pytest.mark.skip(
    reason=(
        "The complementary advertised cell (manylinux_2_28_x86_64 from a macOS arm64 runner, "
        "macosx_11_0_arm64 from a Linux x86-64 runner) requires a second real runner. One host "
        "cannot fabricate the other via emulation/monkeypatching (spec: 'test uses real "
        "alternate fixture builds ... whose production denial is proven'). Narrowing to the "
        "available host cell is explicitly permitted by this suite's own 'narrowing support is "
        "allowed' policy."
    )
)
def test_complementary_advertised_cell_is_unavailable_on_this_runner() -> None:
    raise AssertionError("unreachable: skipped")


@pytest.mark.skip(
    reason=(
        "Wrong Python patch/distribution/OS/ABI/APSW-source-option negative cells require real "
        "alternate fixture builds (a second interpreter/OS/ABI or a differently-compiled APSW), "
        "which this single-host session cannot construct without monkeypatching reported strings "
        "-- explicitly disallowed by this file's own spec. Untested, not presumed compatible."
    )
)
def test_wrong_python_patch_or_abi_negative_cells_are_unavailable_here() -> None:
    raise AssertionError("unreachable: skipped")
