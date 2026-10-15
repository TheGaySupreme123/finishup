"""Installed version/provenance truthfulness of ``finishup version --json``.

Builds the candidate wheel, installs it into a clean isolated tool environment (never the
development checkout via ``PYTHONPATH``), and invokes the installed console script and module
entry from an unrelated working directory with no ambient checkout/private paths. Compares
reported identities to independently probed facts: the source resource manifest, the pinned
project metadata, and the installed environment's own package versions.
"""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_BUILD_TIMEOUT: Final = 120
_RUN_TIMEOUT: Final = 15


def _load_pyproject() -> dict[str, object]:
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _project_version() -> str:
    project = cast(dict[str, object], _load_pyproject()["project"])
    return cast(str, project["version"])


def _source_resource_manifest() -> Any:  # raw JSON document, deliberately untyped
    manifest_path = _REPO_ROOT / "src" / "finishup" / "resources" / "manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


@dataclass(frozen=True, slots=True)
class InstalledCandidate:
    venv_dir: Path
    python: Path
    finishup: Path
    unrelated_cwd: Path


@pytest.fixture(scope="module")
def installed_candidate(tmp_path_factory: pytest.TempPathFactory) -> InstalledCandidate:
    build_out = tmp_path_factory.mktemp("version-manifest-build")
    environment = dict(os.environ)
    environment["TZ"] = "UTC"
    environment["LC_ALL"] = "C"
    environment["SOURCE_DATE_EPOCH"] = "1700000000"
    subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local uv binary
        [
            "uv",
            "build",
            "--wheel",
            "--no-sources",
            "--offline",
            "--no-create-gitignore",
            "-o",
            str(build_out),
        ],
        cwd=_REPO_ROOT,
        env=environment,
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    wheels = [entry for entry in build_out.iterdir() if entry.name.endswith(".whl")]
    assert len(wheels) == 1
    wheel = wheels[0]

    venv_dir = tmp_path_factory.mktemp("version-manifest-venv") / "venv"
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["uv", "venv", "--python", "3.14", str(venv_dir)],
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    python = venv_dir / "bin" / "python"
    subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["uv", "pip", "install", "--python", str(python), "--offline", str(wheel)],
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    unrelated_cwd = tmp_path_factory.mktemp("version-manifest-cwd")
    return InstalledCandidate(
        venv_dir=venv_dir,
        python=python,
        finishup=venv_dir / "bin" / "finishup",
        unrelated_cwd=unrelated_cwd,
    )


def _run(
    installed: InstalledCandidate, arguments: list[str], *, module: bool = False
) -> subprocess.CompletedProcess[bytes]:
    launcher = [str(installed.python), "-m", "finishup"] if module else [str(installed.finishup)]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"}
    }
    environment["PATH"] = os.environ.get("PATH", "")
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local launcher
        [*launcher, *arguments],
        cwd=installed.unrelated_cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        check=False,
        timeout=_RUN_TIMEOUT,
    )


def test_plain_version_reports_the_exact_installed_package_version(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version"])
    assert completed.returncode == 0
    assert completed.stdout.decode("utf-8").strip() == _project_version()
    assert completed.stderr == b""


def test_json_version_is_strict_compact_canonical_json(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    assert completed.returncode == 0
    assert completed.stdout.endswith(b"\n")
    payload = completed.stdout[:-1]
    assert b"\r" not in payload
    parsed = json.loads(payload)
    assert isinstance(parsed, dict)
    # Canonical JSON is compact (no incidental whitespace) and key-sorted.
    assert json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode("utf-8") == payload


def test_json_version_package_identity_matches_pinned_project_metadata(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    manifest = json.loads(completed.stdout)
    assert manifest["package_name"] == "finishup"
    assert manifest["package_version"] == _project_version()


def test_json_version_resource_digest_matches_the_source_manifest(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    manifest = json.loads(completed.stdout)
    source_manifest = _source_resource_manifest()

    assert manifest["resource_manifest_digest"] == source_manifest["resource_set_digest"]
    assert manifest["resource_counts"]["total"] == str(len(source_manifest["entries"]))


def test_default_json_reports_resource_summary_without_enumerating_entries(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    manifest = json.loads(completed.stdout)
    assert manifest["resources"] == []
    assert manifest["resource_counts"]["total"] == str(len(_source_resource_manifest()["entries"]))


def test_explicit_resources_flag_enumerates_all_reviewed_identities(
    installed_candidate: InstalledCandidate,
) -> None:
    """Per spec: explicit ``--resources`` enumerates every reviewed identity."""

    completed = _run(installed_candidate, ["version", "--json", "--resources"])
    assert completed.returncode == 0, (
        f"--resources is not implemented on the installed console script "
        f"(exit {completed.returncode}): {completed.stderr.decode('utf-8', 'replace')!r}"
    )
    manifest = json.loads(completed.stdout)
    source_manifest = _source_resource_manifest()
    assert len(manifest["resources"]) == len(source_manifest["entries"])
    reported_names = {entry["name"] for entry in manifest["resources"]}
    expected_names = {entry["logical_name"] for entry in source_manifest["entries"]}
    assert reported_names == expected_names


def test_apsw_and_sqlite_identity_matches_the_installed_environment(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    manifest = json.loads(completed.stdout)

    probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [
            str(installed_candidate.python),
            "-c",
            "import apsw, json, sys; "
            "json.dump({'version': apsw.apsw_version(), "
            "'sqlite_version': apsw.sqlitelibversion(), "
            "'source_id': apsw.sqlite3_sourceid()}, sys.stdout)",
        ],
        capture_output=True,
        check=True,
        timeout=_RUN_TIMEOUT,
    )
    probed = json.loads(probe.stdout)

    assert manifest["apsw_version"] == {"status": "present", "version": probed["version"]}
    assert manifest["sqlite_version"] == {
        "status": "present",
        "version": probed["sqlite_version"],
    }
    assert manifest["sqlite_source_id"] == {
        "status": "present",
        "source_id": probed["source_id"],
    }


def test_mcp_sdk_version_matches_the_installed_distribution(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    manifest = json.loads(completed.stdout)

    probe = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local interpreter
        [
            str(installed_candidate.python),
            "-c",
            "import importlib.metadata as m; print(m.version('mcp'))",
        ],
        capture_output=True,
        check=True,
        timeout=_RUN_TIMEOUT,
    )
    installed_mcp_version = probe.stdout.decode("utf-8").strip()
    assert manifest["mcp_sdk_version"] == {"status": "present", "version": installed_mcp_version}


def test_standard_install_contains_the_semantic_provider_adapter(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    manifest = json.loads(completed.stdout)
    adapter = manifest["provider_adapters"][0]
    assert adapter["name"] == "openai"
    assert adapter["status"] == "present"
    assert adapter["sdk_distribution"] == "openai"
    assert adapter["sdk_version"] == "2.46.0"


def test_console_and_module_json_version_are_byte_identical(
    installed_candidate: InstalledCandidate,
) -> None:
    console = _run(installed_candidate, ["version", "--json"])
    module = _run(installed_candidate, ["version", "--json"], module=True)
    assert (console.returncode, console.stdout, console.stderr) == (
        module.returncode,
        module.stdout,
        module.stderr,
    )


def test_root_version_flag_matches_the_version_subcommand(
    installed_candidate: InstalledCandidate,
) -> None:
    flag = _run(installed_candidate, ["--version"])
    subcommand = _run(installed_candidate, ["version"])
    assert (flag.returncode, flag.stdout, flag.stderr) == (
        subcommand.returncode,
        subcommand.stdout,
        subcommand.stderr,
    )


def test_json_version_output_has_no_local_path_username_or_env_leak(
    installed_candidate: InstalledCandidate,
) -> None:
    completed = _run(installed_candidate, ["version", "--json"])
    data = completed.stdout
    for forbidden in (
        str(_REPO_ROOT).encode("utf-8"),
        str(Path.home()).encode("utf-8"),
        str(installed_candidate.venv_dir).encode("utf-8"),
    ):
        assert forbidden not in data


def test_json_version_runs_quickly_from_an_unrelated_cwd_with_no_proxy_configured(
    installed_candidate: InstalledCandidate,
) -> None:
    """A fast, deterministic reply from a cwd unrelated to the checkout with proxy env vars
    stripped is the practical proxy for "no network access is required or attempted".
    """

    completed = _run(installed_candidate, ["version", "--json"])
    assert completed.returncode == 0
    assert installed_candidate.unrelated_cwd not in (_REPO_ROOT, installed_candidate.venv_dir)
