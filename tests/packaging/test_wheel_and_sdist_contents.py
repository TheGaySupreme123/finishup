"""Wheel/sdist member allowlist, metadata, RECORD, and rebuild-equivalence gate.

Parses the built wheel ZIP and sdist tarball without unsafe extraction, compares their member
inventories to exact allowlists, validates distribution metadata, and proves the sdist can rebuild
a candidate-equivalent wheel offline.
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from pathlib import Path
from typing import Final, cast

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_BUILD_TIMEOUT: Final = 120

_FORBIDDEN_NAME_MARKERS: Final = (
    "test",
    ".git",
    ".env",
    "__pycache__",
    ".pyc",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".sqlite",
    ".db",
    "-wal",
    "-shm",
    ".map",
    ".claude",
    "CLAUDE.md",
)
_NATIVE_BINARY_SUFFIXES: Final = (".so", ".pyd", ".dylib", ".dll")


def _is_attestation_schema_member(name: str) -> bool:
    """The reviewed attestation schema contains ``test`` in ``attestation``."""

    return name in {
        "yoetz/resources/schemas/consent/chat-user-attestation-1.0.0.schema.json",
        "src/yoetz/resources/schemas/consent/chat-user-attestation-1.0.0.schema.json",
    }


def _is_test_edit_visibility_module(name: str) -> bool:
    """The reviewed runtime module that classifies test-file edits is named for its subject."""

    return name in {
        "yoetz/kernel/test_edit_visibility.py",
        "src/yoetz/kernel/test_edit_visibility.py",
    }


def _is_reviewed_name_exemption(name: str) -> bool:
    return _is_attestation_schema_member(name) or _is_test_edit_visibility_module(name)


def _load_pyproject() -> dict[str, object]:
    with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _project_table() -> dict[str, object]:
    return cast(dict[str, object], _load_pyproject()["project"])


def _project_name_and_version() -> tuple[str, str]:
    project = _project_table()
    name = cast(str, project["name"])
    version = cast(str, project["version"])
    return name, version


@dataclass(frozen=True, slots=True)
class Candidate:
    out_dir: Path
    sdist: Path
    wheel: Path


@pytest.fixture(scope="module")
def candidate(tmp_path_factory: pytest.TempPathFactory) -> Candidate:
    out_dir = tmp_path_factory.mktemp("wheel-sdist-contents")
    environment = dict(os.environ)
    environment["TZ"] = "UTC"
    environment["LC_ALL"] = "C"
    environment["SOURCE_DATE_EPOCH"] = "1700000000"
    subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local uv binary
        [
            "uv",
            "build",
            "--no-sources",
            "--offline",
            "--no-create-gitignore",
            "--clear",
            "-o",
            str(out_dir),
        ],
        cwd=_REPO_ROOT,
        env=environment,
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    entries = sorted(out_dir.iterdir())
    sdists = [entry for entry in entries if entry.name.endswith(".tar.gz")]
    wheels = [entry for entry in entries if entry.name.endswith(".whl")]
    assert len(sdists) == 1
    assert len(wheels) == 1
    return Candidate(out_dir=out_dir, sdist=sdists[0], wheel=wheels[0])


# --------------------------------------------------------------------------
# Safe member enumeration
# --------------------------------------------------------------------------


def _is_safe_member_path(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    if ".." in path.split("/"):
        return False
    return not any(ord(char) < 0x20 for char in path)


def _wheel_file_members(wheel_path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with zipfile.ZipFile(wheel_path) as archive:
        for info in archive.infolist():
            if info.filename.endswith("/"):
                continue
            assert _is_safe_member_path(info.filename), f"unsafe member path {info.filename!r}"
            is_symlink = (info.external_attr >> 16) & 0o170000 == 0o120000
            assert not is_symlink, f"symlink member {info.filename!r} is forbidden"
            members[info.filename] = archive.read(info)
    return members


def _sdist_file_members(sdist_path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with tarfile.open(sdist_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            assert _is_safe_member_path(member.name), f"unsafe member path {member.name!r}"
            assert not (member.issym() or member.islnk() or member.isdev()), (
                f"link/device member {member.name!r} is forbidden"
            )
            extracted = archive.extractfile(member)
            assert extracted is not None
            members[member.name] = extracted.read()
    return members


def _case_collisions(names: list[str]) -> list[str]:
    seen: dict[str, str] = {}
    collisions: list[str] = []
    for name in names:
        folded = name.casefold()
        if folded in seen and seen[folded] != name:
            collisions.append(name)
        seen.setdefault(folded, name)
    return collisions


# --------------------------------------------------------------------------
# Wheel member allowlist
# --------------------------------------------------------------------------


def _classify_wheel_member(name: str, *, dist_info_prefix: str) -> str:
    if name.startswith(dist_info_prefix):
        rest = name[len(dist_info_prefix) :]
        if rest in {"METADATA", "RECORD", "WHEEL", "entry_points.txt"}:
            return "dist_info_core"
        if rest.startswith("licenses/"):
            return "dist_info_license"
        return "unexpected"
    if name == "yoetz/py.typed":
        return "py_typed"
    if name.startswith("yoetz/resources/"):
        return "package_resource"
    if name.startswith("yoetz/") and name.endswith(".py"):
        return "package_python"
    return "unexpected"


def test_wheel_member_inventory_matches_the_exact_allowlist(candidate: Candidate) -> None:
    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)

    unexpected = [
        member_name
        for member_name in members
        if _classify_wheel_member(member_name, dist_info_prefix=dist_info_prefix) == "unexpected"
    ]
    assert not unexpected, f"unexpected wheel members: {unexpected}"

    for member_name in members:
        lowered = member_name.lower()
        if not _is_reviewed_name_exemption(lowered):
            assert not any(marker in lowered for marker in _FORBIDDEN_NAME_MARKERS), member_name
        assert not lowered.endswith(_NATIVE_BINARY_SUFFIXES), member_name


def test_wheel_contains_exactly_one_package_console_entry_and_py_typed(
    candidate: Candidate,
) -> None:
    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)

    top_level_packages = {
        member_name.split("/", 1)[0]
        for member_name in members
        if not member_name.startswith(dist_info_prefix)
    }
    assert top_level_packages == {"yoetz"}
    assert "yoetz/py.typed" in members

    entry_points = members[f"{dist_info_prefix}entry_points.txt"].decode("utf-8")
    assert "[console_scripts]" in entry_points
    assert "yoetz = yoetz.cli.entry:main" in entry_points


def test_wheel_contains_portable_plugin_sources_and_exact_vendored_schemas(
    candidate: Candidate,
) -> None:
    members = _wheel_file_members(candidate.wheel)
    expected = {
        "yoetz/resources/skills/portable/yoetz/SKILL.md",
        "yoetz/resources/support/agent-plugins/1.0.0/mcp.schema.json",
        "yoetz/resources/support/agent-plugins/1.0.0/plugin.schema.json",
    }
    assert expected <= set(members)
    assert (
        hashlib.sha256(
            members["yoetz/resources/support/agent-plugins/1.0.0/plugin.schema.json"]
        ).hexdigest()
        == "0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883"
    )
    assert (
        hashlib.sha256(
            members["yoetz/resources/support/agent-plugins/1.0.0/mcp.schema.json"]
        ).hexdigest()
        == "6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb"
    )


def test_wheel_member_names_have_no_duplicate_or_case_collision(candidate: Candidate) -> None:
    with zipfile.ZipFile(candidate.wheel) as archive:
        names = [info.filename for info in archive.infolist() if not info.filename.endswith("/")]
    assert len(names) == len(set(names)), "duplicate wheel member name"
    assert not _case_collisions(names), "case-colliding wheel member names"


def test_wheel_record_hashes_and_sizes_match_every_member(candidate: Candidate) -> None:
    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)
    record_text = members[f"{dist_info_prefix}RECORD"].decode("utf-8")

    record_rows: dict[str, tuple[str, str]] = {}
    for line in record_text.splitlines():
        if not line:
            continue
        path, digest_field, size_field = line.rsplit(",", 2)
        record_rows[path] = (digest_field, size_field)

    record_path = f"{dist_info_prefix}RECORD"
    assert record_rows[record_path] == ("", "")

    covered = set(record_rows) - {record_path}
    assert covered == set(members) - {record_path}, "RECORD does not cover every wheel member"

    for path, data in members.items():
        if path == record_path:
            continue
        digest_field, size_field = record_rows[path]
        algorithm, encoded = digest_field.split("=", 1)
        assert algorithm == "sha256"
        padded = encoded + "=" * (-len(encoded) % 4)
        expected_digest = base64.urlsafe_b64decode(padded)
        assert hashlib.sha256(data).digest() == expected_digest, f"RECORD hash mismatch: {path}"
        assert int(size_field) == len(data), f"RECORD size mismatch: {path}"


def test_wheel_metadata_matches_declared_project_identity(candidate: Candidate) -> None:
    project = _project_table()
    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)
    metadata = BytesParser(policy=compat32).parsebytes(members[f"{dist_info_prefix}METADATA"])

    assert metadata["Name"] == name
    assert metadata["Version"] == version
    assert metadata["Summary"] == project["description"]
    assert metadata["License-Expression"] == project["license"]

    declared_requires_python = str(project["requires-python"]).replace(" ", "")
    reported_requires_python = str(metadata["Requires-Python"]).replace(" ", "")
    assert reported_requires_python == declared_requires_python

    direct_dependencies = cast(list[str], project["dependencies"])
    requires_dist = metadata.get_all("Requires-Dist") or []
    unconditional = [entry for entry in requires_dist if ";" not in entry]
    assert sorted(unconditional) == sorted(direct_dependencies)

    optional = cast(dict[str, list[str]], project.get("optional-dependencies", {}))
    provides_extra = set(metadata.get_all("Provides-Extra") or [])
    assert provides_extra == set(optional)
    for extra_name, extra_deps in optional.items():
        for dependency in extra_deps:
            assert f"{dependency} ; extra == '{extra_name}'" in requires_dist


def test_wheel_metadata_authors_and_urls_never_exceed_declared_project_facts(
    candidate: Candidate,
) -> None:
    """Packaged metadata must not assert authorship/URL claims beyond what ``pyproject.toml``
    declares: an undeclared field must stay absent rather than being fabricated at build time.
    """

    project = _project_table()
    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)
    metadata = BytesParser(policy=compat32).parsebytes(members[f"{dist_info_prefix}METADATA"])

    declared_urls = cast(dict[str, str], project.get("urls", {}))
    reported_urls = metadata.get_all("Project-URL") or []
    assert len(reported_urls) == len(declared_urls)
    for label, url in declared_urls.items():
        assert f"{label}, {url}" in reported_urls

    declared_authors = cast(list[object], project.get("authors", []))
    if not declared_authors:
        assert metadata["Author"] is None
        assert metadata["Author-email"] is None


def test_wheel_wheel_file_declares_pure_python_universal_tag(candidate: Candidate) -> None:
    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)
    wheel_metadata = BytesParser(policy=compat32).parsebytes(members[f"{dist_info_prefix}WHEEL"])

    assert wheel_metadata["Root-Is-Purelib"] == "true"
    assert wheel_metadata["Tag"] == "py3-none-any"


def test_wheel_has_no_local_direct_url_or_private_index_reference(candidate: Candidate) -> None:
    members = _wheel_file_members(candidate.wheel)
    for path, data in members.items():
        if path.endswith(("METADATA", "RECORD", "WHEEL")):
            text = data.decode("utf-8", errors="strict")
            assert "file://" not in text
            assert str(_REPO_ROOT) not in text


def test_wheel_ships_an_approved_dist_info_license_file(candidate: Candidate) -> None:
    """LICENSE.md: the license file must accompany the installable wheel, not just the metadata
    ``License-Expression`` field.
    """

    name, version = _project_name_and_version()
    dist_info_prefix = f"{name}-{version}.dist-info/"
    members = _wheel_file_members(candidate.wheel)
    license_members = [
        member_name
        for member_name in members
        if member_name.startswith(f"{dist_info_prefix}licenses/")
    ]
    assert license_members, "no dist-info license file is bundled in the wheel"


# --------------------------------------------------------------------------
# Sdist member allowlist
# --------------------------------------------------------------------------


def test_sdist_member_inventory_matches_the_exact_allowlist(candidate: Candidate) -> None:
    name, version = _project_name_and_version()
    prefix = f"{name}-{version}/"
    members = _sdist_file_members(candidate.sdist)

    allowed_top_level_files = {"PKG-INFO", "README.md", "pyproject.toml", "LICENSE"}
    for member_name in members:
        assert member_name.startswith(prefix), member_name
        rest = member_name[len(prefix) :]
        lowered = rest.lower()
        if not _is_reviewed_name_exemption(lowered):
            assert not any(marker in lowered for marker in _FORBIDDEN_NAME_MARKERS), member_name
        assert not lowered.endswith(_NATIVE_BINARY_SUFFIXES), member_name
        if "/" not in rest:
            assert rest in allowed_top_level_files, f"unexpected top-level sdist file: {rest}"
        else:
            assert rest.startswith("src/yoetz/"), f"unexpected sdist path: {rest}"


def test_sdist_ships_the_license_file(candidate: Candidate) -> None:
    """LICENSE.md: the license file must be present in the source distribution."""

    name, version = _project_name_and_version()
    prefix = f"{name}-{version}/"
    members = _sdist_file_members(candidate.sdist)
    assert f"{prefix}LICENSE" in members, "sdist does not contain a top-level LICENSE file"


def test_sdist_member_names_have_no_duplicate_or_case_collision(candidate: Candidate) -> None:
    with tarfile.open(candidate.sdist, mode="r:gz") as archive:
        names = [member.name for member in archive.getmembers() if not member.isdir()]
    assert len(names) == len(set(names)), "duplicate sdist member name"
    assert not _case_collisions(names), "case-colliding sdist member names"


def test_sdist_pkg_info_matches_wheel_metadata_identity(candidate: Candidate) -> None:
    name, version = _project_name_and_version()
    prefix = f"{name}-{version}/"
    sdist_members = _sdist_file_members(candidate.sdist)
    pkg_info = BytesParser(policy=compat32).parsebytes(sdist_members[f"{prefix}PKG-INFO"])

    dist_info_prefix = f"{name}-{version}.dist-info/"
    wheel_members = _wheel_file_members(candidate.wheel)
    metadata = BytesParser(policy=compat32).parsebytes(wheel_members[f"{dist_info_prefix}METADATA"])

    assert pkg_info["Name"] == metadata["Name"]
    assert pkg_info["Version"] == metadata["Version"]
    assert pkg_info["License-Expression"] == metadata["License-Expression"]


def test_sdist_rebuilds_a_candidate_equivalent_wheel_offline(
    candidate: Candidate, tmp_path_factory: pytest.TempPathFactory
) -> None:
    extract_dir = tmp_path_factory.mktemp("sdist-extract")
    with tarfile.open(candidate.sdist, mode="r:gz") as archive:
        archive.extractall(extract_dir, filter="data")

    name, version = _project_name_and_version()
    source_dir = extract_dir / f"{name}-{version}"
    rebuild_out = tmp_path_factory.mktemp("sdist-rebuild")
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
            str(rebuild_out),
        ],
        cwd=source_dir,
        env=environment,
        capture_output=True,
        check=True,
        timeout=_BUILD_TIMEOUT,
    )
    rebuilt_wheels = [entry for entry in rebuild_out.iterdir() if entry.name.endswith(".whl")]
    assert len(rebuilt_wheels) == 1
    assert rebuilt_wheels[0].read_bytes() == candidate.wheel.read_bytes()


# --------------------------------------------------------------------------
# Synthetic mutation fixtures: prove the allowlist/safety predicates reject bad input
# --------------------------------------------------------------------------


def _write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        for member_name, data in members.items():
            archive.writestr(member_name, data)


@pytest.mark.parametrize(
    "bad_path",
    [
        "../escape.py",
        "/absolute.py",
        "yoetz\\backslash.py",
        "yoetz/nested/../../escape.py",
    ],
)
def test_unsafe_member_path_is_rejected(bad_path: str) -> None:
    assert not _is_safe_member_path(bad_path)


def test_traversal_member_in_a_synthetic_wheel_is_rejected(tmp_path: Path) -> None:
    bad_wheel = tmp_path / "bad.whl"
    _write_zip(bad_wheel, {"../escape.py": b"x"})
    with pytest.raises(AssertionError):
        _wheel_file_members(bad_wheel)


def test_duplicate_and_case_collision_detection() -> None:
    assert _case_collisions(["yoetz/a.py", "yoetz/A.py"]) == ["yoetz/A.py"]
    assert _case_collisions(["yoetz/a.py", "yoetz/b.py"]) == []


def test_unexpected_top_level_package_is_rejected() -> None:
    assert _classify_wheel_member("evil/module.py", dist_info_prefix="yoetz-0.1.0.dist-info/") == (
        "unexpected"
    )


def test_native_binary_suffix_is_flagged_by_the_forbidden_check() -> None:
    assert "yoetz/_native.so".lower().endswith(_NATIVE_BINARY_SUFFIXES)
    assert not "yoetz/pure.py".lower().endswith(_NATIVE_BINARY_SUFFIXES)


def test_forbidden_name_marker_catches_test_and_cache_paths() -> None:
    for marker_path in (
        "yoetz/tests/test_x.py",
        "yoetz/__pycache__/x.pyc",
        "yoetz/.git/HEAD",
        ".claude/settings.json",
    ):
        lowered = marker_path.lower()
        assert any(marker in lowered for marker in _FORBIDDEN_NAME_MARKERS)


def test_attestation_schema_exemption_is_exactly_archive_scoped() -> None:
    assert _is_attestation_schema_member(
        "yoetz/resources/schemas/consent/chat-user-attestation-1.0.0.schema.json"
    )
    assert _is_attestation_schema_member(
        "src/yoetz/resources/schemas/consent/chat-user-attestation-1.0.0.schema.json"
    )
    assert not _is_attestation_schema_member(
        "tests/fixtures/chat-user-attestation-1.0.0.schema.json"
    )


def test_test_edit_visibility_exemption_is_exactly_archive_scoped() -> None:
    assert _is_reviewed_name_exemption("yoetz/kernel/test_edit_visibility.py")
    assert _is_reviewed_name_exemption("src/yoetz/kernel/test_edit_visibility.py")
    assert not _is_reviewed_name_exemption("yoetz/kernel/test_edit_visibility_extra.py")
    assert not _is_reviewed_name_exemption("tests/unit/kernel/test_edit_visibility.py")
