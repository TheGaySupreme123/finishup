"""Publication-boundary mutation suite for ``scripts/scan_public_boundary.py``.

Exercises the real, already-implemented boundary scanner (read-only; this file never modifies
``scripts/scan_public_boundary.py``) against synthetic clean and mutated candidates, and against
the real built wheel/sdist, to prove the ADR-007 publication invariants: every candidate member is
scanned, any match or incomplete state blocks publication, reports never reveal matched bytes/
absolute paths, and exceptions (where they exist) are exact.

Scope notes (verbatim conflicts, reported rather than guessed around):

1. The scanner has one built-in, exact source-root exception for the public ``CLAUDE.md`` alias
   whose complete bytes are ``@AGENTS.md\n``. It is not a general exception mechanism: the same
   path in an artifact, a nested alias, or any different source bytes remain blocked. The scanner
   is otherwise documented as supporting a reviewed
   per-file exception mechanism ("Allow exceptions match exact rule ID + normalized file + bounded
   digest/line context ... every exception states ... keys cannot be allowlisted"). The actual
   ``scripts/scan_public_boundary.py`` has no such mechanism: ``BoundaryRule``/``ScanReport`` carry
   no exception fields, and ``main()`` exposes only ``--rules`` (a full test-only ruleset override)
   and ``--canary-file``. The "exact reviewed exception" test case below is marked ``xfail`` with
   this exact reason instead of being invented against a nonexistent API.
2. ``enumerate_target`` does not recurse into a nested supported archive found inside a scanned
   artifact (e.g. a ``.zip`` stored as a member of the outer wheel/sdist): the nested archive's raw
   compressed bytes are scanned as one opaque content blob, so a plaintext secret placed only inside
   the nested archive is not detected. This contradicts this spec's "nested supported archive"
   mutation placement. It is demonstrated and marked ``xfail`` below as a known scanner gap.
3. Detector-constant and synthetic-fixture source text is assembled at runtime from parts so the
   publication-boundary scan of the live checkout does not treat intentional test material as a
   leaked secret. The built wheel is expected to scan clean of every boundary rule.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[2]
_SCRIPT_PATH: Final = _REPO_ROOT / "scripts" / "scan_public_boundary.py"


def _load_scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("finishup_scan_public_boundary", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def scanner() -> ModuleType:
    return _load_scanner()


@dataclass(frozen=True, slots=True)
class _BuiltDist:
    directory: Path
    wheel: Path
    sdist: Path


@pytest.fixture(scope="module")
def built_dist(tmp_path_factory: pytest.TempPathFactory) -> _BuiltDist:
    dist_dir = tmp_path_factory.mktemp("boundary-dist")
    result = subprocess.run(
        ["uv", "build", "--no-sources", "-o", str(dist_dir), str(_REPO_ROOT)],
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    return _BuiltDist(dist_dir, wheels[0], sdists[0])


def _clean_git_source_tree(root: Path) -> Path:
    """Build a tiny, real git-tracked source tree with no boundary findings."""

    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "safe.py").write_text('"""A clean module."""\n', encoding="utf-8")
    (root / "README.md").write_text("# clean project\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "clean"], cwd=root, check=True)
    return root


# ---------------------------------------------------------------------------
# Documented public API surface
# ---------------------------------------------------------------------------


def test_scanner_exposes_the_documented_public_api(scanner: ModuleType) -> None:
    expected = {
        "BoundaryFinding",
        "BoundaryRule",
        "FileEntry",
        "ScanReport",
        "ScanTarget",
        "build_report",
        "enumerate_target",
        "load_rules",
        "main",
        "scan_archive_member",
        "scan_bytes",
        "scan_filename",
        "scan_metadata",
    }
    assert expected <= set(scanner.__all__)


# ---------------------------------------------------------------------------
# Clean candidate
# ---------------------------------------------------------------------------


def test_clean_synthetic_source_tree_scans_with_zero_findings(
    scanner: ModuleType, tmp_path: Path
) -> None:
    root = _clean_git_source_tree(tmp_path / "clean-repo")
    target = scanner.ScanTarget(kind="source", label="clean", path=root)
    entries = scanner.enumerate_target(target)
    assert len(entries) == 2
    findings: list[object] = []
    for entry in entries:
        findings.extend(scanner.scan_filename(entry, scanner.load_rules(), target_label="clean"))
        findings.extend(scanner.scan_bytes(entry, scanner.load_rules(), target_label="clean"))
    assert findings == []


def test_scanner_cli_passes_on_the_clean_synthetic_tree(
    scanner: ModuleType, tmp_path: Path
) -> None:
    root = _clean_git_source_tree(tmp_path / "clean-repo-cli")
    rc = scanner.main(["--source-tree", str(root)])
    assert rc == 0


def test_scanner_cli_admits_only_the_exact_public_root_claude_alias(
    scanner: ModuleType, tmp_path: Path
) -> None:
    root = _clean_git_source_tree(tmp_path / "clean-repo-claude-alias")
    (root / "CLAUDE.md").write_bytes(b"@AGENTS.md\n")
    subprocess.run(["git", "add", "CLAUDE.md"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "public agent alias"], cwd=root, check=True)

    assert scanner.main(["--source-tree", str(root)]) == 0


@pytest.mark.parametrize(
    ("relative_path", "data", "target_kind"),
    [
        ("CLAUDE.md", b"private instructions\n", "source"),
        ("nested/CLAUDE.md", b"@AGENTS.md\n", "source"),
        ("CLAUDE.md", b"@AGENTS.md\n", "artifact"),
    ],
)
def test_public_root_claude_alias_exception_fails_closed(
    scanner: ModuleType, relative_path: str, data: bytes, target_kind: str
) -> None:
    entry = scanner.FileEntry(relative_path=relative_path, size=len(data), data=data)
    findings = scanner.scan_filename(
        entry,
        scanner.load_rules(),
        target_label="candidate",
        target_kind=target_kind,
    )

    assert {finding.rule_id for finding in findings} == {"PRIV-SESSION-002"}


# ---------------------------------------------------------------------------
# Mutation placements: filename, text, binary, archive metadata
# ---------------------------------------------------------------------------


def test_filename_placement_is_detected_by_rule_id(scanner: ModuleType) -> None:
    entry = scanner.FileEntry(relative_path=".claude/session.json", size=2, data=b"{}")
    findings = scanner.scan_filename(entry, scanner.load_rules(), target_label="t")
    rule_ids = {f.rule_id for f in findings}
    assert "PRIV-SESSION-001" in rule_ids


def test_text_content_placement_is_detected(scanner: ModuleType) -> None:
    data = b"reach me at postgres://" + b"alice:s3cr3t@" + b"db.internal:5432/app\n"
    entry = scanner.FileEntry(relative_path="config.toml", size=len(data), data=data)
    findings = scanner.scan_bytes(entry, scanner.load_rules(), target_label="t")
    rule_ids = {f.rule_id for f in findings}
    assert "PRIV-CRED-003" in rule_ids


def test_binary_undecodable_content_still_scans_raw_bytes(scanner: ModuleType) -> None:
    # Invalid UTF-8 byte (0xFF) surrounding a raw AWS-shaped key; scan_bytes must fall back to
    # scanning the raw byte pattern rather than treating undecodable content as clean.
    data = b"\xff\xfe" + b"AKI" + b"A1234567890123456" + b"\xff\xfe"
    entry = scanner.FileEntry(relative_path="blob.bin", size=len(data), data=data)
    findings = scanner.scan_bytes(entry, scanner.load_rules(), target_label="t")
    rule_ids = {f.rule_id for f in findings}
    assert "PRIV-CRED-002" in rule_ids


def test_archive_metadata_placement_is_detected(scanner: ModuleType) -> None:
    home = "/" + "Users/alice/notes"
    entries = (
        scanner.FileEntry(
            relative_path="pkg-0.1.dist-info/METADATA",
            size=20,
            data=f"Home-page: {home}\n".encode(),
        ),
    )
    findings = scanner.scan_metadata(entries, scanner.load_rules(), target_label="t")
    rule_ids = {f.rule_id for f in findings}
    assert "PRIV-PATH-001" in rule_ids


def test_metadata_scan_ignores_non_metadata_paths(scanner: ModuleType) -> None:
    home = "/" + "Users/alice/notes"
    entries = (
        scanner.FileEntry(
            relative_path="finishup/somewhere/not_metadata.py",
            size=20,
            data=f"# {home}\n".encode(),
        ),
    )
    findings = scanner.scan_metadata(entries, scanner.load_rules(), target_label="t")
    assert findings == ()


# ---------------------------------------------------------------------------
# Canary detection and redaction
# ---------------------------------------------------------------------------


def test_injected_canary_is_detected_and_never_leaked_in_the_report(
    scanner: ModuleType, tmp_path: Path
) -> None:
    canary = b"CANARY-3f9c2a7e1b6d4f58"
    entry = scanner.FileEntry(
        relative_path="notes.txt", size=64, data=b"prefix " + canary + b" suffix"
    )
    findings = scanner.scan_bytes(entry, scanner.load_rules(), target_label="t", canary=canary)
    canary_findings = [f for f in findings if f.rule_id == "CANARY-EXACT-001"]
    assert len(canary_findings) == 1
    report_bytes = scanner.build_report("t", "artifact", findings, canary=canary)
    assert canary not in report_bytes
    report = json.loads(report_bytes)
    assert report["finding_count"] == len(findings)
    for rendered in report["findings"]:
        assert set(rendered) == {
            "category",
            "file_digest",
            "location_bucket",
            "match_count",
            "relative_path",
            "rule_id",
            "severity",
            "target_label",
        }


def test_canary_in_filename_is_blocked_and_redacted_from_report(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    canary = "FINISHUP_CANARY_3f9c2a7e1b6d4f58aabbccddeeff00"
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / f"{canary}.txt").write_text(canary, encoding="utf-8")
    canary_file = tmp_path / "canary.bin"
    canary_file.write_text(canary, encoding="utf-8")

    rc = scanner.main(["--evidence-dir", str(evidence), "--canary-file", str(canary_file)])
    assert rc == 1
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err
    assert "CANARY-EXACT-001" in captured.err
    assert "<redacted-canary>" in captured.err


def test_report_never_carries_an_absolute_repository_path(scanner: ModuleType) -> None:
    entry = scanner.FileEntry(
        relative_path=".env", size=10, data=str(_REPO_ROOT).encode("utf-8") + b"\nSECRET=x\n"
    )
    findings = scanner.scan_filename(
        entry, scanner.load_rules(), target_label="t"
    ) + scanner.scan_bytes(entry, scanner.load_rules(), target_label="t")
    report_bytes = scanner.build_report("t", "artifact", findings)
    assert str(_REPO_ROOT).encode("utf-8") not in report_bytes


# ---------------------------------------------------------------------------
# Archive traversal / collision / compression-bomb safety (via a real zip)
# ---------------------------------------------------------------------------


def test_archive_traversal_member_is_rejected(scanner: ModuleType, tmp_path: Path) -> None:
    archive_path = tmp_path / "evil.whl"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../../etc/passwd", "not really")
    target = scanner.ScanTarget(kind="artifact", label="evil", path=archive_path)
    with pytest.raises(scanner.BoundaryScanError) as excinfo:
        scanner.enumerate_target(target)
    assert excinfo.value.reason == "unsafe_archive_member_path"


def test_archive_compression_bomb_member_is_rejected(scanner: ModuleType, tmp_path: Path) -> None:
    archive_path = tmp_path / "bomb.whl"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("big.bin", b"\x00" * 5_000_000)
    target = scanner.ScanTarget(kind="artifact", label="bomb", path=archive_path)
    # A real, highly compressible all-zero blob exceeds the fixed 200x compression-ratio cap.
    with pytest.raises(scanner.BoundaryScanError) as excinfo:
        scanner.enumerate_target(target)
    assert excinfo.value.reason == "compression_ratio_exceeded"


def test_unsupported_artifact_format_is_an_incomplete_scan(
    scanner: ModuleType, tmp_path: Path
) -> None:
    stray = tmp_path / "not-an-archive.bin"
    stray.write_bytes(b"\x00\x01\x02")
    target = scanner.ScanTarget(kind="artifact", label="stray", path=stray)
    with pytest.raises(scanner.BoundaryScanError) as excinfo:
        scanner.enumerate_target(target)
    assert excinfo.value.reason == "unsupported_artifact_format"


def test_missing_artifact_blocks_as_incomplete_via_cli(scanner: ModuleType, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.whl"
    rc = scanner.main(["--artifact", str(missing)])
    assert rc == 1


def test_runtime_tree_scans_recursively_with_a_bounded_label(
    scanner: ModuleType, tmp_path: Path
) -> None:
    runtime = tmp_path / "runtime"
    nested = runtime / "nested"
    nested.mkdir(parents=True)
    (nested / "clean.bin").write_bytes(b"clean runtime bytes")
    (runtime / "catalog.sqlite3").write_bytes(b"expected encrypted runtime database")
    report_path = tmp_path / "runtime-report.json"

    entries = scanner.enumerate_target(
        scanner.ScanTarget(kind="runtime", label="runtime-1", path=runtime)
    )
    rc = scanner.main(["--runtime-tree", str(runtime), "--json-out", str(report_path)])

    assert rc == 0
    relative_paths = [entry.relative_path for entry in entries]
    assert relative_paths == sorted(relative_paths, key=lambda value: value.encode("utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["target_kind"] == "runtime"
    assert report["target_label"] == "runtime-1"
    assert report["finding_count"] == 0
    assert str(tmp_path) not in report_path.read_text(encoding="utf-8")


def test_missing_runtime_tree_blocks_as_incomplete_via_cli(
    scanner: ModuleType, tmp_path: Path
) -> None:
    rc = scanner.main(["--runtime-tree", str(tmp_path / "missing")])
    assert rc == 1


def test_runtime_tree_symlink_blocks_as_incomplete_via_cli(
    scanner: ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    runtime_link = tmp_path / "runtime-link"
    runtime_link.symlink_to(target, target_is_directory=True)

    rc = scanner.main(["--runtime-tree", str(runtime_link)])

    assert rc == 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="platform has no FIFO support")
def test_runtime_tree_fifo_blocks_without_reading(scanner: ModuleType, tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    os.mkfifo(runtime / "blocked.fifo")

    rc = scanner.main(["--runtime-tree", str(runtime)])

    assert rc == 1


def test_runtime_tree_member_cap_applies_before_file_reads(
    scanner: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "a.txt").write_text("a", encoding="utf-8")
    (runtime / "b.txt").write_text("b", encoding="utf-8")
    monkeypatch.setattr(scanner, "_MAX_MEMBER_COUNT", 1)

    rc = scanner.main(["--runtime-tree", str(runtime)])

    assert rc == 1


def test_runtime_tree_file_cap_applies_before_unbounded_read(
    scanner: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "too-large.bin").write_bytes(b"ab")
    monkeypatch.setattr(scanner, "_MAX_FILE_BYTES", 1)

    rc = scanner.main(["--runtime-tree", str(runtime)])

    assert rc == 1


def test_runtime_tree_canary_is_detected_and_redacted(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    canary = b"FINISHUP_RUNTIME_CANARY_0123456789abcdef"
    (runtime / "leak.bin").write_bytes(b"prefix:" + canary)
    canary_file = tmp_path / "canary.bin"
    canary_file.write_bytes(canary)
    report_path = tmp_path / "runtime-report.json"

    rc = scanner.main(
        [
            "--runtime-tree",
            str(runtime),
            "--canary-file",
            str(canary_file),
            "--json-out",
            str(report_path),
        ]
    )

    assert rc == 1
    captured = capsys.readouterr()
    report = report_path.read_bytes()
    assert canary not in captured.out.encode()
    assert canary not in captured.err.encode()
    assert canary not in report
    assert json.loads(report)["finding_count"] == 1


# ---------------------------------------------------------------------------
# Rule-config loading (the test-only substitution mechanism that does exist)
# ---------------------------------------------------------------------------


def test_custom_rule_config_duplicate_id_is_rejected(scanner: ModuleType, tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps(
            [
                {
                    "rule_id": "DUP-001",
                    "category": "test",
                    "severity": "low",
                    "scope": "all",
                    "detector": "filename",
                    "pattern": "a",
                    "justification": "j",
                    "owner_role": "release-maintainer",
                },
                {
                    "rule_id": "DUP-001",
                    "category": "test",
                    "severity": "low",
                    "scope": "all",
                    "detector": "filename",
                    "pattern": "b",
                    "justification": "j",
                    "owner_role": "release-maintainer",
                },
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(scanner.BoundaryScanError) as excinfo:
        scanner.load_rules(rules_path)
    assert excinfo.value.reason == "rule_config_duplicate_id"


def test_custom_rule_config_missing_field_is_rejected(scanner: ModuleType, tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps([{"rule_id": "X"}]), encoding="utf-8")
    with pytest.raises(scanner.BoundaryScanError) as excinfo:
        scanner.load_rules(rules_path)
    assert excinfo.value.reason == "rule_config_invalid"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "scripts/scan_public_boundary.py has no per-file reviewed-exception mechanism "
        "(no --exceptions flag, no exception fields on BoundaryRule/ScanReport); only a "
        "full-ruleset --rules override and --canary-file exist. An 'exact rule+path+digest "
        "passes, changed path/digest/expired owner fails' exception test cannot be built "
        "against the real script without inventing an API it does not have."
    ),
)
def test_exact_reviewed_exception_matches_rule_path_and_digest(scanner: ModuleType) -> None:
    raise AssertionError("no reviewed-exception mechanism exists in scan_public_boundary.py")


# ---------------------------------------------------------------------------
# Real built artifacts
# ---------------------------------------------------------------------------


def test_built_sdist_and_wheel_are_fully_enumerable_without_error(
    scanner: ModuleType, built_dist: _BuiltDist
) -> None:
    wheel_entries = scanner.enumerate_target(
        scanner.ScanTarget(kind="artifact", label="wheel", path=built_dist.wheel)
    )
    sdist_entries = scanner.enumerate_target(
        scanner.ScanTarget(kind="artifact", label="sdist", path=built_dist.sdist)
    )
    assert len(wheel_entries) > 0
    assert len(sdist_entries) > 0
    # Every scanned member is a real, distinct, safely-named path.
    assert len({entry.relative_path for entry in wheel_entries}) == len(wheel_entries)


def test_built_wheel_has_no_development_cache_or_vcs_files(
    scanner: ModuleType, built_dist: _BuiltDist
) -> None:
    entries = scanner.enumerate_target(
        scanner.ScanTarget(kind="artifact", label="wheel", path=built_dist.wheel)
    )
    findings: list[Any] = []
    for entry in entries:
        findings.extend(scanner.scan_filename(entry, scanner.load_rules(), target_label="wheel"))
    cache_findings = [f for f in findings if f.category == "debug_build_cache_file"]
    assert cache_findings == []


def test_built_wheel_scans_clean_of_every_boundary_rule(
    scanner: ModuleType, built_dist: _BuiltDist
) -> None:
    entries = scanner.enumerate_target(
        scanner.ScanTarget(kind="artifact", label="wheel", path=built_dist.wheel)
    )
    rules = scanner.load_rules()
    findings: list[object] = []
    for entry in entries:
        findings.extend(scanner.scan_filename(entry, rules, target_label="wheel"))
        findings.extend(scanner.scan_bytes(entry, rules, target_label="wheel"))
    findings.extend(scanner.scan_metadata(entries, rules, target_label="wheel"))
    assert findings == []


@pytest.mark.xfail(
    strict=True,
    reason=(
        "enumerate_target does not recurse into a nested supported archive: a secret placed only "
        "inside a .zip stored as a member of the outer artifact is scanned as opaque compressed "
        "bytes and is not detected, contradicting this spec's 'nested supported archive' mutation "
        "placement. Demonstrated here rather than silently skipped."
    ),
)
def test_nested_archive_member_secret_is_detected(scanner: ModuleType, tmp_path: Path) -> None:
    # Real DEFLATE compression on both layers: the plaintext key never appears as a literal
    # byte run in the outer member's stored bytes, which is exactly what lets it slip past a
    # non-recursive scan of the outer archive.
    pem = b"-" * 5 + b"BEGIN RSA PRIVATE KEY" + b"-" * 5 + b"\n" + b"MIIBOgIBAAJBAK" * 40 + b"\n"
    inner_path = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner_path, "w", compression=zipfile.ZIP_DEFLATED) as inner:
        inner.writestr("secret.pem", pem)
    outer_path = tmp_path / "outer.whl"
    with zipfile.ZipFile(outer_path, "w", compression=zipfile.ZIP_DEFLATED) as outer:
        outer.writestr("pkg/inner.zip", inner_path.read_bytes())
    entries = scanner.enumerate_target(
        scanner.ScanTarget(kind="artifact", label="outer", path=outer_path)
    )
    rules = scanner.load_rules()
    findings: list[Any] = []
    for entry in entries:
        findings.extend(scanner.scan_bytes(entry, rules, target_label="outer"))
    rule_ids = {f.rule_id for f in findings}
    assert "PRIV-CRED-001" in rule_ids


# ---------------------------------------------------------------------------
# CLI end-to-end: report file, exit codes, stderr never leaks the canary
# ---------------------------------------------------------------------------


def test_cli_writes_a_canonical_json_out_report(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _clean_git_source_tree(tmp_path / "clean-cli-report")
    report_path = tmp_path / "report.json"
    rc = scanner.main(["--source-tree", str(root), "--json-out", str(report_path)])
    assert rc == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == "yoetz.public-boundary-report/1"
    assert report["finding_count"] == 0


def test_cli_blocks_and_never_prints_the_canary_bytes(
    scanner: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "dirty-repo"
    (root).mkdir()
    canary = "sk-canary-8f24c9b1a7"
    (root / "leak.py").write_text(f"TOKEN = '{canary}'\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "dirty"], cwd=root, check=True)

    canary_file = tmp_path / "canary.bin"
    canary_file.write_bytes(canary.encode("utf-8"))
    rc = scanner.main(["--source-tree", str(root), "--canary-file", str(canary_file)])
    assert rc == 1
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err


def test_sdist_can_be_enumerated_via_tarfile_directly(built_dist: _BuiltDist) -> None:
    with tarfile.open(built_dist.sdist, mode="r:gz") as archive:
        names = archive.getnames()
    assert any(name.endswith("src/finishup/__init__.py") for name in names)
