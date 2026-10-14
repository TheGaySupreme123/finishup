"""Public-repository, artifact, and runtime privacy boundary gate.

Blocks publication or unsafe runtime persistence of private strategy/business material, local
paths, transcripts, credentials, tenant/customer identifiers, secret canaries, and unexpected
files across candidate source, sdist, wheel, release-evidence, and explicitly selected live-runtime
targets. This is a deterministic prevention gate, not a claim that pattern matching can discover
every secret; human review and dependency/license scanners remain separate gates. The scanner
performs no network calls and writes only the report paths explicitly requested by the caller.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = [
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
]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BoundaryRule:
    rule_id: str
    category: str
    severity: str
    scope: str
    detector: str
    pattern: str
    justification: str
    owner_role: str


@dataclass(frozen=True, slots=True)
class BoundaryFinding:
    rule_id: str
    category: str
    severity: str
    target_label: str
    relative_path: str
    location_bucket: str
    file_digest: str
    match_count: int


@dataclass(frozen=True, slots=True)
class FileEntry:
    relative_path: str
    size: int
    data: bytes


@dataclass(frozen=True, slots=True)
class ScanTarget:
    kind: str
    label: str
    path: Path


@dataclass(frozen=True, slots=True)
class ScanReport:
    target_label: str
    target_kind: str
    file_count: int
    findings: tuple[BoundaryFinding, ...]
    complete: bool

    @property
    def blocked(self) -> bool:
        return bool(self.findings) or not self.complete


class BoundaryScanError(Exception):
    """A bounded, traceback-free scan failure: any such failure is an incomplete, blocking scan."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# Constants and reviewed default rules
# --------------------------------------------------------------------------

_MAX_FILE_BYTES: Final = 25_000_000
_MAX_AGGREGATE_BYTES: Final = 500_000_000
_MAX_MEMBER_COUNT: Final = 200_000
_MAX_COMPRESSION_RATIO: Final = 200
_READ_CHUNK_BYTES: Final = 1_048_576

# Reviewed public rule config, committed beside the script. Patterns are bounded, anchored where
# practical, and public (synthetic examples only, never real credentials).
_DEFAULT_RULES: Final[tuple[BoundaryRule, ...]] = (
    BoundaryRule(
        "PRIV-PATH-001",
        "local_home_path",
        "high",
        "publication",
        "content",
        r"(?<![\w/.])/Users/[A-Za-z0-9_.\-]+",
        "A maintainer's absolute macOS home path must never reach a public artifact.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-PATH-002",
        "local_home_path",
        "high",
        "publication",
        "content",
        r"(?<![\w/.])/home/[A-Za-z0-9_.\-]+",
        "A maintainer's absolute Linux home path must never reach a public artifact.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-PATH-003",
        "local_repository_path",
        "medium",
        "publication",
        "content",
        r"(?<![\w/.])[A-Za-z]:\\\\Users\\\\[A-Za-z0-9_.\-]+",
        "A maintainer's absolute Windows home path must never reach a public artifact.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-SESSION-001",
        "transcript_session_marker",
        "high",
        "publication",
        "filename",
        r"(^|/)\.claude/",
        "Assistant session/config directories are private drafting state, not a public artifact.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-SESSION-002",
        "transcript_session_marker",
        "medium",
        "publication",
        "filename",
        r"(^|/)CLAUDE\.md$",
        "Private assistant instruction files are not a reviewed public deliverable.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-CRED-001",
        "credential_private_key",
        "critical",
        "all",
        "content",
        r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        "PEM private key material must never appear in a public artifact.",
        "security-reviewer",
    ),
    BoundaryRule(
        "PRIV-CRED-002",
        "credential_token",
        "critical",
        "all",
        "content",
        r"AKIA[0-9A-Z]{16}",
        "AWS-shaped access key identifiers must never appear in a public artifact.",
        "security-reviewer",
    ),
    BoundaryRule(
        "PRIV-CRED-003",
        "credential_uri_userinfo",
        "high",
        "all",
        "content",
        r"[a-zA-Z][a-zA-Z0-9+.\-]{0,15}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@",
        "A URI embedding user:password credentials must never appear in a public artifact.",
        "security-reviewer",
    ),
    BoundaryRule(
        "PRIV-ENV-001",
        "debug_build_cache_file",
        "medium",
        "publication",
        "filename",
        r"(^|/)\.env(\.[A-Za-z0-9_.\-]+)?$",
        "Local dotenv files carry ambient secrets and must not be packaged or exported.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-CACHE-001",
        "debug_build_cache_file",
        "low",
        "publication",
        "filename",
        r"(^|/)__pycache__/|\.pyc$",
        "Interpreter caches are build noise, never a reviewed public deliverable.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-CACHE-002",
        "debug_build_cache_file",
        "low",
        "publication",
        "filename",
        r"(^|/)\.pytest_cache/|(^|/)\.ruff_cache/|(^|/)\.mypy_cache/",
        "Tool caches are local build state, never a reviewed public deliverable.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-DB-001",
        "database_or_wal_file",
        "medium",
        "publication",
        "filename",
        r"\.(sqlite3?|db)(-wal|-shm)?$",
        "Local database/WAL/SHM files may carry user data and must not be packaged or exported.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-MAP-001",
        "source_map",
        "low",
        "publication",
        "filename",
        r"\.map$",
        "Source maps can leak local build paths and are not a reviewed public deliverable.",
        "release-maintainer",
    ),
    BoundaryRule(
        "PRIV-PLAN-001",
        "private_planning_document",
        "high",
        "publication",
        "filename",
        r"(^|/)(STRATEGY|PRIVATE|FOUNDER[-_ ]NOTES?)[A-Za-z0-9_.\- ]*\.(md|txt)$",
        "Private planning/business document names must not enter the public candidate.",
        "release-maintainer",
    ),
)

_TEXT_DECODE_EXTENSIONS: Final = frozenset(
    {".py", ".md", ".txt", ".json", ".toml", ".yml", ".yaml", ".sql", ".cfg", ".ini", ".lock"}
)

_REVIEWED_SOURCE_ROOT_ALIASES: Final[dict[tuple[str, str], bytes]] = {
    ("PRIV-SESSION-002", "CLAUDE.md"): b"@AGENTS.md\n",
}


# --------------------------------------------------------------------------
# Rule loading
# --------------------------------------------------------------------------


def load_rules(path: Path | None = None) -> tuple[BoundaryRule, ...]:
    """Return the reviewed public rule set: the frozen default, or an explicit test fixture."""

    if path is None:
        return _DEFAULT_RULES

    if path.is_symlink() or not path.is_file():
        raise BoundaryScanError("rule_config_unreadable", detail=str(path))
    try:
        payload = cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BoundaryScanError("rule_config_invalid", detail=str(path)) from exc

    if not isinstance(payload, list):
        raise BoundaryScanError("rule_config_invalid", detail=str(path))

    rules: list[BoundaryRule] = []
    seen_ids: set[str] = set()
    for raw in cast("list[object]", payload):
        if not isinstance(raw, dict):
            raise BoundaryScanError("rule_config_invalid", detail=str(path))
        fields = cast("dict[object, object]", raw)
        try:
            rule = BoundaryRule(
                rule_id=str(fields["rule_id"]),
                category=str(fields["category"]),
                severity=str(fields["severity"]),
                scope=str(fields["scope"]),
                detector=str(fields["detector"]),
                pattern=str(fields["pattern"]),
                justification=str(fields["justification"]),
                owner_role=str(fields["owner_role"]),
            )
        except KeyError as exc:
            raise BoundaryScanError("rule_config_invalid", detail=str(path)) from exc
        if rule.rule_id in seen_ids:
            raise BoundaryScanError("rule_config_duplicate_id", detail=rule.rule_id)
        seen_ids.add(rule.rule_id)
        rules.append(rule)
    return tuple(rules)


def _applicable_rules(rules: Sequence[BoundaryRule], target_kind: str) -> tuple[BoundaryRule, ...]:
    """Select rules for a publication target or an explicitly bounded runtime tree."""

    scopes = {"all", target_kind}
    if target_kind != "runtime":
        scopes.add("publication")
    return tuple(rule for rule in rules if rule.scope in scopes)


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------


def _is_safe_member_path(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        return False
    if ".." in path.split("/"):
        return False
    if any(ord(ch) < 0x20 for ch in path):
        return False
    return True


# --------------------------------------------------------------------------
# Target inventory
# --------------------------------------------------------------------------


def enumerate_target(target: ScanTarget) -> tuple[FileEntry, ...]:
    """Return a safe, sorted, size-capped file inventory for one scan target."""

    if target.kind == "source":
        return _enumerate_source(target.path)
    if target.kind == "artifact":
        return _enumerate_artifact(target.path)
    if target.kind == "evidence":
        return _enumerate_evidence(target.path)
    if target.kind == "runtime":
        return _enumerate_runtime(target.path)
    raise BoundaryScanError("unsupported_target_kind", detail=target.kind)


def _enumerate_source(root: Path) -> tuple[FileEntry, ...]:
    if not root.is_dir():
        raise BoundaryScanError("source_tree_missing", detail=str(root))
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, trusted local git binary
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BoundaryScanError("source_tree_listing_failed", detail=str(root)) from exc

    names = [name for name in completed.stdout.decode("utf-8", errors="strict").split("\0") if name]
    entries: list[FileEntry] = []
    aggregate = 0
    for name in sorted(names, key=lambda item: item.encode("utf-8")):
        if not _is_safe_member_path(name):
            raise BoundaryScanError("unsafe_tracked_path", detail=name)
        candidate = root / name
        if candidate.is_symlink() or not candidate.is_file():
            raise BoundaryScanError("unscanned_tracked_entry", detail=name)
        data = candidate.read_bytes()
        if len(data) > _MAX_FILE_BYTES:
            raise BoundaryScanError("file_too_large", detail=name)
        aggregate += len(data)
        if aggregate > _MAX_AGGREGATE_BYTES:
            raise BoundaryScanError("aggregate_too_large", detail=str(root))
        entries.append(FileEntry(relative_path=name, size=len(data), data=data))
    if len(entries) > _MAX_MEMBER_COUNT:
        raise BoundaryScanError("member_count_exceeded", detail=str(root))
    return tuple(entries)


def _enumerate_evidence(root: Path) -> tuple[FileEntry, ...]:
    if not root.is_dir():
        raise BoundaryScanError("evidence_dir_missing", detail=str(root))
    entries: list[FileEntry] = []
    aggregate = 0
    for candidate in sorted(root.rglob("*")):
        if candidate.is_dir():
            continue
        if candidate.is_symlink():
            raise BoundaryScanError("unscanned_evidence_entry", detail=str(candidate))
        relative = candidate.relative_to(root).as_posix()
        if not _is_safe_member_path(relative):
            raise BoundaryScanError("unsafe_evidence_path", detail=relative)
        data = candidate.read_bytes()
        if len(data) > _MAX_FILE_BYTES:
            raise BoundaryScanError("file_too_large", detail=relative)
        aggregate += len(data)
        if aggregate > _MAX_AGGREGATE_BYTES:
            raise BoundaryScanError("aggregate_too_large", detail=str(root))
        entries.append(FileEntry(relative_path=relative, size=len(data), data=data))
    if len(entries) > _MAX_MEMBER_COUNT:
        raise BoundaryScanError("member_count_exceeded", detail=str(root))
    return tuple(entries)


def _enumerate_runtime(root: Path) -> tuple[FileEntry, ...]:
    """Enumerate one explicitly selected live-runtime tree without following symlinks."""

    if root.is_symlink() or not root.is_dir():
        raise BoundaryScanError("runtime_tree_missing", detail=str(root))
    entries: list[FileEntry] = []
    aggregate = 0
    discovered = 0
    pending: list[tuple[Path, str]] = [(root, "directory")]
    while pending:
        candidate, kind = pending.pop()
        if kind == "directory":
            children: list[tuple[Path, str]] = []
            try:
                with os.scandir(candidate) as iterator:
                    for child in iterator:
                        discovered += 1
                        if discovered > _MAX_MEMBER_COUNT:
                            raise BoundaryScanError("member_count_exceeded", detail=str(root))
                        if child.is_symlink():
                            child_kind = "unsupported"
                        elif child.is_dir(follow_symlinks=False):
                            child_kind = "directory"
                        elif child.is_file(follow_symlinks=False):
                            child_kind = "file"
                        else:
                            child_kind = "unsupported"
                        children.append((Path(child.path), child_kind))
            except BoundaryScanError:
                raise
            except OSError as exc:
                raise BoundaryScanError("unscanned_runtime_entry", detail=str(candidate)) from exc
            children.sort(
                key=lambda item: item[0].name.encode("utf-8", errors="surrogateescape"),
                reverse=True,
            )
            pending.extend(children)
            continue
        if kind != "file":
            raise BoundaryScanError("unscanned_runtime_entry", detail=str(candidate))
        relative = candidate.relative_to(root).as_posix()
        if not _is_safe_member_path(relative):
            raise BoundaryScanError("unsafe_runtime_path", detail=relative)
        data = _read_runtime_file(candidate, relative)
        aggregate += len(data)
        if aggregate > _MAX_AGGREGATE_BYTES:
            raise BoundaryScanError("aggregate_too_large", detail=str(root))
        entries.append(FileEntry(relative_path=relative, size=len(data), data=data))
    return tuple(entries)


def _read_runtime_file(candidate: Path, relative: str) -> bytes:
    """Read one regular runtime file through a nonblocking, no-follow descriptor."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise BoundaryScanError("unscanned_runtime_entry", detail=str(candidate)) from exc
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode):
            raise BoundaryScanError("unscanned_runtime_entry", detail=str(candidate))
        if facts.st_size > _MAX_FILE_BYTES:
            raise BoundaryScanError("file_too_large", detail=relative)
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, _MAX_FILE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_FILE_BYTES:
                raise BoundaryScanError("file_too_large", detail=relative)
        return b"".join(chunks)
    except BoundaryScanError:
        raise
    except OSError as exc:
        raise BoundaryScanError("unscanned_runtime_entry", detail=str(candidate)) from exc
    finally:
        os.close(descriptor)


def _enumerate_artifact(path: Path) -> tuple[FileEntry, ...]:
    if path.is_symlink() or not path.is_file():
        raise BoundaryScanError("artifact_missing", detail=str(path))

    name = path.name
    if name.endswith((".whl", ".zip")):
        return _enumerate_zip(path)
    if name.endswith((".tar.gz", ".tgz", ".tar")):
        return _enumerate_tar(path)
    raise BoundaryScanError("unsupported_artifact_format", detail=name)


def _enumerate_zip(path: Path) -> tuple[FileEntry, ...]:
    entries: list[FileEntry] = []
    aggregate = 0
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > _MAX_MEMBER_COUNT:
                raise BoundaryScanError("member_count_exceeded", detail=str(path))
            for info in sorted(infos, key=lambda item: item.filename.encode("utf-8")):
                member = info.filename
                if member.endswith("/"):
                    continue
                if not _is_safe_member_path(member):
                    raise BoundaryScanError("unsafe_archive_member_path", detail=member)
                if info.file_size > _MAX_FILE_BYTES:
                    raise BoundaryScanError("archive_member_too_large", detail=member)
                if info.compress_size > 0 and info.file_size / max(info.compress_size, 1) > (
                    _MAX_COMPRESSION_RATIO
                ):
                    raise BoundaryScanError("compression_ratio_exceeded", detail=member)
                data = archive.read(info)
                aggregate += len(data)
                if aggregate > _MAX_AGGREGATE_BYTES:
                    raise BoundaryScanError("aggregate_too_large", detail=str(path))
                entries.append(FileEntry(relative_path=member, size=len(data), data=data))
    except zipfile.BadZipFile as exc:
        raise BoundaryScanError("archive_unreadable", detail=str(path)) from exc
    return tuple(entries)


def _enumerate_tar(path: Path) -> tuple[FileEntry, ...]:
    entries: list[FileEntry] = []
    aggregate = 0
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > _MAX_MEMBER_COUNT:
                raise BoundaryScanError("member_count_exceeded", detail=str(path))
            for member in sorted(members, key=lambda item: item.name.encode("utf-8")):
                if not member.isfile():
                    if member.issym() or member.islnk() or member.isdev():
                        raise BoundaryScanError("unsupported_archive_member", detail=member.name)
                    continue
                if not _is_safe_member_path(member.name):
                    raise BoundaryScanError("unsafe_archive_member_path", detail=member.name)
                if member.size > _MAX_FILE_BYTES:
                    raise BoundaryScanError("archive_member_too_large", detail=member.name)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise BoundaryScanError("archive_member_unreadable", detail=member.name)
                data = extracted.read()
                aggregate += len(data)
                if aggregate > _MAX_AGGREGATE_BYTES:
                    raise BoundaryScanError("aggregate_too_large", detail=str(path))
                entries.append(FileEntry(relative_path=member.name, size=len(data), data=data))
    except tarfile.TarError as exc:
        raise BoundaryScanError("archive_unreadable", detail=str(path)) from exc
    return tuple(entries)


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------


def _digest(data: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


_CANARY_PLACEHOLDER: Final = "<redacted-canary>"


def _redact_canary_text(value: str, canary: bytes | None) -> str:
    """Strip exact canary text from report/console fields; never echo the secret."""

    if not canary:
        return value
    try:
        token = canary.decode("utf-8")
    except UnicodeDecodeError:
        return value
    if not token:
        return value
    return value.replace(token, _CANARY_PLACEHOLDER)


def _redact_finding(finding: BoundaryFinding, canary: bytes | None) -> BoundaryFinding:
    if not canary:
        return finding
    return BoundaryFinding(
        rule_id=finding.rule_id,
        category=finding.category,
        severity=finding.severity,
        target_label=_redact_canary_text(finding.target_label, canary),
        relative_path=_redact_canary_text(finding.relative_path, canary),
        location_bucket=finding.location_bucket,
        file_digest=finding.file_digest,
        match_count=finding.match_count,
    )


def scan_filename(
    entry: FileEntry,
    rules: Sequence[BoundaryRule],
    *,
    target_label: str,
    target_kind: str | None = None,
    canary: bytes | None = None,
) -> tuple[BoundaryFinding, ...]:
    """Apply every ``filename``-scoped rule to one entry's relative path.

    One reviewed repository-root agent-instruction alias is admitted only for a source tree and
    only when both its normalized path and bytes match exactly. The same filename remains blocked
    in artifacts, nested paths, and source files carrying any other content.
    """

    findings: list[BoundaryFinding] = []
    path_bytes = entry.relative_path.encode("utf-8", errors="surrogateescape")
    if canary and canary in path_bytes:
        findings.append(
            BoundaryFinding(
                rule_id="CANARY-EXACT-001",
                category="injected_canary",
                severity="critical",
                target_label=target_label,
                relative_path=entry.relative_path,
                location_bucket="filename",
                file_digest=_digest(entry.data),
                match_count=path_bytes.count(canary),
            )
        )
    for rule in rules:
        if rule.detector != "filename":
            continue
        reviewed_alias = _REVIEWED_SOURCE_ROOT_ALIASES.get((rule.rule_id, entry.relative_path))
        if target_kind == "source" and reviewed_alias is not None and entry.data == reviewed_alias:
            continue
        matches = len(re.findall(rule.pattern, entry.relative_path))
        if matches:
            findings.append(
                BoundaryFinding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    target_label=target_label,
                    relative_path=entry.relative_path,
                    location_bucket="filename",
                    file_digest=_digest(entry.data),
                    match_count=matches,
                )
            )
    return tuple(findings)


def scan_bytes(
    entry: FileEntry,
    rules: Sequence[BoundaryRule],
    *,
    target_label: str,
    canary: bytes | None = None,
) -> tuple[BoundaryFinding, ...]:
    """Apply every ``content``-scoped rule, plus an optional exact canary match, to raw bytes."""

    findings: list[BoundaryFinding] = []

    if canary and canary in entry.data:
        findings.append(
            BoundaryFinding(
                rule_id="CANARY-EXACT-001",
                category="injected_canary",
                severity="critical",
                target_label=target_label,
                relative_path=entry.relative_path,
                location_bucket="content",
                file_digest=_digest(entry.data),
                match_count=entry.data.count(canary),
            )
        )

    content_rules = [rule for rule in rules if rule.detector == "content"]
    if not content_rules:
        return tuple(findings)

    suffix = Path(entry.relative_path).suffix
    text: str | None = None
    if suffix in _TEXT_DECODE_EXTENSIONS or suffix == "":
        try:
            text = entry.data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = None

    for rule in content_rules:
        matches = 0
        if text is not None:
            matches = len(re.findall(rule.pattern, text))
        else:
            matches = len(re.findall(rule.pattern.encode("utf-8"), entry.data))
        if matches:
            findings.append(
                BoundaryFinding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    target_label=target_label,
                    relative_path=entry.relative_path,
                    location_bucket="content",
                    file_digest=_digest(entry.data),
                    match_count=matches,
                )
            )
    return tuple(findings)


def scan_archive_member(
    archive_label: str,
    member: FileEntry,
    rules: Sequence[BoundaryRule],
    *,
    canary: bytes | None = None,
) -> tuple[BoundaryFinding, ...]:
    """Apply filename and content detectors to one archive member."""

    return scan_filename(member, rules, target_label=archive_label, canary=canary) + scan_bytes(
        member, rules, target_label=archive_label, canary=canary
    )


_METADATA_PATH_MARKERS: Final = ("dist-info/RECORD", "PKG-INFO", "METADATA", "direct_url.json")


def scan_metadata(
    entries: Sequence[FileEntry], rules: Sequence[BoundaryRule], *, target_label: str
) -> tuple[BoundaryFinding, ...]:
    """Apply boundary detectors to wheel/sdist metadata entries only."""

    findings: list[BoundaryFinding] = []
    for entry in entries:
        if not any(marker in entry.relative_path for marker in _METADATA_PATH_MARKERS):
            continue
        findings += scan_filename(entry, rules, target_label=target_label)
        findings += scan_bytes(entry, rules, target_label=target_label)
    return tuple(findings)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def _finding_sort_key(finding: BoundaryFinding) -> tuple[str, str, str]:
    return (finding.rule_id, finding.target_label, finding.relative_path)


def build_report(
    target_label: str,
    target_kind: str,
    findings: Sequence[BoundaryFinding],
    *,
    canary: bytes | None = None,
) -> bytes:
    """Render a canonical, redacted JSON scan report: no matched bytes, no absolute paths."""

    sanitized = tuple(_redact_finding(finding, canary) for finding in findings)
    ordered = sorted(sanitized, key=_finding_sort_key)
    document: dict[str, JsonValue] = {
        "findings": [
            {
                "category": finding.category,
                "file_digest": finding.file_digest,
                "location_bucket": finding.location_bucket,
                "match_count": finding.match_count,
                "relative_path": finding.relative_path,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "target_label": finding.target_label,
            }
            for finding in ordered
        ],
        "finding_count": len(ordered),
        "schema": "yoetz.public-boundary-report/1",
        "target_kind": target_kind,
        "target_label": _redact_canary_text(target_label, canary),
    }
    return canonical_encode(document)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan_public_boundary.py",
        description="Block publication of private/local material across source and built artifacts.",
    )
    parser.add_argument(
        "--source-tree", type=Path, default=None, help="Scan a tracked source tree."
    )
    parser.add_argument(
        "--artifact", type=Path, action="append", default=[], help="Scan one built wheel/sdist."
    )
    parser.add_argument(
        "--evidence-dir", type=Path, default=None, help="Scan a release-evidence output directory."
    )
    parser.add_argument(
        "--runtime-tree",
        type=Path,
        action="append",
        default=[],
        help="Scan one explicitly selected live-runtime directory recursively.",
    )
    parser.add_argument(
        "--canary-file",
        type=Path,
        default=None,
        help="CI-secret-store path to bytes that must never appear in a scanned target.",
    )
    parser.add_argument("--rules", type=Path, default=None, help="Test-only explicit rule config.")
    parser.add_argument(
        "--json-out", type=Path, default=None, help="Write the canonical JSON report."
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    targets: list[ScanTarget] = []
    if args.source_tree is not None:
        targets.append(
            ScanTarget(kind="source", label=str(args.source_tree), path=args.source_tree)
        )
    for artifact in args.artifact:
        targets.append(ScanTarget(kind="artifact", label=str(artifact), path=artifact))
    if args.evidence_dir is not None:
        targets.append(
            ScanTarget(kind="evidence", label=str(args.evidence_dir), path=args.evidence_dir)
        )
    for index, runtime_tree in enumerate(args.runtime_tree, start=1):
        targets.append(ScanTarget(kind="runtime", label=f"runtime-{index}", path=runtime_tree))

    if not targets:
        parser.error(
            "at least one of --source-tree, --artifact, --evidence-dir, --runtime-tree is required"
        )
        return 2

    canary: bytes | None = None
    if args.canary_file is not None:
        try:
            canary = args.canary_file.read_bytes()
        except OSError as exc:
            print(f"scan_public_boundary: invocation error: {exc}", file=sys.stderr)
            return 2

    try:
        rules = load_rules(args.rules)
    except BoundaryScanError as exc:
        print(f"scan_public_boundary: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1

    all_findings: list[BoundaryFinding] = []
    total_files = 0
    incomplete = False

    for target in targets:
        try:
            entries = enumerate_target(target)
        except BoundaryScanError as exc:
            print(f"scan_public_boundary: FAIL ({exc.reason}) {target.label}", file=sys.stderr)
            incomplete = True
            continue

        total_files += len(entries)
        target_rules = _applicable_rules(rules, target.kind)
        for entry in entries:
            all_findings.extend(
                scan_filename(
                    entry,
                    target_rules,
                    target_label=target.label,
                    target_kind=target.kind,
                    canary=canary,
                )
            )
            all_findings.extend(
                scan_bytes(entry, target_rules, target_label=target.label, canary=canary)
            )
        if target.kind == "artifact":
            all_findings.extend(scan_metadata(entries, target_rules, target_label=target.label))

    report_bytes = build_report(
        ",".join(target.label for target in targets),
        ",".join(sorted({target.kind for target in targets})),
        all_findings,
        canary=canary,
    )
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_bytes(report_bytes)

    ordered_findings = sorted(
        (_redact_finding(finding, canary) for finding in all_findings),
        key=_finding_sort_key,
    )
    if not ordered_findings and not incomplete:
        print(f"scan_public_boundary: PASS ({total_files} file(s) scanned)")
        return 0

    print("scan_public_boundary: FAIL", file=sys.stderr)
    for finding in ordered_findings:
        print(
            f"  {finding.rule_id} [{finding.severity}] {finding.target_label}:{finding.relative_path} "
            f"({finding.category})",
            file=sys.stderr,
        )
    if incomplete:
        print("  incomplete scan", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
