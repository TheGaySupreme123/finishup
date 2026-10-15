"""Build the typed input manifest consumed by ``generate_release_evidence.py``.

The release workflow supplies candidate artifacts, reviewed support/limitation inputs, and one
machine-result record for every required release gate.  This script is the single boundary that
normalizes those inputs into the evidence generator's canonical manifest; it rejects ambiguity
instead of letting an inline workflow snippet silently omit a gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

_REQUIRED_GATES: tuple[str, ...] = (
    "clean_source_identity",
    "artifact_checksums",
    "resource_manifest_parity",
    "unit_tests",
    "property_tests",
    "integration_tests",
    "conformance_tests",
    "packaging_tests",
    "security_privacy_scan",
    "capability_matrix",
    "dependency_vulnerability_license",
    "clean_install",
)
_WORKFLOW_RESULTS = frozenset({"success", "failure", "cancelled", "skipped"})
_SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class ReleaseInputError(Exception):
    """A bounded input-construction failure suitable for a public workflow log."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class GateRecord:
    name: str
    source_results: tuple[str, ...]
    input_digests: tuple[str, ...]

    def render(self) -> dict[str, object]:
        if all(result == "success" for result in self.source_results):
            status, reason = "pass", "all_sources_succeeded"
        elif "failure" in self.source_results:
            status, reason = "fail", "source_failure"
        elif "cancelled" in self.source_results:
            status, reason = "fail", "source_cancelled"
        else:
            status, reason = "incomplete", "source_skipped"
        return {
            "status": status,
            "reason_code": reason,
            "input_digests": list(self.input_digests),
        }


def _read_json(path: Path, *, expected_keys: frozenset[str] | None = None) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseInputError("input_missing", detail=str(path))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseInputError("input_invalid_json", detail=str(path)) from exc
    if not isinstance(value, dict):
        raise ReleaseInputError("input_invalid_shape", detail=str(path))
    document = cast(dict[str, object], value)
    if expected_keys is not None and frozenset(document) != expected_keys:
        raise ReleaseInputError("input_unknown_or_missing_field", detail=str(path))
    return document


def _normalise_digest(raw: str, *, detail: str) -> str:
    if not _SHA256.fullmatch(raw):
        raise ReleaseInputError("digest_invalid", detail=detail)
    return raw if raw.startswith("sha256:") else f"sha256:{raw}"


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _artifacts(
    artifact_root: Path, output_parent: Path, candidate_digest: str
) -> list[dict[str, str]]:
    if artifact_root.is_symlink() or not artifact_root.is_dir():
        raise ReleaseInputError("artifact_root_missing", detail=str(artifact_root))
    if not _path_within(artifact_root, output_parent):
        raise ReleaseInputError("artifact_root_outside_output_root", detail=str(artifact_root))

    found = sorted(
        (path for path in artifact_root.iterdir() if path.name.endswith((".whl", ".tar.gz"))),
        key=lambda path: path.name.encode("utf-8"),
    )
    if not found:
        raise ReleaseInputError("artifact_missing", detail=str(artifact_root))

    checksum_path = artifact_root / "SHA256SUMS"
    if checksum_path.is_symlink() or not checksum_path.is_file():
        raise ReleaseInputError("candidate_checksum_missing")
    if _hash(checksum_path) != candidate_digest:
        raise ReleaseInputError("candidate_artifact_digest_mismatch")
    try:
        checksum_lines = checksum_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseInputError("candidate_checksum_invalid") from exc
    declared: dict[str, str] = {}
    for line in checksum_lines:
        digest, separator, source_path = line.partition("  ")
        name = PurePosixPath(source_path).name
        if (
            separator != "  "
            or not _SHA256.fullmatch(digest)
            or not name.endswith((".whl", ".tar.gz"))
            or name in declared
        ):
            raise ReleaseInputError("candidate_checksum_invalid")
        declared[name] = _normalise_digest(digest, detail=name)
    if set(declared) != {path.name for path in found}:
        raise ReleaseInputError("candidate_checksum_invalid")

    entries: list[dict[str, str]] = []
    for path in found:
        if path.is_symlink() or not path.is_file() or not _path_within(path, artifact_root):
            raise ReleaseInputError("artifact_invalid", detail=path.name)
        artifact_digest = _hash(path)
        if artifact_digest != declared[path.name]:
            raise ReleaseInputError("candidate_artifact_digest_mismatch")
        entries.append(
            {
                "path": path.resolve().relative_to(output_parent.resolve()).as_posix(),
                "sha256": artifact_digest,
            }
        )
    return entries


def _gate_record(raw: str) -> GateRecord:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseInputError("gate_record_invalid_json") from exc
    if not isinstance(value, dict):
        raise ReleaseInputError("gate_record_invalid_shape")
    fields = cast(dict[str, object], value)
    if set(fields) != {"name", "source_results", "input_digests"}:
        raise ReleaseInputError("gate_record_invalid_shape")
    name = fields["name"]
    source_results = fields["source_results"]
    input_digests = fields["input_digests"]
    if not isinstance(name, str) or name not in _REQUIRED_GATES:
        raise ReleaseInputError("gate_record_unknown", detail=str(name))
    if not isinstance(source_results, list) or not source_results:
        raise ReleaseInputError("gate_record_result_invalid", detail=name)
    results: list[str] = []
    for result in cast(list[object], source_results):
        if not isinstance(result, str) or result not in _WORKFLOW_RESULTS:
            raise ReleaseInputError("gate_record_result_invalid", detail=name)
        results.append(result)
    if not isinstance(input_digests, list) or not input_digests:
        raise ReleaseInputError("gate_record_digest_invalid", detail=name)
    digests: list[str] = []
    for digest in cast(list[object], input_digests):
        if not isinstance(digest, str):
            raise ReleaseInputError("gate_record_digest_invalid", detail=name)
        digests.append(_normalise_digest(digest, detail=name))
    normalized = tuple(digests)
    if len(set(normalized)) != len(normalized):
        raise ReleaseInputError("gate_record_digest_duplicate", detail=name)
    return GateRecord(name, tuple(results), normalized)


def _gates(raw_records: Sequence[str]) -> dict[str, object]:
    by_name: dict[str, GateRecord] = {}
    for raw in raw_records:
        record = _gate_record(raw)
        if record.name in by_name:
            raise ReleaseInputError("gate_record_duplicate", detail=record.name)
        by_name[record.name] = record
    missing = [name for name in _REQUIRED_GATES if name not in by_name]
    if missing:
        raise ReleaseInputError("gate_record_missing", detail=",".join(missing))
    return {name: by_name[name].render() for name in _REQUIRED_GATES}


def _support_cells(path: Path, candidate_digest: str) -> list[dict[str, object]]:
    document = _read_json(path)
    # Frozen legacy identifier (ADR-048): capability-matrix format tag of release inputs.
    if document.get("schema") != "yoetz.capability-matrix/1":
        raise ReleaseInputError("support_matrix_schema_invalid", detail=str(path))
    if document.get("candidate_artifact_digest") != candidate_digest:
        raise ReleaseInputError("support_matrix_candidate_digest_mismatch", detail=str(path))
    cells = document.get("cells")
    if not isinstance(cells, list):
        raise ReleaseInputError("support_matrix_cells_invalid", detail=str(path))

    rendered: list[dict[str, object]] = []
    for cell in cast(list[object], cells):
        if not isinstance(cell, dict):
            raise ReleaseInputError("support_matrix_cell_invalid", detail=str(path))
        fields = cast(dict[str, object], cell)
        required = ("capability_family", "external_version", "platform", "requirement_id", "status")
        if not all(isinstance(fields.get(key), str) and str(fields[key]) for key in required):
            raise ReleaseInputError("support_matrix_cell_invalid", detail=str(path))
        rendered.append(
            {
                "label": ":".join(str(fields[key]) for key in required[:-1]),
                "status": str(fields["status"]),
            }
        )
    return sorted(rendered, key=lambda cell: str(cell["label"]).encode("utf-8"))


def _limitations(path: Path) -> list[dict[str, str]]:
    document = _read_json(path, expected_keys=frozenset({"schema", "limitations"}))
    # Frozen legacy identifier (ADR-048): format tag of release/known-limitations.json.
    if document["schema"] != "yoetz.release-known-limitations/1":
        raise ReleaseInputError("limitations_schema_invalid", detail=str(path))
    raw_items = document["limitations"]
    if not isinstance(raw_items, list):
        raise ReleaseInputError("limitations_invalid", detail=str(path))
    items: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in cast(list[object], raw_items):
        if not isinstance(item, dict):
            raise ReleaseInputError("limitation_invalid", detail=str(path))
        fields = cast(dict[str, object], item)
        if set(fields) != {"code", "description"}:
            raise ReleaseInputError("limitation_invalid", detail=str(path))
        code, description = fields["code"], fields["description"]
        if (
            not isinstance(code, str)
            or not code
            or not isinstance(description, str)
            or not description
        ):
            raise ReleaseInputError("limitation_invalid", detail=str(path))
        if code in seen:
            raise ReleaseInputError("limitation_duplicate", detail=code)
        seen.add(code)
        items.append({"code": code, "description": description})
    return sorted(items, key=lambda item: item["code"].encode("utf-8"))


def build_manifest(args: argparse.Namespace) -> dict[str, object]:
    version = str(args.candidate_version)
    tag = str(args.candidate_tag)
    commit = str(args.candidate_commit)
    if not version or tag != f"v{version}" or not _COMMIT.fullmatch(commit):
        raise ReleaseInputError("candidate_identity_invalid")
    candidate_digest = _normalise_digest(str(args.candidate_digest), detail="candidate")
    output = cast(Path, args.output)
    output_parent = output.parent.resolve()
    return {
        "candidate_version": version,
        "candidate_tag": tag,
        "candidate_commit": commit,
        "artifacts": _artifacts(cast(Path, args.artifact_root), output_parent, candidate_digest),
        "gates": _gates(cast(list[str], args.gate_record)),
        "support_matrix_cells": _support_cells(cast(Path, args.support_matrix), candidate_digest),
        "known_limitations": _limitations(cast(Path, args.known_limitations)),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="build_release_inputs.py")
    parser.add_argument("--candidate-version", required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--support-matrix", type=Path, required=True)
    parser.add_argument("--known-limitations", type=Path, required=True)
    parser.add_argument("--gate-record", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = build_manifest(args)
        output = cast(Path, args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output.parent, prefix=".release-inputs-", delete=False
        ) as handle:
            json.dump(manifest, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        os.replace(temporary, output)
    except ReleaseInputError as exc:
        print(f"build_release_inputs: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1
    except OSError:
        print("build_release_inputs: FAIL (io_error)", file=sys.stderr)
        return 1
    print("build_release_inputs: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
