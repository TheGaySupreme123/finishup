"""Aggregate redacted external capability evidence into one honest support matrix.

Turns per-case capability evidence from installed-artifact tests into a deterministic support
matrix. This script aggregates observations; it never runs Codex, MCP, providers, keyrings, or
product operations, and it never upgrades an untested version/platform pair into a support claim.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = [
    "CapabilityEvidence",
    "CapabilityMatrix",
    "aggregate_capabilities",
    "load_evidence",
    "main",
    "render_json",
    "render_markdown",
    "validate_evidence",
]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

_ALLOWED_OUTCOMES: Final = frozenset({"pass", "fail", "unsupported", "inconclusive"})
_MAX_EVIDENCE_FILES: Final = 20_000
_MAX_EVIDENCE_BYTES: Final = 5_000_000
_FORBIDDEN_RECORD_FIELDS: Final = frozenset(
    {"transcript", "prompt", "source_payload", "command_output", "credential", "raw_output"}
)


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    schema: str
    case_id: str
    requirement_id: str
    capability_family: str
    artifact_digest: str
    resource_set_digest: str
    platform: str
    external_version: str
    outcome: str
    started_at: str
    finished_at: str
    duration_seconds: float
    evidence_locator_digest: str
    limitation_codes: tuple[str, ...]
    test_revision: str
    record_digest: str


@dataclass(frozen=True, slots=True)
class CapabilityCell:
    capability_family: str
    external_version: str
    platform: str
    requirement_id: str
    status: str


@dataclass(frozen=True, slots=True)
class CapabilityMatrix:
    candidate_artifact_digest: str
    policy_digest: str
    evidence_set_digest: str
    cells: tuple[CapabilityCell, ...]
    matrix_digest: str


class CapabilityMatrixError(Exception):
    """A bounded, traceback-free evidence-loading/validation/aggregation failure."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def _read_canonical_json(path: Path, *, max_bytes: int) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise CapabilityMatrixError("file_missing", detail=str(path))
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise CapabilityMatrixError("file_too_large", detail=str(path))
    try:
        parsed = json.loads(
            data.decode("utf-8"),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("float_forbidden")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CapabilityMatrixError("invalid_json", detail=str(path)) from exc
    if not isinstance(parsed, dict):
        raise CapabilityMatrixError("invalid_json_shape", detail=str(path))
    return cast(dict[str, object], parsed)


def load_evidence(paths: Sequence[Path]) -> tuple[CapabilityEvidence, ...]:
    """Load, canonically parse, and structurally validate every evidence file, in ASCII order."""

    records: list[CapabilityEvidence] = []
    seen_identity: set[tuple[str, str, str, str]] = set()

    for path in sorted(paths, key=lambda item: item.as_posix().encode("utf-8")):
        payload = _read_canonical_json(path, max_bytes=_MAX_EVIDENCE_BYTES)

        forbidden_present = _FORBIDDEN_RECORD_FIELDS & payload.keys()
        if forbidden_present:
            raise CapabilityMatrixError("forbidden_field_present", detail=str(path))

        try:
            outcome = str(payload["outcome"])
            if outcome not in _ALLOWED_OUTCOMES:
                raise CapabilityMatrixError("outcome_invalid", detail=str(path))
            started_at = str(payload["started_at"])
            finished_at = str(payload["finished_at"])
            start_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            finish_dt = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
            duration = (finish_dt - start_dt).total_seconds()
            if duration < 0:
                raise CapabilityMatrixError("finish_before_start", detail=str(path))

            record = CapabilityEvidence(
                schema=str(payload["schema"]),
                case_id=str(payload["case_id"]),
                requirement_id=str(payload["requirement_id"]),
                capability_family=str(payload["capability_family"]),
                artifact_digest=str(payload["artifact_digest"]),
                resource_set_digest=str(payload["resource_set_digest"]),
                platform=str(payload["platform"]),
                external_version=str(payload["external_version"]),
                outcome=outcome,
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=duration,
                evidence_locator_digest=str(payload.get("evidence_locator_digest", "")),
                limitation_codes=tuple(
                    sorted(
                        str(item)
                        for item in cast(list[object], payload.get("limitation_codes", []))
                    )
                ),
                test_revision=str(payload["test_revision"]),
                record_digest=str(payload["record_digest"]),
            )
        except (KeyError, ValueError) as exc:
            raise CapabilityMatrixError(
                "evidence_field_missing_or_invalid", detail=str(path)
            ) from exc

        identity = (
            record.case_id,
            record.artifact_digest,
            record.platform,
            record.external_version,
        )
        if identity in seen_identity:
            raise CapabilityMatrixError("duplicate_evidence_identity", detail=str(path))
        seen_identity.add(identity)
        records.append(record)

    if len(records) > _MAX_EVIDENCE_FILES:
        raise CapabilityMatrixError("too_many_evidence_files")

    return tuple(records)


def validate_evidence(record: CapabilityEvidence, candidate_artifact_digest: str) -> None:
    """Validate that one record belongs to the exact candidate under evaluation."""

    if record.artifact_digest != candidate_artifact_digest:
        raise CapabilityMatrixError("evidence_wrong_candidate", detail=record.case_id)
    if not record.case_id or not record.requirement_id or not record.capability_family:
        raise CapabilityMatrixError("evidence_identity_incomplete", detail=record.case_id)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def aggregate_capabilities(
    records: Sequence[CapabilityEvidence],
    policy: Mapping[str, object],
    *,
    candidate_artifact_digest: str,
    policy_digest: str,
) -> CapabilityMatrix:
    """Aggregate validated records into a conservative, deterministic capability matrix."""

    required_cases = cast(list[dict[str, object]], policy.get("required_cases", []))

    grouped: dict[tuple[str, str, str, str], list[CapabilityEvidence]] = {}
    for record in records:
        key = (
            record.capability_family,
            record.external_version,
            record.platform,
            record.requirement_id,
        )
        grouped.setdefault(key, []).append(record)

    cells: list[CapabilityCell] = []
    for requirement in required_cases:
        family = str(requirement["capability_family"])
        version = str(requirement["external_version"])
        platform = str(requirement["platform"])
        requirement_id = str(requirement["requirement_id"])
        key = (family, version, platform, requirement_id)
        cell_records = grouped.get(key, ())

        if not cell_records:
            status = "untested"
        else:
            outcomes = {record.outcome for record in cell_records}
            has_conflict = "pass" in outcomes and "fail" in outcomes
            if has_conflict:
                status = "inconclusive"
            elif "fail" in outcomes:
                status = "failed"
            elif outcomes == {"pass"}:
                status = "supported"
            elif "unsupported" in outcomes and outcomes <= {"unsupported"}:
                status = "unsupported"
            else:
                status = "inconclusive"

        cells.append(
            CapabilityCell(
                capability_family=family,
                external_version=version,
                platform=platform,
                requirement_id=requirement_id,
                status=status,
            )
        )

    ordered_cells = tuple(
        sorted(
            cells,
            key=lambda cell: (
                cell.capability_family,
                cell.external_version,
                cell.platform,
                cell.requirement_id,
            ),
        )
    )

    evidence_material: JsonValue = [
        {
            "artifact_digest": record.artifact_digest,
            "case_id": record.case_id,
            "outcome": record.outcome,
            "platform": record.platform,
        }
        for record in sorted(records, key=lambda item: item.case_id.encode("utf-8"))
    ]
    evidence_set_digest = f"sha256:{_sha256_hex(canonical_encode(evidence_material))}"

    matrix_material: JsonValue = [
        {
            "capability_family": cell.capability_family,
            "external_version": cell.external_version,
            "platform": cell.platform,
            "requirement_id": cell.requirement_id,
            "status": cell.status,
        }
        for cell in ordered_cells
    ]
    matrix_digest = f"sha256:{_sha256_hex(canonical_encode(matrix_material))}"

    return CapabilityMatrix(
        candidate_artifact_digest=candidate_artifact_digest,
        policy_digest=policy_digest,
        evidence_set_digest=evidence_set_digest,
        cells=ordered_cells,
        matrix_digest=matrix_digest,
    )


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def render_json(matrix: CapabilityMatrix) -> bytes:
    """Render the canonical JSON capability matrix, schema ``yoetz.capability-matrix/1``."""

    document: dict[str, JsonValue] = {
        "candidate_artifact_digest": matrix.candidate_artifact_digest,
        "cells": [
            {
                "capability_family": cell.capability_family,
                "external_version": cell.external_version,
                "platform": cell.platform,
                "requirement_id": cell.requirement_id,
                "status": cell.status,
            }
            for cell in matrix.cells
        ],
        "evidence_set_digest": matrix.evidence_set_digest,
        "matrix_digest": matrix.matrix_digest,
        "policy_digest": matrix.policy_digest,
        "schema": "yoetz.capability-matrix/1",
    }
    return canonical_encode(document)


def render_markdown(matrix: CapabilityMatrix) -> bytes:
    """Render a deterministic human-readable table view of the JSON matrix."""

    lines = [
        "# FinishUP capability matrix",
        "",
        f"Candidate artifact: `{matrix.candidate_artifact_digest}`",
        f"Policy: `{matrix.policy_digest}`",
        f"Evidence set: `{matrix.evidence_set_digest}`",
        f"Matrix digest: `{matrix.matrix_digest}`",
        "",
        "| Capability family | External version | Platform | Requirement | Status |",
        "|---|---|---|---|---|",
    ]
    for cell in matrix.cells:
        lines.append(
            f"| {cell.capability_family} | {cell.external_version} | {cell.platform} | "
            f"{cell.requirement_id} | {cell.status} |"
        )
    lines.append("")
    return "\n".join(lines).encode("utf-8")


# --------------------------------------------------------------------------
# Gate evaluation
# --------------------------------------------------------------------------


def _evaluate_gate(matrix: CapabilityMatrix) -> bool:
    return all(cell.status == "supported" for cell in matrix.cells)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_capability_matrix.py",
        description="Aggregate per-case capability evidence into one deterministic support matrix.",
    )
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--markdown-out", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        candidate = _read_canonical_json(args.candidate_manifest, max_bytes=_MAX_EVIDENCE_BYTES)
        policy = _read_canonical_json(args.policy, max_bytes=_MAX_EVIDENCE_BYTES)
        candidate_digest = str(candidate["artifact_digest"])
        policy_digest = f"sha256:{_sha256_hex(canonical_encode(cast(JsonValue, policy)))}"

        if not args.evidence_dir.is_dir():
            raise CapabilityMatrixError("evidence_dir_missing", detail=str(args.evidence_dir))
        evidence_paths = [
            path
            for path in sorted(args.evidence_dir.rglob("*.json"))
            if path.is_file() and not path.is_symlink()
        ]
        records = load_evidence(evidence_paths)
        for record in records:
            validate_evidence(record, candidate_digest)

        matrix = aggregate_capabilities(
            records,
            policy,
            candidate_artifact_digest=candidate_digest,
            policy_digest=policy_digest,
        )
    except CapabilityMatrixError as exc:
        print(f"generate_capability_matrix: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1
    except (KeyError, OSError) as exc:
        print(f"generate_capability_matrix: invocation error: {exc}", file=sys.stderr)
        return 2

    json_bytes = render_json(matrix)
    markdown_bytes = render_markdown(matrix)

    if args.check:
        json_ok = args.json_out.is_file() and args.json_out.read_bytes() == json_bytes
        markdown_ok = (
            args.markdown_out.is_file() and args.markdown_out.read_bytes() == markdown_bytes
        )
        if not (json_ok and markdown_ok):
            print("generate_capability_matrix: FAIL (output drift)", file=sys.stderr)
            return 1
    else:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            dir=args.json_out.parent, prefix=".capability-matrix-"
        ) as staging:
            staging_root = Path(staging)
            (staging_root / "matrix.json").write_bytes(json_bytes)
            (staging_root / "matrix.md").write_bytes(markdown_bytes)
            for name in ("matrix.json", "matrix.md"):
                with open(staging_root / name, "rb") as handle:
                    os.fsync(handle.fileno())
            os.replace(staging_root / "matrix.json", args.json_out)
            os.replace(staging_root / "matrix.md", args.markdown_out)

    if not _evaluate_gate(matrix):
        print(
            "generate_capability_matrix: FAIL (claim gate: not every cell is supported)",
            file=sys.stderr,
        )
        for cell in matrix.cells:
            if cell.status != "supported":
                print(
                    f"  {cell.capability_family} {cell.external_version} {cell.platform} "
                    f"{cell.requirement_id}: {cell.status}",
                    file=sys.stderr,
                )
        return 1

    print(f"generate_capability_matrix: PASS ({len(matrix.cells)} cell(s), all supported)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
