"""Assemble the deterministic release proof bundle for one tagged FinishUP candidate.

Assembles the evidence that justifies a specific public-alpha artifact and its bounded support
claims: artifact checksums, build/test/scan gate results, resource identity, platform/SQLite
support, capability matrix, known limitations, and offline verification instructions. The output
describes proved bytes; it never manufactures pass evidence or signs on behalf of an unavailable
signing system.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.protocol.canonical import JsonValue, canonical_encode

__all__ = [
    "GateResult",
    "ReleaseArtifact",
    "ReleaseEvidence",
    "ReleaseInputs",
    "evaluate_release_gates",
    "hash_artifacts",
    "load_and_validate_inputs",
    "main",
    "render_checksums",
    "render_evidence_json",
    "render_limitations",
    "render_support_matrix",
    "verify_evidence_bundle",
    "write_evidence_bundle",
]


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

_ALLOWED_GATE_STATUS: Final = frozenset({"pass", "fail", "incomplete", "not_applicable"})
_MAX_INPUT_BYTES: Final = 50_000_000
_MAX_ARTIFACT_BYTES: Final = 500_000_000

# The required release gate names. Every one must be represented, explicitly, in the input
# manifest's ``gates`` object; a missing key is ``incomplete``, never silently omitted.
_REQUIRED_GATES: Final[tuple[str, ...]] = (
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


@dataclass(frozen=True, slots=True)
class ReleaseArtifact:
    filename: str
    relative_path: str
    size: int
    sha256: str
    expected_sha256: str


@dataclass(frozen=True, slots=True)
class GateResult:
    name: str
    status: str
    reason_code: str
    input_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReleaseInputs:
    candidate_version: str
    candidate_tag: str
    candidate_commit: str
    artifacts: tuple[ReleaseArtifact, ...]
    gate_manifest: Mapping[str, object]
    support_matrix_cells: tuple[Mapping[str, object], ...]
    known_limitations: tuple[Mapping[str, object], ...]
    root: Path


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    candidate_version: str
    candidate_tag: str
    candidate_commit: str
    artifacts: tuple[ReleaseArtifact, ...]
    gates: tuple[GateResult, ...]
    eligible: bool
    evidence_set_digest: str


class ReleaseEvidenceError(Exception):
    """A bounded, traceback-free input-loading/hashing/gate failure."""

    def __init__(self, reason: str, *, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def _read_json(path: Path, *, max_bytes: int) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseEvidenceError("input_missing", detail=str(path))
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ReleaseEvidenceError("input_too_large", detail=str(path))
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseEvidenceError("input_invalid_json", detail=str(path)) from exc
    if not isinstance(parsed, dict):
        raise ReleaseEvidenceError("input_invalid_shape", detail=str(path))
    return cast(dict[str, object], parsed)


def load_and_validate_inputs(manifest_path: Path) -> ReleaseInputs:
    """Load the explicit canonical release-input manifest and verify every declared digest."""

    manifest = _read_json(manifest_path, max_bytes=_MAX_INPUT_BYTES)
    root = manifest_path.parent

    try:
        candidate_version = str(manifest["candidate_version"])
        candidate_tag = str(manifest["candidate_tag"])
        candidate_commit = str(manifest["candidate_commit"])
        raw_artifacts = cast(list[dict[str, object]], manifest["artifacts"])
        gate_manifest = cast(dict[str, object], manifest.get("gates", {}))
        support_cells = cast(list[dict[str, object]], manifest.get("support_matrix_cells", []))
        limitations = cast(list[dict[str, object]], manifest.get("known_limitations", []))
    except KeyError as exc:
        raise ReleaseEvidenceError("input_manifest_field_missing") from exc

    artifacts: list[ReleaseArtifact] = []
    for raw in raw_artifacts:
        try:
            relative_path = str(raw["path"])
            expected_sha256 = str(raw["sha256"])
        except KeyError as exc:
            raise ReleaseEvidenceError("artifact_entry_field_missing") from exc
        artifact_path = root / relative_path
        if artifact_path.is_symlink() or not artifact_path.is_file():
            raise ReleaseEvidenceError("artifact_missing", detail=relative_path)
        artifacts.append(
            ReleaseArtifact(
                filename=Path(relative_path).name,
                relative_path=relative_path,
                size=0,
                sha256="",
                expected_sha256=expected_sha256,
            )
        )

    return ReleaseInputs(
        candidate_version=candidate_version,
        candidate_tag=candidate_tag,
        candidate_commit=candidate_commit,
        artifacts=tuple(artifacts),
        gate_manifest=gate_manifest,
        support_matrix_cells=tuple(support_cells),
        known_limitations=tuple(limitations),
        root=root,
    )


def hash_artifacts(inputs: ReleaseInputs) -> tuple[ReleaseArtifact, ...]:
    """Re-hash every declared artifact and require an exact match against its expected digest."""

    hashed: list[ReleaseArtifact] = []
    for artifact in inputs.artifacts:
        path = inputs.root / artifact.relative_path
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ReleaseEvidenceError(
                "artifact_changed_during_hash", detail=artifact.relative_path
            )
        if len(data) > _MAX_ARTIFACT_BYTES:
            raise ReleaseEvidenceError("artifact_too_large", detail=artifact.relative_path)
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if digest != artifact.expected_sha256:
            raise ReleaseEvidenceError("artifact_digest_mismatch", detail=artifact.relative_path)
        hashed.append(
            ReleaseArtifact(
                filename=artifact.filename,
                relative_path=artifact.relative_path,
                size=len(data),
                sha256=digest,
                expected_sha256=artifact.expected_sha256,
            )
        )
    return tuple(sorted(hashed, key=lambda item: item.relative_path.encode("utf-8")))


# --------------------------------------------------------------------------
# Gate evaluation
# --------------------------------------------------------------------------


def evaluate_release_gates(inputs: ReleaseInputs) -> tuple[GateResult, ...]:
    """Evaluate every required named gate to a deterministic, bounded status."""

    results: list[GateResult] = []
    for name in _REQUIRED_GATES:
        entry = inputs.gate_manifest.get(name)
        if entry is None:
            results.append(
                GateResult(
                    name=name,
                    status="incomplete",
                    reason_code="gate_not_reported",
                    input_digests=(),
                )
            )
            continue
        if not isinstance(entry, dict):
            results.append(
                GateResult(
                    name=name,
                    status="incomplete",
                    reason_code="gate_shape_invalid",
                    input_digests=(),
                )
            )
            continue

        fields = cast(dict[str, object], entry)
        status = str(fields.get("status", "incomplete"))
        reason_code = str(fields.get("reason_code", "unspecified"))
        digests = tuple(
            sorted(str(item) for item in cast(list[object], fields.get("input_digests", [])))
        )

        if status not in _ALLOWED_GATE_STATUS:
            results.append(
                GateResult(
                    name=name,
                    status="incomplete",
                    reason_code="gate_status_invalid",
                    input_digests=digests,
                )
            )
            continue
        results.append(
            GateResult(name=name, status=status, reason_code=reason_code, input_digests=digests)
        )

    return tuple(results)


def _eligible(gates: Sequence[GateResult]) -> bool:
    return all(gate.status in {"pass", "not_applicable"} for gate in gates)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _evidence_set_digest(
    inputs: ReleaseInputs, artifacts: Sequence[ReleaseArtifact], gates: Sequence[GateResult]
) -> str:
    material: JsonValue = {
        "artifacts": [
            {"path": artifact.relative_path, "sha256": artifact.sha256} for artifact in artifacts
        ],
        "candidate_commit": inputs.candidate_commit,
        "candidate_tag": inputs.candidate_tag,
        "candidate_version": inputs.candidate_version,
        "gates": [
            {"name": gate.name, "reason_code": gate.reason_code, "status": gate.status}
            for gate in gates
        ],
    }
    return f"sha256:{hashlib.sha256(canonical_encode(material)).hexdigest()}"


def render_evidence_json(evidence: ReleaseEvidence) -> bytes:
    """Render ``release-evidence.json`` per schema ``yoetz.release-evidence/1``."""

    document: dict[str, JsonValue] = {
        "artifacts": [
            {
                "filename": artifact.filename,
                "path": artifact.relative_path,
                "sha256": artifact.sha256,
                "size": artifact.size,
            }
            for artifact in evidence.artifacts
        ],
        "candidate_commit": evidence.candidate_commit,
        "candidate_tag": evidence.candidate_tag,
        "candidate_version": evidence.candidate_version,
        "eligible": evidence.eligible,
        "evidence_set_digest": evidence.evidence_set_digest,
        "gates": [
            {
                "input_digests": list(gate.input_digests),
                "name": gate.name,
                "reason_code": gate.reason_code,
                "status": gate.status,
            }
            for gate in evidence.gates
        ],
        "schema": "yoetz.release-evidence/1",
        "signature_status": "not_provided",
    }
    return canonical_encode(document)


def render_checksums(evidence: ReleaseEvidence) -> bytes:
    """Render ``SHA256SUMS`` for every release artifact, in ASCII path order."""

    lines = [
        f"{artifact.sha256.removeprefix('sha256:')}  {artifact.relative_path}"
        for artifact in evidence.artifacts
    ]
    return ("\n".join(lines) + "\n").encode("utf-8") if lines else b""


def render_support_matrix(inputs: ReleaseInputs) -> bytes:
    """Render ``support-matrix.md`` from structured platform/capability cells."""

    lines = ["# Support matrix", "", "| Cell | Status |", "|---|---|"]
    for cell in sorted(
        inputs.support_matrix_cells, key=lambda item: json.dumps(item, sort_keys=True)
    ):
        label = str(cell.get("label", "unknown"))
        status = str(cell.get("status", "untested"))
        lines.append(f"| {label} | {status} |")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def render_limitations(inputs: ReleaseInputs) -> bytes:
    """Render ``known-limitations.md`` from reviewed bounded limitation entries."""

    lines = ["# Known limitations", ""]
    for entry in sorted(inputs.known_limitations, key=lambda item: str(item.get("code", ""))):
        code = str(entry.get("code", "UNSPECIFIED"))
        description = str(entry.get("description", ""))
        lines.append(f"- `{code}`: {description}")
    if not inputs.known_limitations:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def _render_verify_instructions(evidence: ReleaseEvidence) -> bytes:
    lines = [
        "# Offline verification",
        "",
        "```text",
        "sha256sum -c SHA256SUMS",
        "python scripts/generate_release_evidence.py \\",
        "  --input-manifest dist/release-inputs.json \\",
        f"  --output-dir dist/release-evidence/{evidence.candidate_version} --check",
        "```",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


# --------------------------------------------------------------------------
# Bundle write/verify
# --------------------------------------------------------------------------

_BUNDLE_FILES: Final = (
    "SHA256SUMS",
    "VERIFY.md",
    "known-limitations.md",
    "release-evidence.json",
    "support-matrix.md",
)


def write_evidence_bundle(output_dir: Path, documents: Mapping[str, bytes]) -> None:
    """Stage, fsync, and atomically publish the release-evidence bundle.

    A version directory is replaced only when it is absent or exactly regenerable: if it already
    exists and matches ``documents`` byte-for-byte this is a deterministic idempotent no-op; if it
    exists with any different byte, this fails closed rather than rebinding a published version to
    different evidence.
    """

    if output_dir.exists():
        try:
            verify_evidence_bundle(output_dir, documents)
        except ReleaseEvidenceError as exc:
            raise ReleaseEvidenceError(
                "output_dir_conflicts_with_published_version", detail=exc.detail
            ) from exc
        return

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output_dir.parent, prefix=".release-evidence-") as staging:
        staging_root = Path(staging)
        for name, data in documents.items():
            destination = staging_root / name
            destination.write_bytes(data)
            with open(destination, "rb") as handle:
                os.fsync(handle.fileno())
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging_root, output_dir)


def verify_evidence_bundle(output_dir: Path, expected: Mapping[str, bytes]) -> None:
    """Recompute and compare every published bundle document byte-for-byte."""

    for name, data in expected.items():
        candidate = output_dir / name
        if candidate.is_symlink() or not candidate.is_file():
            raise ReleaseEvidenceError("bundle_file_missing", detail=name)
        if candidate.read_bytes() != data:
            raise ReleaseEvidenceError("bundle_file_mismatch", detail=name)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_release_evidence.py",
        description="Assemble or verify the deterministic release proof bundle for one candidate.",
    )
    parser.add_argument("--input-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        inputs = load_and_validate_inputs(args.input_manifest)
        artifacts = hash_artifacts(inputs)
        gates = evaluate_release_gates(inputs)
        evidence = ReleaseEvidence(
            candidate_version=inputs.candidate_version,
            candidate_tag=inputs.candidate_tag,
            candidate_commit=inputs.candidate_commit,
            artifacts=artifacts,
            gates=gates,
            eligible=_eligible(gates),
            evidence_set_digest=_evidence_set_digest(inputs, artifacts, gates),
        )
    except ReleaseEvidenceError as exc:
        print(f"generate_release_evidence: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1

    documents = {
        "release-evidence.json": render_evidence_json(evidence),
        "SHA256SUMS": render_checksums(evidence),
        "support-matrix.md": render_support_matrix(inputs),
        "known-limitations.md": render_limitations(inputs),
        "VERIFY.md": _render_verify_instructions(evidence),
    }

    if not evidence.eligible:
        print(
            "generate_release_evidence: FAIL (one or more required gates did not pass)",
            file=sys.stderr,
        )
        for gate in evidence.gates:
            if gate.status not in {"pass", "not_applicable"}:
                print(f"  {gate.name}: {gate.status} ({gate.reason_code})", file=sys.stderr)
        return 1

    try:
        if args.check:
            verify_evidence_bundle(args.output_dir, documents)
        else:
            write_evidence_bundle(args.output_dir, documents)
            verify_evidence_bundle(args.output_dir, documents)
    except ReleaseEvidenceError as exc:
        print(f"generate_release_evidence: FAIL ({exc.reason}) {exc.detail}", file=sys.stderr)
        return 1

    verb = "VERIFIED" if args.check else "WROTE"
    print(
        f"generate_release_evidence: {verb} ({len(evidence.artifacts)} artifact(s), all gates pass)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
