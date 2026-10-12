"""Converge and verify every generated artifact in the packaged-resource ripple.

Resource inventory changes cross four generated layers: the package resource manifest, the
version-manifest schema, the schema inventory/runtime-support digests, and the packaged copies of
those files, followed by the committed Codex plugin and skill trees. This command owns that order
and repeats it to a byte-identical fixed point instead of requiring a multi-pass manual sequence.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Final

_SCRIPT_ROOT = Path(__file__).resolve().parent
_DEFAULT_REPO_ROOT = _SCRIPT_ROOT.parent

_MAX_PASSES: Final = 5
_VERSION_MANIFEST_SCHEMA: Final = "version/version-manifest-2.3.0.schema.json"
_OWNED_ROOTS: Final = (
    "schemas",
    "src/yoetz/resources",
    ".agents/plugins/yoetz",
    ".agents/skills/yoetz",
)
_OWNED_FILES: Final = (
    "skills/codex/yoetz/manifest.json",
    "support/runtime-support.json",
)
_SEMANTIC_CHECK_SOURCE: Final = """\
import json
import pathlib

from jsonschema import Draft202012Validator

from yoetz.protocol.schemas import load_schema_catalog
from yoetz.version import build_version_manifest, version_manifest_json

# Matching source and mirror bytes can share a stale schema inventory. Exercise the same closed
# catalog loader used by every public request before claiming the package is usable.
load_schema_catalog()
schema = json.loads(
    pathlib.Path("schemas/version/version-manifest-2.3.0.schema.json").read_bytes()
)
document = json.loads(version_manifest_json(build_version_manifest(), include_resources=True))
Draft202012Validator(schema).validate(document)
"""


def _iter_owned_files(repo_root: Path) -> Iterator[Path]:
    """Yield every byte-owned artifact in deterministic path order."""

    paths: list[Path] = []
    for relative_root in _OWNED_ROOTS:
        root = repo_root / relative_root
        if root.is_dir():
            paths.extend(path for path in root.rglob("*") if path.is_file())
    paths.extend(repo_root / relative_path for relative_path in _OWNED_FILES)
    yield from sorted(set(paths), key=lambda path: path.relative_to(repo_root).as_posix().encode())


def _owned_digest(repo_root: Path) -> str:
    """Bind the complete owned byte set, including relative names, for convergence checks."""

    digest = hashlib.sha256()
    for path in _iter_owned_files(repo_root):
        relative = path.relative_to(repo_root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _child_environment(repo_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    source_root = str(repo_root / "src")
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_root if not existing else os.pathsep.join((source_root, existing))
    )
    return environment


def _run(repo_root: Path, script_name: str, *arguments: str) -> bool:
    script = repo_root / "scripts" / script_name
    completed = subprocess.run(
        [sys.executable, str(script), *arguments],
        cwd=repo_root,
        env=_child_environment(repo_root),
        check=False,
    )
    return completed.returncode == 0


def _preflight(repo_root: Path) -> bool:
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "from verify_resource_manifest import load_inventory_config; "
            "from yoetz.version import REVIEWED_RESOURCE_COUNT; "
            "print(len(load_inventory_config().entries), REVIEWED_RESOURCE_COUNT)",
        ],
        cwd=repo_root / "scripts",
        env=_child_environment(repo_root),
        capture_output=True,
        check=False,
        text=True,
    )
    if probe.returncode != 0:
        print("sync_resource_ripple: FAIL (preflight_failed)", file=sys.stderr)
        if probe.stderr:
            print(probe.stderr.rstrip(), file=sys.stderr)
        return False
    try:
        actual_count, reviewed_count = (int(value) for value in probe.stdout.split())
    except ValueError:
        print("sync_resource_ripple: FAIL (preflight_output_invalid)", file=sys.stderr)
        return False
    if actual_count == reviewed_count:
        return _run(repo_root, "sync_committed_agent_trees.py", "--preflight")
    print(
        "sync_resource_ripple: FAIL (reviewed_resource_count_mismatch)\n"
        f"  inventory entries: {actual_count}\n"
        f"  REVIEWED_RESOURCE_COUNT: {reviewed_count}\n"
        "  review and update the single cardinality tripwire in src/yoetz/version.py first",
        file=sys.stderr,
    )
    return False


def _installed_manifest_agrees_with_schema(repo_root: Path) -> bool:
    """Prove the installed manifest still satisfies the generated version-manifest schema.

    Both sub-checks below are byte comparisons against artifacts that a mis-ordered regeneration
    leaves internally self-consistent, so neither notices a stale cardinality constant or a stale
    runtime-support digest. Building the manifest exercises the support/resource-set binding and
    validating it against the on-disk schema exercises the generated cardinalities, which is the
    drift that previously escaped local verification and failed only in CI.
    """

    completed = subprocess.run(
        [sys.executable, "-c", _SEMANTIC_CHECK_SOURCE],
        cwd=repo_root,
        env=_child_environment(repo_root),
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode == 0:
        return True
    print("sync_resource_ripple: FAIL (installed_manifest_disagrees_with_schema)", file=sys.stderr)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr)
    return False


def _check(repo_root: Path) -> bool:
    return (
        _run(repo_root, "generate_project_policy_fixture.py", "--check")
        and _run(repo_root, "generate_check_conclusion_fixture.py", "--check")
        and _run(repo_root, "generate_check_totals_fixture.py", "--check")
        and _run(repo_root, "generate_check_observations_awaited_fixture.py", "--check")
        and _run(repo_root, "generate_check_inspection_fixture.py", "--check")
        and _run(repo_root, "generate_review_dialogue_fixture.py", "--check")
        and _run(repo_root, "generate_task_statement_fixture.py", "--check")
        and _run(repo_root, "generate_schemas.py", "--check")
        and _run(repo_root, "verify_resource_manifest.py", "--check")
        and _installed_manifest_agrees_with_schema(repo_root)
        and _run(repo_root, "sync_committed_agent_trees.py", "--check")
        and _run(repo_root, "sync_mcp_descriptor_digests.py", "--check")
    )


def _write_pass(repo_root: Path) -> bool:
    if not (repo_root / "schemas" / _VERSION_MANIFEST_SCHEMA).exists():
        if not _run(
            repo_root, "generate_schemas.py", "--write", "--only", _VERSION_MANIFEST_SCHEMA
        ):
            return False
    steps = (
        ("generate_project_policy_fixture.py", "--write"),
        ("generate_check_conclusion_fixture.py", "--write"),
        ("generate_check_totals_fixture.py", "--write"),
        ("generate_check_observations_awaited_fixture.py", "--write"),
        ("generate_check_inspection_fixture.py", "--write"),
        ("generate_review_dialogue_fixture.py", "--write"),
        ("generate_task_statement_fixture.py", "--write"),
        (
            "generate_schemas.py",
            "--write",
            "--include-builder-owned",
            "--only",
            "events/check-recorded-1.4.0.schema.json",
            "--only",
            "events/finding-recorded-1.4.0.schema.json",
            "--only",
            "findings/finding-1.4.0.schema.json",
            "--only",
            "findings/provider-judgment-1.2.0.schema.json",
            "--only",
            "operations/check-result-1.4.0.schema.json",
            "--only",
            "operations/read-guidance-request-1.1.0.schema.json",
            "--only",
            "operations/read-guidance-result-1.1.0.schema.json",
            "--only",
            "service/control-request-2.6.1.schema.json",
            "--only",
            "service/control-result-2.6.1.schema.json",
            "--only",
            "privacy/privacy-policy-1.0.0.schema.json",
            "--only",
            "privacy/privacy-policy-1.1.0.schema.json",
            "--only",
            "privacy/egress-receipt-1.1.0.schema.json",
            "--only",
            "operations/status-result-1.1.0.schema.json",
            "--only",
            "operations/status-result-1.2.0.schema.json",
            "--only",
            "integrations/host-connection-1.0.0.schema.json",
            "--only",
            "integrations/mcp-removal-1.0.0.schema.json",
            "--only",
            "integrations/setup-readiness-1.0.0.schema.json",
            "--only",
            "integrations/setup-status-2.0.0.schema.json",
            "--only",
            "service/isolation-report-1.0.0.schema.json",
        ),
        ("sync_repository_authority_schemas.py", "--write"),
        ("sync_semantic_capacity_schemas.py",),
        # Mirror the reviewed sources into the package tree and recompute the resource-set digest.
        ("verify_resource_manifest.py", "--sync"),
        # Rebind the runtime-support digests to that resource-set digest. This must precede the
        # version-manifest regeneration below: build_version_manifest() fails closed with
        # support_resource_set_mismatch while runtime-support still carries the previous digest.
        ("sync_service_status_schema.py",),
        # Mirror the refreshed runtime-support bytes. The resource-set digest is unchanged here
        # because runtime_support content is deliberately excluded from that digest.
        ("verify_resource_manifest.py", "--sync"),
        # Regenerate the version-manifest cardinalities from the now-consistent installed manifest.
        (
            "generate_schemas.py",
            "--write",
            "--only",
            _VERSION_MANIFEST_SCHEMA,
        ),
        # Mirror the regenerated schema bytes and schema inventory. The resource-set digest moves
        # when they change, which the next pass rebinds into runtime-support.
        ("verify_resource_manifest.py", "--sync"),
        ("sync_mcp_descriptor_digests.py", "--write"),
    )
    for script_name, *arguments in steps:
        if not _run(repo_root, script_name, *arguments):
            print(f"sync_resource_ripple: FAIL (step_failed) {script_name}", file=sys.stderr)
            return False
    return True


def _write_to_fixed_point(repo_root: Path) -> bool:
    previous = _owned_digest(repo_root)
    for pass_number in range(1, _MAX_PASSES + 1):
        if not _write_pass(repo_root):
            return False
        current = _owned_digest(repo_root)
        if current == previous:
            # Render only after package digests converge: the skill ownership marker binds
            # the complete installed resource set. Include its bytes in the same fixed point.
            if not _run(repo_root, "sync_committed_agent_trees.py", "--write"):
                return False
            current = _owned_digest(repo_root)
        if current == previous:
            if not _check(repo_root):
                print("sync_resource_ripple: FAIL (post_convergence_check)", file=sys.stderr)
                return False
            print(f"sync_resource_ripple: PASS (fixed point after {pass_number} pass(es))")
            return True
        previous = current
    print(
        f"sync_resource_ripple: FAIL (did_not_converge after {_MAX_PASSES} passes)",
        file=sys.stderr,
    )
    return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sync_resource_ripple.py",
        description="Converge or verify generated schemas, packaged resources, and agent trees.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Read-only fixed-point verification.")
    mode.add_argument(
        "--write", action="store_true", help="Regenerate to a byte-stable fixed point."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Test-only: operate on another complete checkout.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    repo_root = args.repo_root.resolve() if args.repo_root is not None else _DEFAULT_REPO_ROOT
    if not repo_root.is_dir():
        print(f"sync_resource_ripple: FAIL (repo_root_missing) {repo_root}", file=sys.stderr)
        return 2
    if not _preflight(repo_root):
        return 1
    if args.check:
        if not _check(repo_root):
            print("sync_resource_ripple: FAIL (drift_detected)", file=sys.stderr)
            return 1
        print("sync_resource_ripple: PASS (generated artifacts are at a fixed point)")
        return 0
    return 0 if _write_to_fixed_point(repo_root) else 1


if __name__ == "__main__":
    sys.exit(main())
