"""Generate or verify the reviewer's derived Codex model catalog (#1118, ADR-006).

``--write --codex PATH`` runs ``PATH debug models --bundled`` (a pinned Codex executable, under a
scratch home: no login, no network), checks that the bundled ``gpt-6.1-sol`` entry has the pinned
source digest, and writes the derived file into ``support/codex-evaluator/``. Run the resource
ripple afterwards so the package mirror follows.

``--check`` (the default) needs no Codex: it proves the committed file has the pinned derived
digest and that undoing exactly the derivation reproduces the pinned source-entry digest.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path

from finishup.adapters.providers.codex_capability import (
    codex_bundled_model_catalog,
    codex_cli_version,
)
from finishup.adapters.providers.codex_reviewer_catalog import (
    REVIEWER_CATALOG_DERIVED_SHA256,
    REVIEWER_CATALOG_RESOURCE,
    REVIEWER_CATALOG_RUNTIME_VERSIONS,
    REVIEWER_CATALOG_SOURCE_ENTRY_SHA256,
    bundled_entry_sha256,
    derive_reviewer_catalog,
    restore_source_entry,
)
from finishup.protocol.canonical import canonical_encode

_ROOT = Path(__file__).resolve().parent.parent


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _target(root: Path) -> Path:
    return root / REVIEWER_CATALOG_RESOURCE


def check(root: Path) -> list[str]:
    """Return every pin violation of the committed derived file (empty when it holds)."""

    path = _target(root)
    try:
        data = path.read_bytes()
    except OSError:
        return [f"missing: {REVIEWER_CATALOG_RESOURCE}"]
    problems: list[str] = []
    if _sha256(data) != REVIEWER_CATALOG_DERIVED_SHA256:
        problems.append(
            f"derived digest {_sha256(data)} != pinned {REVIEWER_CATALOG_DERIVED_SHA256}"
        )
    try:
        source = restore_source_entry(data)
    except ValueError as error:
        problems.append(f"derivation not reversible: {error}")
    else:
        restored = _sha256(canonical_encode(dict(source)))
        if restored != REVIEWER_CATALOG_SOURCE_ENTRY_SHA256:
            problems.append(
                f"restored source digest {restored} != pinned {REVIEWER_CATALOG_SOURCE_ENTRY_SHA256}"
            )
    return problems


def write(root: Path, codex: Path) -> None:
    """Derive the file from one pinned-release executable and write it into the source tree."""

    with tempfile.TemporaryDirectory(prefix="reviewer-catalog-") as scratch:
        version = codex_cli_version(codex, scratch_parent=Path(scratch))
        if version not in REVIEWER_CATALOG_RUNTIME_VERSIONS:
            pinned = ", ".join(sorted(REVIEWER_CATALOG_RUNTIME_VERSIONS))
            raise SystemExit(f"codex {version} is not a pinned release ({pinned})")
        catalog = codex_bundled_model_catalog(codex, scratch_parent=Path(scratch))
    print(f"source entry: {bundled_entry_sha256(catalog)}")
    data = derive_reviewer_catalog(catalog)
    _target(root).write_bytes(data)
    print(f"derived file: {_sha256(data)} ({len(data)} bytes) -> {REVIEWER_CATALOG_RESOURCE}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--codex", type=Path, help="a pinned Codex executable (for --write)")
    parser.add_argument("--root", type=Path, default=_ROOT)
    args = parser.parse_args(argv)
    if args.write:
        if args.codex is None:
            parser.error("--write needs --codex")
        write(args.root, args.codex)
    problems = check(args.root)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
