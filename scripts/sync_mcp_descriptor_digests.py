"""Regenerate reviewed MCP descriptor identities after an intentional presentation change.

Load the local descriptor definitions without their final identity assertion, derive fresh hashes,
then run the unchanged honesty and boundary validator against those hashes before writing anything.
No installed state or service is accessed. The conformance golden set follows the same reviewed edit.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
import types
from pathlib import Path


def synchronize(root: Path, *, write: bool) -> bool:
    path = root / "src/finishup/mcp/descriptors.py"
    original = path.read_text(encoding="utf-8")
    tree = ast.parse(original, filename=str(path))
    tree.body = [
        node
        for node in tree.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "_lint_descriptor_sets"
        )
    ]
    name = "_finishup_descriptor_generation"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(tree, str(path), "exec"), module.__dict__)
        namespace = module.__dict__
        replacements: dict[str, str] = {}
        digests: dict[str, dict[str, str]] = {}
        sets: dict[str, str] = {}
        for profile, descriptors in namespace["TOOL_DESCRIPTORS"].items():
            digests[profile] = {}
            for descriptor in descriptors:
                digest = namespace["_digest_descriptor"](descriptor)
                digests[profile][descriptor.name] = digest
                replacements[namespace["TOOL_DESCRIPTOR_DIGESTS"][profile][descriptor.name]] = (
                    digest
                )
            data = b"\n".join(
                namespace["_canonical_descriptor_bytes"](item) for item in descriptors
            )
            sets[profile] = "sha256:" + hashlib.sha256(data).hexdigest()
            replacements[namespace["TOOL_DESCRIPTOR_SET_DIGEST"][profile]] = sets[profile]
        namespace["TOOL_DESCRIPTOR_DIGESTS"] = digests
        namespace["TOOL_DESCRIPTOR_SET_DIGEST"] = sets
        namespace["_lint_descriptor_sets"]()
    finally:
        del sys.modules[name]
    clean = True
    golden_test = root / "tests/conformance/surfaces/test_mcp_contract_matrix.py"
    targets = (path, golden_test) if golden_test.is_file() else (path,)
    for target in targets:
        before = target.read_text(encoding="utf-8")
        after = before
        for previous, current in replacements.items():
            after = after.replace(previous, current)
        if before != after:
            clean = False
            if write:
                target.write_text(after, encoding="utf-8")
    return clean or write


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    clean = synchronize(Path(__file__).resolve().parent.parent, write=args.write)
    print("sync_mcp_descriptor_digests: " + ("PASS" if clean else "FAIL (identity drift)"))
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
