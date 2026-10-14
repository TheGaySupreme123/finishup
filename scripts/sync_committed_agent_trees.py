"""Render the repository's two committed agent trees from the packaged canonical sources.

This is a repository generator, not an installer. Its only destinations are below this
script's checkout. Host homes, integration targets, and live install paths are never resolved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree
from yoetz.adapters.integrations.codex_skill import (
    build_managed_marker,
    expected_skill_member_paths,
    load_packaged_skill_members,
    load_packaged_skill_source,
)
from yoetz.ports.integrations import IntegrationScope
from yoetz.protocol.canonical import JsonValue, canonical_digest

_ROOT = Path(__file__).resolve().parent.parent
_TREES = {
    ".agents/plugins/yoetz": ".yoetz-plugin-install.json",
    ".agents/skills/yoetz": ".yoetz-install.json",
}
_REMEDIATION = "uv run python scripts/sync_resource_ripple.py --write"


def _existing_tree(root: Path) -> dict[str, bytes]:
    # Inspect parents before descent so even a missing target below a linked parent fails.
    for path in (*reversed(root.relative_to(_ROOT).parents), root.relative_to(_ROOT)):
        candidate = _ROOT / path
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
            raise ValueError("unsafe_agent_tree")
    if not root.exists():
        return {}
    paths = sorted(root.rglob("*"))
    for path in paths:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("unsafe_agent_tree")
    return {
        path.relative_to(root).as_posix(): path.read_bytes() for path in paths if path.is_file()
    }


def _recorded_extras(existing: Mapping[str, bytes], marker_name: str, extras: set[str]) -> bool:
    """Remove obsolete generated members only when their old marker still binds the bytes."""

    if not extras:
        return True
    try:
        value: object = json.loads(existing.get(marker_name, b"{}"))
        if type(value) is not dict:
            return False
        marker = cast(dict[str, JsonValue], value)
        digest = marker.pop("marker_digest", None)
        if canonical_digest(cast(JsonValue, marker)) != digest:
            return False
        raw_entries = marker.get("managed_files")
        if type(raw_entries) is not list:
            return False
        values = cast(list[JsonValue], raw_entries)
        if any(type(entry) is not dict for entry in values):
            return False
        entries = cast(list[dict[str, JsonValue]], values)
        for name in extras:
            matches = [entry for entry in entries if entry.get("relative_path") == name]
            if len(matches) != 1:
                return False
            data = existing[name]
            if matches[0].get("size") != len(data) or matches[0].get("sha256") != (
                "sha256:" + hashlib.sha256(data).hexdigest()
            ):
                return False
    except ValueError, TypeError, UnicodeError:
        return False
    return True


def _expected_trees() -> dict[str, dict[str, bytes]]:
    skill = dict(load_packaged_skill_members())
    skill[".yoetz-install.json"] = build_managed_marker(
        load_packaged_skill_source(), IntegrationScope.TRUSTED_PROJECT
    )
    return {
        ".agents/plugins/yoetz": render_plugin_install_tree(),
        ".agents/skills/yoetz": skill,
    }


def _expected_tree_paths() -> dict[str, set[str]]:
    """Return the canonical member names without reading the packaged bytes.

    Resource-ripple preflight runs before the package mirror and its nested skill manifest have
    been regenerated.  It still has to reject foreign files before any source is written, so this
    path inventory deliberately comes from the integration renderer's source layout rather than
    ``load_packaged_skill_members``.  Full byte validation remains in ``_expected_trees`` for
    ``--check`` and ``--write``.
    """

    skill_member_paths = expected_skill_member_paths()
    skill_paths = set(skill_member_paths) | {_TREES[".agents/skills/yoetz"]}
    plugin_paths = {
        ".codex-plugin/plugin.json",
        "hooks/hooks.json",
        ".mcp.json",
        _TREES[".agents/plugins/yoetz"],
    }
    plugin_paths.update(f"skills/yoetz/{path}" for path in skill_member_paths)
    return {
        ".agents/plugins/yoetz": plugin_paths,
        ".agents/skills/yoetz": skill_paths,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    try:
        existing = {name: _existing_tree(_ROOT / name) for name in _TREES}
        if args.preflight:
            # Preflight must run before the package mirror is regenerated. Check foreign names
            # from the canonical source layout first, while leaving byte/manifest validation to
            # the normal renderer below once the mirror is current.
            expected_names = _expected_tree_paths()
            for name, members in expected_names.items():
                extras = set(existing[name]) - members
                if not _recorded_extras(existing[name], _TREES[name], extras):
                    print(
                        f"sync_committed_agent_trees: FAIL (foreign_agent_files) {name}",
                        file=sys.stderr,
                    )
                    return 1
            return 0

        expected = _expected_trees()
        # Validate both trees before writing either one. Foreign files are never removed.
        for name, members in expected.items():
            extras = set(existing[name]) - set(members)
            if not _recorded_extras(existing[name], _TREES[name], extras):
                print(
                    f"sync_committed_agent_trees: FAIL (foreign_agent_files) {name}",
                    file=sys.stderr,
                )
                return 1
        drifted = [name for name in expected if existing[name] != expected[name]]
        if args.check and drifted:
            for name in drifted:
                print(
                    f"sync_committed_agent_trees: FAIL (agent_tree_drift) {name}\n"
                    "  canonical owners: guidance/, skills/codex/yoetz/, packaged resources, "
                    "Codex integration renderers\n"
                    f"  regenerate: {_REMEDIATION}",
                    file=sys.stderr,
                )
            return 1
        if args.write:
            for name in drifted:
                root = _ROOT / name
                for relative, data in expected[name].items():
                    if existing[name].get(relative) == data:
                        continue
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                for relative in set(existing[name]) - set(expected[name]):
                    (root / relative).unlink()
        print("sync_committed_agent_trees: PASS (both committed trees match their renderers)")
        return 0
    except (OSError, ValueError) as error:
        reason = (
            "unsafe_agent_tree" if str(error) == "unsafe_agent_tree" else "agent_generation_failed"
        )
        print(f"sync_committed_agent_trees: FAIL ({reason})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
