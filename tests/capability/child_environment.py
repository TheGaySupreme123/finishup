"""One private instance boundary for all capability MCP subprocess transports."""

from __future__ import annotations

import os
from pathlib import Path

from finishup.config.paths import ensure_owner_only_dir


def child_environment(tmp_path: Path) -> dict[str, str]:
    """Replace ambient instance selection; a conflicting candidate pin still fails closed.

    The candidate interpreter is deliberately not replaced or unpinned. A pinned candidate
    must be provisioned for this root or refuse it before touching its original instance.
    """
    home = tmp_path.resolve() / "mcp-home"
    ensure_owner_only_dir(home)
    for directory in ("cache", "config", "data", "runtime", "state", "finishup/state"):
        ensure_owner_only_dir(home / directory)
    root = str(home / "finishup" / "state")
    return {
        # Neither product variable namespace is inherited (ADR-048).
        **{
            name: value
            for name, value in os.environ.items()
            if not name.startswith(("FINISHUP_", "YOETZ_"))
        },
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_DATA_HOME": str(home / "data"),
        "XDG_RUNTIME_DIR": str(home / "runtime"),
        "XDG_STATE_HOME": str(home / "state"),
        # Both spellings with one value, so a pre-rename candidate isolates too (ADR-048).
        "FINISHUP_ISOLATED_ROOT": root,
        "YOETZ_ISOLATED_ROOT": root,
    }
