"""Compatibility exports for the neutral workspace-locator boundary.

The resolver is shared by hook ingress, the CLI, and MCP. Its implementation lives in
``finishup.adapters.workspace_binding`` so the ordinary MCP import graph does not reach the CLI package.
This module remains as a compatibility import for existing callers.
"""

from finishup.adapters.workspace_binding import (
    MAX_WORKSPACE_LOCATOR_BYTES,
    canonical_workspace_locator,
    resolve_workspace_locator,
)

__all__ = [
    "MAX_WORKSPACE_LOCATOR_BYTES",
    "canonical_workspace_locator",
    "resolve_workspace_locator",
]
