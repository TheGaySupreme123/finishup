"""Client-side FinishUP code: what runs between an agent or person and a FinishUP server.

Hooks, the MCP bridge, the CLI, and the terminal interface are client surfaces that already live
in their own packages; new client-only code (server targets, their runtimes, credentials) lives
here. This package may import SHARED and CLIENT modules only (ADR-051; the cut line is enforced
by ``tests/unit/architecture``). Importing it is inert.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
