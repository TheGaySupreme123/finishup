"""Home-directory prefixes for synthetic test paths.

The public-boundary scanner (``scripts/scan_public_boundary.py``, rules PRIV-PATH-001 and
PRIV-PATH-002) refuses every absolute macOS or Linux home path in a tracked file, because a real
one publishes a maintainer's account name. Tests whose behaviour depends on a path lying under a
home tree (``~/.ssh``, ``HOME``, a host-managed worktree) build it from these prefixes, so the
committed bytes carry no account-shaped path while the value under test is the realistic one.
Tests that only need some private-looking path use a neutral root such as ``/srv`` instead.
"""

from __future__ import annotations

from typing import Final

LINUX_HOME: Final = "/" + "home"
MACOS_HOME: Final = "/" + "Users"
