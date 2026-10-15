"""Deprecated release-runtime bootstrap import path (ADR-048).

A process started from an earlier installation re-executes into a retained runtime with a fixed
bootstrap that imports this module. When the package was replaced in between, the retained copy
holds FinishUP, so the lease adoption forwards to the FinishUP implementation.
"""

from __future__ import annotations

from finishup.adapters.release_runtime import adopt_release_lease

__all__ = ["adopt_release_lease"]
