"""Deprecated ``yoetz`` import name of FinishUP (ADR-048).

FinishUP shipped as Yoetz through 0.2.5. Installations from that era recorded three spellings
that must keep working for the deprecation window, and each module here forwards one of them to
``finishup`` without behavior of its own:

- ``python -m yoetz`` (host hooks and MCP entries, and the service spawn of an older running
  client) runs ``yoetz.__main__``;
- the console script of an earlier ``yoetz`` wheel imports ``yoetz.cli.entry:main``;
- the fixed release-runtime bootstrap of an older process imports
  ``yoetz.adapters.release_runtime.adopt_release_lease`` and ``yoetz.cli.entry.main``.
"""

from __future__ import annotations

from finishup import __version__

__all__ = ("__version__",)
