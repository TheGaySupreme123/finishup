"""The MCP serving route each FinishUP session last used, for route-less status reads (#985).

An MCP bridge names its serving route (``policy`` or ``strict``) on every ``status`` and
``check``. The Stop-hook closure gate, the CLI and benchmark exports carry no route, so before
this they read the policy route and could list ``semantic_review_not_requested`` as work the
agent's own strict view never showed. The service remembers, per session, the route the last
successful route-carrying call named, and a later route-less ``status`` for the same session
reads on that route.

The memory is one small owner-only JSON file in the service state directory holding only opaque
``ses_`` ids and the closed route token; it survives a service restart or upgrade. It is
bounded (least recently written first out), written atomically, never follows a symlink, and
loaded lazily on first use. When two bridges serve one session on different routes, the last
successful call wins. Every failure is silent: reads fall back to the policy route.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Final, Literal, cast

__all__ = ["SESSION_ROUTE_FILE_NAME", "SessionRouteMemory"]

SESSION_ROUTE_FILE_NAME: Final = "session-routes.json"
_MAX_SESSIONS: Final = 256
_MAX_FILE_BYTES: Final = 64 * 1024
_ROUTES: Final = frozenset({"policy", "strict"})

type _Route = Literal["policy", "strict"]


def _valid_session(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("ses_")
        and len(value) <= 64
        and value.isascii()
        and all(char.isalnum() or char in "_-" for char in value)
    )


class SessionRouteMemory:
    """Bounded per-session route memory; ``path=None`` keeps it in process memory only."""

    def __init__(self, path: Path | None) -> None:
        self._path = path
        self._routes: dict[str, _Route] | None = None

    def _loaded(self) -> dict[str, _Route]:
        if self._routes is None:
            self._routes = self._read()
        return self._routes

    def _read(self) -> dict[str, _Route]:
        path = self._path
        if path is None:
            return {}
        try:
            if path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
                return {}
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(raw, dict):
            return {}
        routes: dict[str, _Route] = {}
        for key, value in cast(dict[object, object], raw).items():
            if _valid_session(key) and value in _ROUTES:
                routes[cast(str, key)] = cast(_Route, value)
        while len(routes) > _MAX_SESSIONS:
            routes.pop(next(iter(routes)))
        return routes

    def get(self, session_id: str) -> _Route | None:
        with contextlib.suppress(Exception):
            return self._loaded().get(session_id)
        return None

    def remember(self, session_id: str, route: _Route) -> None:
        """Record a successful route-carrying call; most recent last. Never raises."""

        if not _valid_session(session_id) or route not in _ROUTES:
            return
        with contextlib.suppress(Exception):
            routes = self._loaded()
            if next(reversed(routes), None) == session_id and routes[session_id] == route:
                return
            routes.pop(session_id, None)
            routes[session_id] = route
            while len(routes) > _MAX_SESSIONS:
                routes.pop(next(iter(routes)))
            self._write(routes)

    def _write(self, routes: dict[str, _Route]) -> None:
        path = self._path
        if path is None:
            return
        directory = path.parent
        if directory.is_symlink() or not directory.is_dir():
            return
        temporary = directory / f".{path.name}.{os.getpid()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.write(descriptor, json.dumps(routes).encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(temporary, 0o600)
        # os.replace swaps the directory entry itself, so a symlink planted at the path is
        # replaced, never followed.
        os.replace(temporary, path)
