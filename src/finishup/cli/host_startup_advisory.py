"""A fresh grant snapshot on supported SessionStart context channels (issue #857).

No host hook identifies the serving MCP transport. Report only the repository grant and
project admission observation; neither a registration nor another bridge's startup proves
the route of this session. Nothing here offers a retry or changes admission.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final, cast

from finishup.cli.host_hold_advisory import (
    AsyncRunner,
    PrivacyConnector,
    read_admission_state,
    read_repository_grant,
)

_MAX_READ_SECONDS: Final = 0.5
_MIN_READ_SECONDS: Final = 0.05
_COMMANDS: Final = {
    "claude": "finishup integrate claude admission grant",
    "codex": "finishup integrate codex admission grant",
    "cursor": "finishup integrate cursor admission grant",
}
_NOTICE: Final = (
    "At session start, FinishUP read a repository grant permitting external AI review, "
    "but no host admission entry for check. Route and host approval remain unconfirmed. "
    "Owner: {command}. If held, preserve the exact request for approval; never silently downgrade."
)


def append_admission_notice(
    context: str,
    host: str,
    workspace_locator: str | None,
    *,
    connect: PrivacyConnector | None,
    run_async: AsyncRunner,
    deadline: float,
    max_chars: int,
    skip_service: bool = False,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """Append a closed notice within spare hook time/space; failure preserves prior context.

    One 500 ms budget includes the local admission read, connection, grant RPC and cleanup,
    capped again by the caller's remaining hook budget. Exhaustion is silent, not consent.
    The connector, when injected, must already be bound to the supplied workspace.
    """

    if skip_service or workspace_locator is None or host not in _COMMANDS:
        return context
    notice = _NOTICE.format(command=_COMMANDS[host])
    combined = " ".join(part for part in (context, notice) if part)
    if len(combined) > max_chars:
        return context
    expires = min(deadline, monotonic() + _MAX_READ_SECONDS)
    if expires - monotonic() < _MIN_READ_SECONDS:
        return context
    try:
        if read_admission_state(workspace_locator, host=host) != "absent":
            return context
        remaining = expires - monotonic()
        if remaining < _MIN_READ_SECONDS:
            return context
        if connect is None:
            from finishup.cli.hooks import bound_connector
            from finishup.service.client import connect_service

            connect = cast(PrivacyConnector, bound_connector(connect_service, workspace_locator))
        result = run_async(
            lambda: read_repository_grant(connect, deadline_ms=int(remaining * 1_000))
        )
        if result == "grant_confirmed" and monotonic() < expires:
            return combined
    except Exception:
        pass
    return context
