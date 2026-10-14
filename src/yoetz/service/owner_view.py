"""The owner's one-use full receipt view (ADR-009 round 3).

Every ordinary client result is projected for ``agent_context``. The only way to the
``local_human_view`` of a receipt is a grant the human-control ceremony mints after the owner
reauthenticates (OS user presence or the vault passphrase) for one exact receipt request on one
control connection. The grant lives in service memory, is consumed by the first matching receipt
call, and expires after ``OWNER_RECEIPT_VIEW_GRANT_SECONDS``. No terminal fact, client kind, UID or
hello field can create one.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from typing import Final

from yoetz.protocol.canonical import canonical_digest
from yoetz.service.confidential_protocol import (
    OWNER_RECEIPT_VIEW_GRANT_SECONDS,
    OwnerReceiptViewTarget,
    human_target_json,
)

__all__ = [
    "OwnerViewGrants",
    "control_connection_digest",
    "owner_receipt_view_target",
    "owner_receipt_view_target_digest",
]

_CONNECTION_DOMAIN: Final = b"yoetz.owner-view.control-connection/1\x00"
_MAX_PENDING_GRANTS: Final = 8


def control_connection_digest(connection_nonce: str) -> str:
    """A digest of the control connection's nonce; the nonce itself never leaves the session."""

    if type(connection_nonce) is not str or len(connection_nonce) != 64:
        raise ValueError("connection_nonce_invalid")
    return "sha256:" + hashlib.sha256(_CONNECTION_DOMAIN + connection_nonce.encode()).hexdigest()


def owner_receipt_view_target(request: object, connection_nonce: str) -> OwnerReceiptViewTarget:
    """The exact ceremony target for one receipt request on one control connection.

    ``request`` is a ``ReceiptRequest``-shaped value; the client and the service derive the
    target from the same fields, so only the owner's own call on its own connection matches.
    """

    def text(name: str) -> str:
        value = getattr(request, name)
        value = getattr(value, "value", value)
        if type(value) is not str:
            raise ValueError("owner_receipt_view_target_invalid")
        return value

    return OwnerReceiptViewTarget(
        task_id=text("task_id"),
        session_id=text("session_id"),
        receipt_request_id=text("request_id"),
        format=text("format"),  # pyright: ignore[reportArgumentType]
        include=text("include"),  # pyright: ignore[reportArgumentType]
        redaction_profile=text("redaction_profile"),  # pyright: ignore[reportArgumentType]
        control_connection_digest=control_connection_digest(connection_nonce),
    )


def owner_receipt_view_target_digest(target: OwnerReceiptViewTarget) -> str:
    return canonical_digest(human_target_json(target))


class OwnerViewGrants:
    """One-use, expiring owner receipt view grants, held in service memory only."""

    def __init__(self, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._grants: dict[str, float] = {}

    def issue(self, target_digest: str) -> int:
        """Record one grant for ``target_digest``; returns its lifetime in seconds."""

        now = self._monotonic()
        with self._lock:
            self._expire(now)
            if len(self._grants) >= _MAX_PENDING_GRANTS and target_digest not in self._grants:
                oldest = min(self._grants, key=lambda digest: self._grants[digest])
                del self._grants[oldest]
            self._grants[target_digest] = now + OWNER_RECEIPT_VIEW_GRANT_SECONDS
        return OWNER_RECEIPT_VIEW_GRANT_SECONDS

    def consume(self, target_digest: str) -> bool:
        """True exactly once for a live grant; a missing, used or expired one is False."""

        now = self._monotonic()
        with self._lock:
            self._expire(now)
            return self._grants.pop(target_digest, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()

    def _expire(self, now: float) -> None:
        for digest in [digest for digest, expiry in self._grants.items() if expiry <= now]:
            del self._grants[digest]
