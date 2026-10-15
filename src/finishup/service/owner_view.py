"""The owner's one-use full receipt view (ADR-009 round 3).

Every ordinary client result is projected for ``agent_context``. The only way to the
``local_human_view`` of a receipt is a grant the human-control ceremony mints after the owner
reauthenticates (OS user presence or the vault passphrase) for one exact receipt request on one
admitted control connection. The grant lives in service memory under that connection's
service-minted admission identity, is consumed only by the matching receipt call on that
connection, is revoked when it closes, and expires after ``OWNER_RECEIPT_VIEW_GRANT_SECONDS``. No
terminal fact, client kind, UID or hello field can create one.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections.abc import Callable
from typing import Final

from finishup.protocol.canonical import canonical_digest
from finishup.service.confidential_protocol import (
    OWNER_RECEIPT_VIEW_GRANT_SECONDS,
    OwnerReceiptViewTarget,
    human_target_json,
)

__all__ = [
    "OwnerViewConnectionRefused",
    "OwnerViewGrants",
    "control_connection_digest",
    "owner_receipt_view_target",
    "owner_receipt_view_target_digest",
]

# Frozen legacy identifier (ADR-048): HMAC domain separator in the shared `yoetz.<name>/<n>` tag
# family; changing it changes every derived connection binding.
_CONNECTION_DOMAIN: Final = b"yoetz.owner-view.control-connection/1\x00"
_MAX_PENDING_GRANTS: Final = 8
_MAX_SEEN_CONNECTIONS: Final = 65_536


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


class OwnerViewConnectionRefused(Exception):
    """A control connection claimed a nonce that is live or was already used in this service."""


class OwnerViewGrants:
    """One-use, expiring owner receipt view grants bound to one admitted control connection.

    The service mints an opaque admission identity for every admitted control connection
    (``admit``); the client never supplies it. The client's hello nonce is only a lookup key: it
    must be unique among every connection this service has admitted (a duplicate or reused
    nonce is refused at admission), and at ceremony time it resolves to exactly the one live
    admission that owns it. The grant is stored under that admission, consumed only by a receipt
    call on that same admission, and revoked when the connection closes. A new socket always gets
    a fresh admission, so it can never adopt an earlier connection's grant.
    """

    def __init__(self, monotonic: Callable[[], float] = time.monotonic) -> None:
        self._monotonic = monotonic
        self._lock = threading.Lock()
        # connection digest -> live admission id
        self._live: dict[str, str] = {}
        # digests of closed connections, never admitted again (bounded, oldest evicted first);
        # a digest is in exactly one of ``_live`` and ``_seen``
        self._seen: dict[str, None] = {}
        # (admission id, target digest) -> expiry
        self._grants: dict[tuple[str, str], float] = {}

    def admit(self, connection_nonce: str) -> str:
        """Register one admitted connection; returns its service-minted admission identity."""

        digest = control_connection_digest(connection_nonce)
        with self._lock:
            if digest in self._seen or digest in self._live:
                raise OwnerViewConnectionRefused("connection_nonce_reused")
            admission = secrets.token_hex(32)
            self._live[digest] = admission
            return admission

    def release(self, admission: str) -> None:
        """The connection closed: forget it and revoke every grant it held."""

        with self._lock:
            for digest in [digest for digest, live in self._live.items() if live == admission]:
                del self._live[digest]
                # A closed connection's nonce stays refused. Only closed ones are remembered here
                # (a live one is in ``_live``), so evicting the oldest keeps the bound even while
                # an early connection stays open.
                self._seen[digest] = None
                while len(self._seen) > _MAX_SEEN_CONNECTIONS:
                    del self._seen[next(iter(self._seen))]
            for key in [key for key in self._grants if key[0] == admission]:
                del self._grants[key]

    def issue(self, target_digest: str, control_connection_digest: str) -> int:
        """Grant the view to the one live connection the ceremony target names.

        Raises ``LookupError`` when no live admitted connection owns that digest (it closed,
        or it never existed), so a ceremony can never mint a grant nobody may consume.
        """

        now = self._monotonic()
        with self._lock:
            self._expire(now)
            admission = self._live.get(control_connection_digest)
            if admission is None:
                raise LookupError("owner_view_connection_unavailable")
            if len(self._grants) >= _MAX_PENDING_GRANTS:
                oldest = min(self._grants, key=lambda key: self._grants[key])
                del self._grants[oldest]
            self._grants[(admission, target_digest)] = now + OWNER_RECEIPT_VIEW_GRANT_SECONDS
        return OWNER_RECEIPT_VIEW_GRANT_SECONDS

    def consume(self, admission: str, target_digest: str) -> bool:
        """True exactly once, on the granted connection, for a live grant of that target."""

        now = self._monotonic()
        with self._lock:
            self._expire(now)
            return self._grants.pop((admission, target_digest), None) is not None

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()
            for digest in self._live:
                self._seen[digest] = None
            self._live.clear()
            while len(self._seen) > _MAX_SEEN_CONNECTIONS:
                del self._seen[next(iter(self._seen))]

    def _expire(self, now: float) -> None:
        for key in [key for key, expiry in self._grants.items() if expiry <= now]:
            del self._grants[key]
