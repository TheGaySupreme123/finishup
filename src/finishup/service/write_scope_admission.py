"""Whether the running service reads the ``docs`` write scope (n7 RC2, issue #1106 round 2).

The hook, the session-stream reader in the hook process and the running service share one local
observation store. The service's own outbox sweeper and every store read decode each persisted
envelope, and a build that predates the ``docs`` class (an earlier 0.3.0 pre-release build still
running after an upgrade) refuses a row naming it for the whole workspace
(``invalid_event_value_type``): it could then read no consent, list no pending workspace and sweep
nothing. The hook connects without superseding an incompatible holder, so such a service keeps
running for the rest of the host session that was open during the upgrade.

A writer therefore records ``docs`` only while the singleton holder's stamp shows this
installation's schema manifest digest: the control-request 2.9.0 bytes that carry the enum are
pinned by that manifest, so an equal digest is a holder whose store reader admits the class.
Anything else (no live holder, an unreadable stamp, another digest, a stamp with no digest) is
the older class (``domain.write_scope.without_docs_scope``), which only keeps the edit counting.
The stamp is advisory identity, never a fence; the answer only chooses between two classes every
reader accepts or the one this build and its own service accept.
"""

from __future__ import annotations

__all__ = ["docs_write_scope_admitted"]


def docs_write_scope_admitted() -> bool:
    """True only when the live singleton holder is stamped with this installation's manifest."""

    try:
        from finishup.config.paths import state_dir
        from finishup.service.lifecycle import (
            SINGLETON_LOCK_NAME,
            probe_singleton_holder_identity,
        )

        holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
        if holder is None or holder.schema_manifest_digest is None:
            return False
        from finishup.protocol.schemas import schema_manifest_digest

        return holder.schema_manifest_digest == schema_manifest_digest()
    except Exception:
        return False
