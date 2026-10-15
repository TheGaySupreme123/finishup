PRAGMA application_id = 0x594F4554;

-- Migration 0005 owns the durable suspension record for a semantic attempt that is
-- waiting on one local disclosure decision. Migrations 0001-0004 remain immutable;
-- existing ledger/object/observation rows stay readable.
--
-- Why a side table rather than a new `semantic_jobs.state`: the job row's state CHECK
-- lives on a STRICT table with circular foreign keys to `semantic_attempts`, and
-- migrations run inside one transaction with `PRAGMA foreign_keys = ON`, which cannot
-- be toggled there. An additive row keeps the rebuild out of the upgrade path.
--
-- The waiting job stays `leased` with its `started` attempt intact. That is the whole
-- point: approval must resume the *same* attempt, because the provider request id is
-- part of the prepared bytes the human approved. Minting a fresh attempt would change
-- the prepared case digest and silently orphan the decision.
--
-- `lease_expires_at` on the job may fall into the past while a human decides. The
-- ordinary reclaim path treats that as lease loss and expires the attempt; the claim
-- path consults this table first so a live wait suspends that clock. The bound on the
-- wait is `pending_expires_at` — the proposal's own expiry — not the lease TTL.

CREATE TABLE semantic_disclosure_waits (
    job_id TEXT PRIMARY KEY REFERENCES semantic_jobs(job_id),
    attempt_id TEXT NOT NULL,
    writer_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    -- Opaque privacy-proposal identifier. Structural only: no proposal content, no
    -- prepared bytes, no destination, and no credential material is recorded here.
    pending_id TEXT NOT NULL,
    pending_expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('awaiting', 'resolved')),
    resolved_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (job_id, attempt_id)
        REFERENCES semantic_attempts(job_id, attempt_id),
    FOREIGN KEY (writer_id, operation_id)
        REFERENCES operations(writer_id, operation_id),
    -- One wait per proposal: a resumed decision is consumed exactly once.
    UNIQUE (writer_id, operation_id, pending_id),
    CHECK (
        (state = 'awaiting' AND resolved_at IS NULL)
        OR (state = 'resolved' AND resolved_at IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE INDEX semantic_disclosure_waits_by_operation
    ON semantic_disclosure_waits (writer_id, operation_id, state);

CREATE INDEX semantic_disclosure_waits_by_pending
    ON semantic_disclosure_waits (pending_id, state);

PRAGMA user_version = 5;
