PRAGMA application_id = 0x594F4554;

-- Migration 0017 records the durable steps of a reviewer-loop job (issue #1118): each model
-- turn (at most 5), the one format repair, and each read (at most 3). A step is reserved before it
-- runs and its result captured after; neither is refunded. Rows hold keyed commitments and byte
-- counts only: never a path, argument, prompt, model text or read result. Existing jobs have no
-- rows; nothing is backfilled.
CREATE TABLE semantic_review_steps (
    job_id TEXT NOT NULL REFERENCES semantic_jobs(job_id),
    kind TEXT NOT NULL CHECK (kind IN ('turn', 'repair', 'read')),
    ordinal INTEGER NOT NULL CHECK (
        ordinal >= 1 AND ordinal <= CASE kind WHEN 'turn' THEN 5 WHEN 'repair' THEN 1 ELSE 3 END
    ),
    selector_commitment TEXT NOT NULL CHECK (length(selector_commitment) BETWEEN 1 AND 128),
    capture_commitment TEXT CHECK (
        capture_commitment IS NULL OR length(capture_commitment) BETWEEN 1 AND 128
    ),
    capture_bytes INTEGER CHECK (capture_bytes BETWEEN 0 AND 1048576),
    PRIMARY KEY (job_id, kind, ordinal),
    CHECK ((capture_commitment IS NULL) = (capture_bytes IS NULL))
) STRICT, WITHOUT ROWID;

PRAGMA user_version = 17;
