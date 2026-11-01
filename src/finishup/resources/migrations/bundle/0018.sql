PRAGMA application_id = 0x594F4554;

-- #1173: keep every reviewer attempt durably spent, including two bounded corrections.
-- Preserve all existing reservations/captures byte-for-byte; only the ordinal bounds widen.
CREATE TABLE semantic_review_steps_v18 (
    job_id TEXT NOT NULL REFERENCES semantic_jobs(job_id),
    kind TEXT NOT NULL CHECK (kind IN ('turn', 'repair', 'read')),
    ordinal INTEGER NOT NULL CHECK (
        ordinal >= 1 AND ordinal <= CASE kind WHEN 'turn' THEN 7 WHEN 'repair' THEN 1 ELSE 5 END
    ),
    selector_commitment TEXT NOT NULL CHECK (length(selector_commitment) BETWEEN 1 AND 128),
    capture_commitment TEXT CHECK (
        capture_commitment IS NULL OR length(capture_commitment) BETWEEN 1 AND 128
    ),
    capture_bytes INTEGER CHECK (capture_bytes BETWEEN 0 AND 1048576),
    PRIMARY KEY (job_id, kind, ordinal),
    CHECK ((capture_commitment IS NULL) = (capture_bytes IS NULL))
) STRICT, WITHOUT ROWID;

INSERT INTO semantic_review_steps_v18 SELECT * FROM semantic_review_steps;
DROP TABLE semantic_review_steps;
ALTER TABLE semantic_review_steps_v18 RENAME TO semantic_review_steps;

PRAGMA user_version = 18;
