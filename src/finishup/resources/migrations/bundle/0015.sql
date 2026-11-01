PRAGMA application_id = 0x594F4554;

-- Migration 0015 records bounded structural progress for durable AI-powered review jobs
-- (issue #571 item A2). One row per job holds the furthest non-terminal phase observed, the
-- physical attempt ordinal that reached it, when the job was queued, and the job's frozen total
-- execution deadline. The terminal phase is not stored: it is derived from the terminal
-- semantic_jobs row, so a job has exactly one terminal state. Only closed structural values are
-- written: no prompt, response, token text, reasoning, credential, account identity, or path.
-- Existing jobs have no row and report no progress; nothing is backfilled.
CREATE TABLE semantic_progress (
    job_id TEXT PRIMARY KEY REFERENCES semantic_jobs(job_id),
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal BETWEEN 0 AND 9007199254740991),
    phase TEXT NOT NULL CHECK (
        phase IN (
            'queued',
            'case_admitted',
            'runtime_starting',
            'account_model_validation',
            'provider_sampling',
            'response_validation',
            'cleanup'
        )
    ),
    phase_rank INTEGER NOT NULL CHECK (
        phase_rank = CASE phase
            WHEN 'queued' THEN 1
            WHEN 'case_admitted' THEN 2
            WHEN 'runtime_starting' THEN 3
            WHEN 'account_model_validation' THEN 4
            WHEN 'provider_sampling' THEN 5
            WHEN 'response_validation' THEN 6
            WHEN 'cleanup' THEN 7
        END
    ),
    phase_entered_at TEXT NOT NULL CHECK (length(phase_entered_at) = 24),
    queued_at TEXT NOT NULL CHECK (length(queued_at) = 24),
    deadline_at TEXT NOT NULL CHECK (length(deadline_at) = 24),
    CHECK (attempt_ordinal > 0 OR phase = 'queued')
) STRICT, WITHOUT ROWID;

PRAGMA user_version = 15;
