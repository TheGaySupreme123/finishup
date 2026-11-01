PRAGMA application_id = 0x594F4554;

-- Migration 0008 adds the plaintext digest bindings needed to materialize encrypted
-- observation content and inspection snapshots as immutable ledger evidence. Existing
-- rows remain readable with NULL bindings and therefore retain their weaker coverage.

ALTER TABLE observation_content_manifests ADD COLUMN content_digest TEXT
    CHECK (
        content_digest IS NULL
        OR (
            length(content_digest) = 71
            AND substr(content_digest, 1, 7) = 'sha256:'
            AND substr(content_digest, 8) NOT GLOB '*[^0-9a-f]*'
        )
    );

ALTER TABLE observation_content_manifests ADD COLUMN content_bytes INTEGER
    CHECK (content_bytes IS NULL OR (content_bytes > 0 AND content_bytes <= 524288));

ALTER TABLE observation_inspection_snapshots ADD COLUMN facts_content_digest TEXT
    CHECK (
        facts_content_digest IS NULL
        OR (
            length(facts_content_digest) = 71
            AND substr(facts_content_digest, 1, 7) = 'sha256:'
            AND substr(facts_content_digest, 8) NOT GLOB '*[^0-9a-f]*'
        )
    );

ALTER TABLE observation_inspection_snapshots ADD COLUMN facts_content_bytes INTEGER
    CHECK (
        facts_content_bytes IS NULL
        OR (facts_content_bytes > 0 AND facts_content_bytes <= 4194304)
    );

ALTER TABLE observation_inspection_snapshots ADD COLUMN excerpt_content_digest TEXT
    CHECK (
        excerpt_content_digest IS NULL
        OR (
            length(excerpt_content_digest) = 71
            AND substr(excerpt_content_digest, 1, 7) = 'sha256:'
            AND substr(excerpt_content_digest, 8) NOT GLOB '*[^0-9a-f]*'
        )
    );

ALTER TABLE observation_inspection_snapshots ADD COLUMN excerpt_content_bytes INTEGER
    CHECK (
        excerpt_content_bytes IS NULL
        OR (excerpt_content_bytes > 0 AND excerpt_content_bytes <= 4194304)
    );

ALTER TABLE observation_inspection_snapshots ADD COLUMN excerpt_redacted INTEGER NOT NULL DEFAULT 0
    CHECK (excerpt_redacted IN (0, 1));

ALTER TABLE observation_inspection_snapshots ADD COLUMN excerpt_truncated INTEGER NOT NULL DEFAULT 0
    CHECK (excerpt_truncated IN (0, 1));

PRAGMA user_version = 8;
