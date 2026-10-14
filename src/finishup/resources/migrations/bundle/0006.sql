PRAGMA application_id = 0x594F4554;

-- Migration 0006 persists the exact reason a pending check released its operation
-- lease. Status recovery reads this operation-bound discriminator rather than
-- reconstructing a continuation from mutable repository authority after restart.

ALTER TABLE operations ADD COLUMN suspension_kind TEXT
    CHECK (suspension_kind IS NULL OR suspension_kind = 'repository_grant');

PRAGMA user_version = 6;
