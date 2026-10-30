-- Declared quiet period (#1239, owner decision D6 in #1247). When the agent declared it expects
-- no contact until, already clamped by the service's lineage.max_declared_quiet_seconds. A
-- service time, never caller text; open work out of contact keeps its window from this time.
ALTER TABLE lineage_task_meta ADD COLUMN quiet_until TEXT;

PRAGMA user_version = 7;
