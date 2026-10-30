-- Declared quiet period (#1239, owner decision D6 in #1247). When the agent declared it expects
-- no contact until, already clamped by the service's lineage.max_declared_quiet_seconds. A
-- service time, never caller text; open work out of contact keeps its window from this time.
ALTER TABLE lineage_task_meta ADD COLUMN quiet_until TEXT;
-- Implied quiet period (#1239, D6). When a tool call the host announced on the task's own active
-- session, with the call's own timeout, can end: the hook's receipt time plus that timeout,
-- clamped by the same setting. A service time kept apart from quiet_until, so a declaration or
-- its replay never shortens it; the window runs from the later of the two.
ALTER TABLE lineage_task_meta ADD COLUMN implied_quiet_until TEXT;

PRAGMA user_version = 7;
