-- Task lifecycle reasons (#1239, owner decision D6 in #1247). Why open work will be, or terminal
-- work was, abandoned: a closed token, never caller text. Only a ``contact_lost`` abandonment is
-- reversible, by the same session's ``work_closed``; the reason survives that close as history.
ALTER TABLE lineage_task_meta
ADD COLUMN abandonment_reason TEXT CHECK (
    abandonment_reason IS NULL OR
    abandonment_reason IN ('contact_lost', 'session_ended', 'attach_handle_expired')
);

PRAGMA user_version = 6;
