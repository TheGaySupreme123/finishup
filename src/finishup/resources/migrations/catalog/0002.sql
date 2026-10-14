CREATE TABLE publish_responses (
    writer_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    sink TEXT NOT NULL CHECK (sink IN ('agent_context', 'local_human_view')),
    task_id TEXT NOT NULL REFERENCES task_routes(task_id),
    session_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    result_canonical BLOB NOT NULL,
    result_digest TEXT NOT NULL,
    PRIMARY KEY (writer_id, request_id, sink)
) STRICT, WITHOUT ROWID;

PRAGMA user_version = 2;
