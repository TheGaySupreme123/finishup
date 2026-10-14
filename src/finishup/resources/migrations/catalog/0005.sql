-- Project lifecycle request journal.  This table contains only authenticated digests and
-- structural identifiers/references; project title and description plaintext stay in encrypted
-- task-bundle objects.  The response bytes are the structural control response used for exact
-- same-request replay.  Create/amend reservations also retain the resolved source task route
-- so a crash before text_ready cannot rewrite a finalized object after route rotation.
CREATE TABLE project_operations (
    installation_id TEXT NOT NULL
        CHECK (length(installation_id) = 40 AND substr(installation_id, 1, 4) = 'ins_'),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 40 AND substr(request_id, 1, 4) = 'req_'),
    request_digest TEXT NOT NULL
        CHECK (
            length(request_digest) = 76 AND
            substr(request_digest, 1, 12) = 'hmac-sha256:'
        ),
    operation TEXT NOT NULL CHECK (
        operation IN ('create', 'link', 'unlink', 'amend', 'dissolve',
                      'opt_out', 'opt_in', 'grant', 'revoke')
    ),
    phase TEXT NOT NULL CHECK (
        phase IN ('reserved', 'text_ready', 'effect_pending', 'completed')
    ),
    project_id TEXT CHECK (
        project_id IS NULL OR
        (length(project_id) = 40 AND substr(project_id, 1, 4) = 'prj_')
    ),
    owner_task_id TEXT CHECK (
        owner_task_id IS NULL OR
        (length(owner_task_id) = 40 AND substr(owner_task_id, 1, 4) = 'tsk_')
    ),
    owner_route_generation INTEGER CHECK (
        owner_route_generation IS NULL OR owner_route_generation > 0
    ),
    member_kind TEXT CHECK (
        member_kind IS NULL OR member_kind IN ('task', 'repository', 'workspace')
    ),
    member_commitment_or_id TEXT,
    effect_generation INTEGER CHECK (effect_generation IS NULL OR effect_generation > 0),
    audit_record_id TEXT CHECK (
        audit_record_id IS NULL OR
        length(audit_record_id) BETWEEN 1 AND 128 AND
        audit_record_id NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    reserved_project_id TEXT CHECK (
        reserved_project_id IS NULL OR
        (length(reserved_project_id) = 40 AND substr(reserved_project_id, 1, 4) = 'prj_')
    ),
    reserved_title_object_id TEXT CHECK (
        reserved_title_object_id IS NULL OR
        (length(reserved_title_object_id) = 40 AND substr(reserved_title_object_id, 1, 4) = 'obj_')
    ),
    reserved_description_object_id TEXT CHECK (
        reserved_description_object_id IS NULL OR
        (length(reserved_description_object_id) = 40 AND substr(reserved_description_object_id, 1, 4) = 'obj_')
    ),
    prior_title_ref_canonical BLOB CHECK (
        prior_title_ref_canonical IS NULL OR length(prior_title_ref_canonical) BETWEEN 1 AND 2048
    ),
    prior_description_ref_canonical BLOB CHECK (
        prior_description_ref_canonical IS NULL OR length(prior_description_ref_canonical) BETWEEN 1 AND 2048
    ),
    title_ref_canonical BLOB CHECK (
        title_ref_canonical IS NULL OR length(title_ref_canonical) BETWEEN 1 AND 2048
    ),
    description_ref_canonical BLOB CHECK (
        description_ref_canonical IS NULL OR length(description_ref_canonical) BETWEEN 1 AND 2048
    ),
    result_canonical BLOB CHECK (
        result_canonical IS NULL OR length(result_canonical) BETWEEN 2 AND 1048576
    ),
    result_digest TEXT CHECK (
        result_digest IS NULL OR
        (length(result_digest) = 71 AND substr(result_digest, 1, 7) = 'sha256:')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (installation_id, request_id),
    CHECK (phase = 'completed' OR result_canonical IS NULL),
    CHECK (phase = 'completed' OR result_digest IS NULL),
    CHECK ((result_canonical IS NULL) = (result_digest IS NULL)),
    CHECK (member_kind IS NULL OR member_commitment_or_id IS NOT NULL),
    CHECK (member_kind IS NOT NULL OR member_commitment_or_id IS NULL),
    CHECK ((owner_task_id IS NULL) = (owner_route_generation IS NULL)),
    CHECK (operation IN ('create', 'amend') OR (
        owner_task_id IS NULL AND owner_route_generation IS NULL
    )),
    CHECK (operation = 'create' OR reserved_project_id IS NULL),
    CHECK (operation IN ('create', 'amend') OR reserved_title_object_id IS NULL),
    CHECK (operation IN ('create', 'amend') OR reserved_description_object_id IS NULL),
    CHECK (operation = 'amend' OR (
        prior_title_ref_canonical IS NULL AND prior_description_ref_canonical IS NULL
    ))
) STRICT, WITHOUT ROWID;

CREATE INDEX project_operations_phase
ON project_operations(installation_id, phase, updated_at, request_id);

PRAGMA user_version = 5;
