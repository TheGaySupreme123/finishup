# Migration and rollback runbook

This runbook documents a safe schema-migration and recovery procedure. **"Rollback" means routing
back to a fully verified, restored pre-migration backup in a new target where compatibility is
proven** — it is never reverse SQL, a binary downgrade, or copying an old database over the active
bundle.

For a supported package update from 0.2 to 0.3, the fresh service owns the compatible bundle
schema transition during controlled startup: it takes the verified backup first, applies the
registered forward migration, verifies the preserved frontier and replay, and only then becomes
READY. That normal path needs no per-task approval ceremony. Use this runbook for an explicit
backup, restore, or ad-hoc migration, or when startup reports an unsupported, interrupted, or
ambiguous upgrade that requires operator-controlled recovery.

## 1. Scope and compatibility decision

Before migrating, confirm the exact current/candidate package, platform, SQLite, resource, and
migration identities against the public compatibility matrix (see
[`compatibility.md`](../protocol/compatibility.md)). Confirm adequate local disk space, a currently
supported key/object state, no active quarantine, no other owner/maintenance process, and the known
task/session/current frontier. Read the release notes and known limitations, and confirm the
migration path is contiguous and immutable. Stop if the target schema is newer than the candidate
package understands, a migration in the path is missing, this would be a downgrade, the filesystem
is unsafe, or a verified backup cannot be created first.

Migration may change the physical schema and projection generation, but it can never rewrite
canonical event bytes, digests, or meaning. An old binary may become unable to write or read after a
newer schema/event lands — downgrading the package is never presumed to be a rollback.

## 2. Preconditions

- Stable migration `request_id`, session, target version, and expected frontier.
- No competing maintenance or a second service instance.
- A destination with capacity for both the migration and its mandatory backup.

## 3. Preview a migration

```text
finishup migrate preview --input <request.json> --json
```

Review the from/to versions, the ordered migration IDs that will run, the current
frontier/head, the backup mode/destination policy, capacity, warnings, and the plan digest. Stop or
re-preview on any mismatch.

## 4. Backup-first execution

```text
finishup migrate execute --input <plan.json> --json
```

Explicitly confirm the exact plan digest; non-interactive use requires the plan digest plus explicit
acceptance. The runtime first acquires an exclusive maintenance generation and creates/verifies a
full backup through the complete frontier-pin/online-Backup/object-manifest procedure described in
[`backup-restore.md`](backup-restore.md) — **no schema step begins before that backup is verified.**
The runner then applies each forward migration transactionally where supported, advances
`user_version` and metadata together, preserves canonical bytes exactly, creates and replays a new
projection generation, and reopens through the normal safety gate. The same request ID resolves a
timeout or response loss — never launch a second migration or hand-edit metadata.

## 5. Verify success

Compare the result: from/to version, backup manifest digest, frontier before and after (no
migration event means the same canonical frontier), canonical count/byte/head samples or a full
chain check per policy, the object inventory, the new schema identity, the projection replay digest,
and a `status`/`check`/`receipt` cycle against known task state. Close and reopen the bundle and
verify again. Retain the pre-migration backup and this evidence through your release retention
window.

Do not describe data as "verified" beyond the exact integrity/replay/coverage checks performed.
Migration does not refresh repository evidence or re-run AI-powered review results.

## 6. Interrupted or failed migration classification

| Situation | Classification | Action |
|---|---|---|
| Failure before the backup terminal result | No schema mutation occurred | Retry the same request once the cause is resolved. |
| Backup terminal, failure before schema step | Safe to stop | The backup remains valid; resolve the cause, then retry. |
| Transactional migration step fails and rolls back, and the safety gate proves the old schema/state | Old bundle unaffected | Keep the old bundle active; preserve the backup and error; resolve the cause before retrying. |
| Ambiguous DDL/metadata mismatch, replay, integrity, or generation failure | Non-repairable in place | Writes quarantine; result is `rollback_required`. Do not rerun, downgrade, or hand-edit. |
| Response lost after apparent success | Outcome unknown | Look up the same request/status/version to determine the real outcome. |

## 7. Rollback by verified restore

1. Preserve the failed/current target and the pre-migration backup; stop all writers.
2. Install a package version that supports reading the backup format and reaching the desired
   target schema, per the compatibility matrix — often the migration candidate itself can restore
   the old snapshot. Do not simply reinstall the old package over the current data directory.
3. Run a restore preview against the pre-migration backup; verify its manifest, task, frontier, key,
   object, and database identities, the generated new route, and whether any migration would run
   during restore. For a true pre-migration rollback, do not accept a plan that silently
   re-migrates it forward.
4. Confirm the exact plan. Restore into a new quarantined target, replay fully, reopen, then perform
   the catalog compare-and-swap route switch. The current failed route is retained, not deleted.
5. Verify the restored frontier/head/replay/receipt, and explicitly identify any acknowledged work
   that happened after the backup's frontier and is therefore absent from the rollback target.
   Decide manually whether and how to republish that work — never merge databases.

## 8. Package downgrade warning

Reinstalling an older package binary is **not** rollback by itself. An older package may be unable
to open a bundle a newer package already migrated, and it never reverses a schema change. Downgrade
compatibility is exact-cell evidence from the release support matrix, not an assumption.

## 9. Prohibited actions

- No reverse or "down" migration SQL.
- No hand-editing `user_version` or migration metadata.
- No copying or replacing a live database/`-wal`/`-shm` file.
- No deleting projection or event rows to satisfy an older schema.
- No force-opening an unknown schema version.
- No running two writers against the same bundle.
- No removing the backup or the failed target before verification completes.
- No claiming that uninstalling a binary restored any data.

## 10. Evidence and exit criteria

Migration succeeds only when the post-migration verification in section 5 passes completely and the
old backup/evidence is retained through the retention window. Rollback succeeds only when the
restored route passes the same verification and the disclosed post-backup work gap has been reviewed
by a human. Neither outcome is claimed from a partial check.

See also: [`backup-restore.md`](backup-restore.md), [`quarantine-recovery.md`](quarantine-recovery.md),
and [`../protocol/compatibility.md`](../protocol/compatibility.md).
