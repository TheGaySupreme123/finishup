# Quarantine recovery runbook

This runbook gives operators a safe, preserve-first procedure when FinishUP classifies a catalog,
bundle, object, tail, or migration state as corrupt, unsafe, or quarantined. It exists to prevent
speculative repair, direct database edits, deletion of evidence, key resets, and confusing
projection repair with canonical-data recovery.

## 1. What quarantine means

Quarantine disables **writes** because the runtime cannot currently prove the invariants it needs
to accept one safely. It does **not** mean the data is empty or deleted, does not prove malicious
corruption, and does not make every backup you hold bad. Read-only structural/version inspection may
remain available; payload reads still require a valid key and a safe verified state.

## 2. Immediate stop/preserve steps

Do these in order, immediately:

1. **Stop retrying with new request IDs**, and stop all FinishUP CLI/MCP processes for this
   installation. Do not kill unrelated processes, and let a shielded commit the current process
   reports as in-flight finish on its own.
2. **Preserve the original bundle/catalog/quarantine records exactly where the runtime placed
   them.** Do not copy a live database/`-wal`/`-shm` file, rename anything, `chmod` it, hand-edit
   it, `VACUUM` it, checkpoint it with an external SQLite tool, delete a temp/object file, reset a
   key, or run a newer/older binary against it speculatively.
3. **Record safe structural facts** (see section 3) — never a path, payload, or secret.
4. **Verify there is no competing owner or maintenance process**, and that the filesystem remains
   local, owner-only, and on a supported filesystem.

## 3. Record safe structural facts

Write down: the installed artifact/version/resource/SQLite identity, the public error reason code
and correlation ID, the task/session IDs if already known, the last verified `Frontier`, and whether
the failure followed a crash, a full disk, a key problem, a migration, or a filesystem change. Do
**not** record paths, payloads, or secrets.

## 4. Classify the failure

Use the bounded reason and evidence — never a single exception string or a file timestamp — to
place the failure into one of these buckets:

- Projection-cache digest/generation/lag failure while the canonical ledger and object chains still
  verify.
- An incomplete operation/backup/restore/migration marker left after a process died.
- A live or stale owner generation, or an ordinary busy state.
- A locked/missing key, or a key-backend mismatch.
- A missing or tampered ciphertext object, or a key-slot/authentication failure.
- A canonical entry, index, global, or writer-chain database-integrity mismatch.
- A catalog route/operation contradiction.
- An unsupported or newer storage/resource/runtime identity.

Normal startup/recovery logic owns tail/marker classification internally; as an operator you use
only the public `status`/recovery/restore surfaces to observe it — never a raw SQLite shell.

## 5. Projection-only recovery

If canonical ledger and object chains verify but only the *projection* cache is inconsistent, normal
supported recovery discards and rebuilds a fresh projection generation directly from canonical
events, verifies the reference digest/frontier, and reopens. **Do not drop tables manually.**
Success requires canonical database/object/key verification plus a reference-equal replay; any
unknown or redacted event remains an explicit, disclosed gap rather than being silently dropped.

## 6. Interrupted-operation/startup recovery

For an interrupted operation, backup, restore, or migration marker, retry the same request ID when
you know it. The recorded phase is only a lower bound — the runtime always revalidates the
object/database/manifest/route before resuming. If the outcome is unknown after a commit or route
switch, resolve it through the durable operation or `status` result, not by guessing. Stale-generation
recovery uses compare-and-swap only after proving the prior owner is truly absent — a PID or
timestamp alone is never sufficient.

A busy or live-owner state means stopping the duplicate client, or waiting boundedly — never
deleting a lock, heartbeat, or catalog row yourself. Key-related states route to
[`key-recovery.md`](key-recovery.md) and are never "corrupt empty payload." An unsupported version
identity requires a known compatible package or migration path — never force the metadata.

## 7. Canonical/object/catalog corruption

A canonical event, database, object, or catalog contradiction is **not repairable in place** and
remains quarantined. Use a previously verified backup and
[`backup-restore.md`](backup-restore.md): verify the source, build a new quarantined target, replay
it fully, and perform the atomic catalog switch, retaining both the original and the prior route. If
no verified backup or key exists, state plainly that recovery is not proven — preserve the evidence
and seek expert support. Never fabricate a missing event or object, and never delete one just to make
a check pass.

## 8. Restore and verify

After restore, compare the expected frontier, receipt, and coverage against what actually restored,
and explicitly disclose any lost work that happened after the backup's frontier. Keep the quarantined
original until a retention/support decision is made — it is not cleared by ordinary garbage
collection.

## 9. Escalation evidence and privacy

Allowed in a support request: package/protocol/storage/resource/SQLite identities and digests, the
bounded reason and correlation ID, counts, frontiers/head hashes, the operation/migration phase
enum, the manifest digest, and a key classification without any locator or secret. **Prohibited:**
database/WAL/SHM/object/recovery-artifact bytes, manifest paths, raw logs, tracebacks,
configuration/environment content, repository/workspace references, prompts/payloads, or key
material. Any diagnostic bundle must use a documented profile and pass the secret canary scan.

## 10. Prohibited actions

- No speculative repair before classification.
- No hand-editing a database, manifest, or version field.
- No deleting a lock, heartbeat, or catalog row.
- No running a newer or older binary against quarantined data "to see if it helps."
- No forensic imaging guidance — this runbook is not a substitute for qualified storage-recovery
  support on media/disk failure.

## 11. Exit criteria

Writes resume only when the normal startup gate returns a currently supported identity, keys are
available, the database/tail/chains/objects all verify, projection replay matches, no unresolved
recovery marker remains, and the current owner generation has been acquired cleanly. Record the
restored/recovered frontier and any remaining gaps honestly. Never say "data repaired" when the
actual procedure restored an older backup.

See also: [`backup-restore.md`](backup-restore.md), [`key-recovery.md`](key-recovery.md), and
[`migration-rollback.md`](migration-rollback.md). Ordinary product support uses repository issues;
security and conduct reports use the separate private routes in [`../../SECURITY.md`](../../SECURITY.md)
and [`../../CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md).
