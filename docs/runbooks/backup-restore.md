# Backup and restore runbook

This runbook is the safe operator procedure for creating a frontier-pinned encrypted bundle backup
and restoring it into a new target that passes every structural, cryptographic, replay, and
route-switch check before FinishUP atomically switches the active route to it. Follow it exactly — do
not improvise a shortcut such as copying a live database, overwriting the active bundle, calling a
machine-bound backup portable, or treating a manifest checksum as a signature.

## 1. Scope, data sensitivity, and guarantees

A backup is an encrypted snapshot of **one task at one `Frontier`**, plus the exactly referenced
ciphertext objects and a structural manifest. SQLite's online Backup API gives database consistency;
an object pin protects the referenced object set until the backup finalizes. A backup does **not**
capture uncommitted work, prove correctness, sign data, or guarantee portability without the correct
recovery mode, key, and a clean-profile drill (see section 7).

Backups are sensitive even though payloads are encrypted: structural metadata (IDs, sizes, times,
versions) and ciphertext both remain readable as bytes. Store a backup owner-only, outside
repositories, cloud-synced folders, network shares, or shared temp directories. FinishUP rejects
obviously unsafe destinations at preview time.

## 2. Choose machine-bound or portable recovery

| Mode | What it stores | Restore requirement |
|---|---|---|
| `machine_bound` | A nonsecret key locator/fingerprint in the manifest | Only where the original verified key-backend entry is still available; copying the backup alone to another machine is not enough. |
| `portable_recovery` | A separate authenticated recovery artifact wrapping the bundle key with a user-held recovery secret | Keep the backup, artifact, and secret under a custody policy appropriate to your threat model; call it "portable" only after a clean-profile drill (section 7). |

Neither mode protects against a compromised active account, root, or live process memory, and
deletion is never forensic erasure — see [`key-recovery.md`](key-recovery.md).

These are one-task bundle backups. They do not recover the installation vault. For compact or
self-contained installation recovery, use the separate ADR-024 `finishup service recovery` lifecycle;
do not relabel a bundle `portable_recovery` artifact as an installation set.

## 3. Preconditions and capacity

- Verify a supported package/platform: `finishup version --json`.
- Identify the exact task and a stable new destination with capacity and owner-only permissions.
- Ensure no competing maintenance operation is running against the same installation.

## 4. Preview and create a backup

1. Prepare a strict request with a stable `request_id`, session, destination, mode, and an optional
   expected frontier. Never place a recovery secret in this request.
2. `finishup backup preview --input <request.json> --json`. For portable mode, enter the recovery
   secret only through the foreground no-echo confidential helper after reviewing the exact plan —
   v0.1 has no inherited-descriptor or password-file-descriptor channel.
3. Review the preview: actual task frontier/head, mode, whether the target is new, object
   count/bytes, versions, warnings, and the plan digest. If work or the frontier changes, preview
   again before confirming.
4. Confirm the exact plan digest explicitly: `finishup backup execute --input <plan.json> --json`.
   Never mint a new request ID after a timeout — the same ID resolves to the same operation.
5. Wait for the terminal result. Success records the manifest, object-set, database, and (for
   portable mode) recovery-artifact digests, plus the pinned frontier. Do not rename an
   `.incomplete-*` directory or treat it as a finished backup.
6. Run a verification/read-only preview against the finalized backup set and compare its digests
   against the recorded manifest. Store checksums as your evidence policy requires.

Internally, the current process pins the frontier, snapshots SQLite through the online Backup API,
copies the already-verified ciphertext objects, writes a recovery artifact if requested, and writes
the manifest **last**, atomically publishing into the destination. It never copies a live
`ledger.sqlite3`, its `-wal`, or its `-shm` file.

## 5. Restore preview

1. Preserve the current installation/bundle — do not move, delete, or edit it. Verify the package
   and platform, and confirm you own the source backup.
2. `finishup restore preview --input <request.json> --json`. Review the source manifest's
   task/frontier/database/object/key/version integrity, the current active route/frontier, any
   required supported migration, the generated new-target identity, the retained prior route,
   warnings, and the plan digest. A task mismatch, a newer unsupported version, tamper evidence, or
   a missing member stops here.

## 6. Restore into a new target

1. Confirm the exact plan: `finishup restore execute --input <plan.json> --json`. Restore creates a
   fresh, generated, quarantined target, uses the SQLite Backup API into a new database, copies and
   authenticates ciphertext objects, resolves the key, verifies chains and integrity, replays the
   full ledger, and reopens normally. It never merges histories and never overwrites active files.
2. The catalog switches the active route in one generation-fenced transaction only after every
   verification step passes. If the response is lost after the switch, the outcome is unknown —
   rerun the identical request or check `status`; never start a second restore.

## 7. Post-restore verification (the clean-profile drill)

Verify the active route structurally: `status` at the expected restored frontier/head, a fresh
`check`, and a receipt appropriate to the captured data. Keep the prior route and backup until a
reviewed retention decision and at least one successful reopen/use cycle. Only after this full drill
completes should a `portable_recovery` backup be described as "portable" in your own operational
documentation.

## 8. Failure and cancellation handling

| Reason | Action |
|---|---|
| Plan is stale | Preview again. |
| Bundle busy | Stop the other maintenance operation, or retry the same request later. |
| Target exists / unsafe | Choose a new safe destination. |
| Key locked/missing/wrong | Resolve the key backend or secret — never reset a key. |
| Manifest/object/database/replay mismatch | Stop; preserve everything for support. |
| Route changed since preview | Preview the current state again. |
| Migration needed | For a supported 0.2-to-0.3 update, let controlled service startup perform its backup-first migration; for explicit backup/restore work, use a supported candidate package or stop. |

Cancellation or a timeout never proves failure — inspect the structural result or `status` and retry
the exact same request. No log or support bundle should ever include a path, a manifest with a user
extension, database/object bytes, a secret or key, a payload, or a raw traceback.

## 9. What never to do

- Never `cp`, use Finder, or `rsync` a live database, `-wal`, or `-shm` file.
- Never overwrite the active bundle.
- Never delete or move the prior route during a restore.
- Never hand-edit a SQLite file, manifest, or version field.
- Never disable fsync, integrity checks, or key checks "to make it go faster."
- Never place a secret in a shell command, environment variable, or plain file.
- Never call a `machine_bound` backup "portable."
- Never treat installing an old package binary as a rollback.
- Never manually change a catalog path.

## 10. Evidence and support checklist

If you need help, share only: package/protocol/storage versions, the bounded error reason and
correlation ID, manifest/object/database digests, the exact frontier involved, and the drill step
reached. Never share a database file, an object file, a recovery secret or artifact, a path, or a
raw exception/log line.
