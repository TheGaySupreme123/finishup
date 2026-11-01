# Key recovery runbook

This runbook explains how to respond safely to a locked key, a missing key, a key-backend failure,
or a wrong/tampered recovery secret or artifact, and how machine-bound versus portable recovery
works. It never suggests exporting a plaintext key, resetting a key over encrypted data, placing a
secret in a shell or environment variable, or claims that encrypted data is recoverable without the
correct bundle master key (BMK) or recovery artifact.

## 1. Threat and recovery scope

Terms used below: the **bundle master key (BMK)** protects one task bundle's objects; a **nonsecret
key slot/fingerprint** identifies which key entry a bundle expects; the **OS backend** is your
platform's verified keyring; **passphrase mode** wraps the installation vault key with an
Argon2id-derived key instead of the OS keyring; a **recovery secret** and its **portable recovery
artifact** together let you unwrap a BMK on a different machine.

An **installation recovery set** is different: it seals the installation vault authority and, in
self-contained mode, a consistent encrypted snapshot of the catalog, vault, bundles, and objects.
It is provisioned only while the vault is ready and restored only through `finishup service recovery`.
See ADR-024. A bundle portable-recovery artifact cannot be used as an installation set.

A raw BMK or any derived key is **never** shown, exported, or logged. Attacks against a compromised
live account, root, or process memory are outside what at-rest encryption protects against. Logical
redaction is not forensic erasure — see [`backup-restore.md`](backup-restore.md).

## 2. Identify key mode and failure reason

Run the operation that failed with `--json` and read its bounded reason code before acting:

| Reason | Meaning | Safe action |
|---|---|---|
| `key_locked` | Expected backend/entry exists but is denied or locked | Unlock/authorize the verified backend, then retry the *same* operation. Never create a replacement key. |
| `key_missing` | Expected key-slot entry is absent | Check you are on the correct OS profile/account/backend and backup mode. Do not initialize or reset. |
| `unsupported_backend` / `backend_unverified` | Backend is not on the supported list | Install/configure a supported backend through the public package policy. There is no plaintext fallback. |
| `key_id_mismatch` / `recovered_key_cannot_decrypt` | Wrong bundle/key, or corruption | Quarantine and stop; see [`quarantine-recovery.md`](quarantine-recovery.md). |
| `recovery_secret_wrong` | Secret entered incorrectly | Re-enter it safely; this is distinct from artifact tamper. |
| `recovery_artifact_tampered` / `format_unsupported` | Artifact itself is bad | Stop and use another verified artifact/package; never hand-edit its KDF, nonce, or header. |
| `recovery_material_required` | Ordinary installation unlock paths are gone and a recovery generation was provisioned | Run `finishup service recovery` in the protected local-human flow. |
| `permanently_unrecoverable` | No ordinary key or valid provisioned installation recovery generation exists | Preserve the old encrypted state; do not initialize over it. |

## 3. `key_locked`

The key exists but access is currently denied (for example, the OS keyring session is locked).
Unlock or authorize the verified backend through its normal platform mechanism, then retry the exact
same FinishUP operation. Never create a replacement key entry to work around a locked backend.

## 4. `key_missing` / backend unavailable

Confirm you are running as the same OS user/profile and backend that originally held the key, and
confirm which recovery mode the backup manifest declares. A `machine_bound` backup cannot be
restored anywhere the original key entry is absent — copying keychain or Secret Service internals,
or copying the whole backup directory, does not make it portable. Do not initialize a new vault or
reset a key "to fix it" — that does not recover the existing encrypted data.

## 5. Machine-bound backup restore

Restore must occur on the same installation/profile with the original verified key-backend entry
present, and the manifest's nonsecret key slot/fingerprint must match. Preview the restore; if the
entry is unavailable, there is no local workaround. Follow the verified new-target restore procedure
in [`backup-restore.md`](backup-restore.md) and compare object authentication and full replay before
the route switch.

## 6. Portable recovery artifact restore

Requires a finalized backup manifest with `mode=portable_recovery`, the matching separate recovery
artifact (digest/format/task/key identity must all match), and the recovery secret. Inspect and
confirm the restore plan first. Supply the secret only through the interactive protected prompt —
never through argv, an environment variable, JSON, a config file, shell history, chat, or an issue
tracker.

The adapter authenticates the artifact's metadata, derives the wrapping key using the recorded
Argon2id policy, unwraps the BMK into the verified destination backend, proves sample-then-full
object decryption and authentication plus a complete replay, and only then switches the route. A
wrong secret creates no persistent replacement key or target activation — it is safe to retry. A
tampered artifact is a distinct failure and is not retried indefinitely as "wrong secret." The
secret and any transient handles are released promptly; CPython cannot guarantee perfect memory
zeroization, so this runbook says "minimize lifetime," never "guaranteed erase."

## 7. Clean-profile recovery drill

Before calling any backup "portable" in your own documentation:

1. Use a synthetic or controlled bundle and its finalized backup/artifact.
2. Provision a clean, supported profile with **no** original key entry present.
3. Install the exact supported package artifact offline and verify its versions.
4. Restore using the recovery artifact and secret into a new target.
5. Verify the key slot, object authentication, canonical chains, and full replay/frontier/receipt.
6. Close and reopen the restored bundle, and repeat the read/check cycle.
7. Retain only redacted structural drill evidence and digests; destroy the test state afterward.

Never upload production user data to "prove" a drill. Repeat the drill after any recovery-format,
KDF, backend, or platform change.

## 8. Key and recovery custody

Separate the custody of backup ciphertext, the recovery artifact, and the recovery secret according
to your own threat model — FinishUP does not prescribe one storage policy. A checksum detects
accidental change; it is not a signature and not a secret. Never store a secret beside its artifact
in a FinishUP configuration file or a repository.

## 9. Installation-vault access recovery

Provision compact and/or self-contained recovery while the service is ready:

1. Run `finishup service recovery provision` locally and choose set mode and secret form.
2. Review the digest-bound plan, member counts/bytes, compatibility cells, and destination class.
3. Enter/confirm an Argon2id passphrase or record the generated recovery code from the protected
   prompt. The create-only `.yirs` destination is selected locally before mutation; its path never
   reaches the service. Keep the secret separate from the set.
4. Let FinishUP finish its reopen/replay/check/receipt drill. An incomplete set is not recovery
   material. If the final file write fails after the generation commits, rerun
   `finishup service recovery export` and choose a new destination; do not reprovision.
5. Re-run the clean-profile drill after rotation or a recovery-format/platform change.

After unlock loss, run `finishup service recovery status`. If the set is external, stop the daemon and
run `finishup service recovery import`. An imported archive is only *staged*: its header is not
authenticated, so it never becomes the active generation on import and whatever generation was
already in force stays usable if the import turns out to be the wrong one.

Then run the exact reported `finishup service recovery restore` command. Select the set only in an
allowlisted native picker when that platform cell exists, otherwise in the trusted terminal.

Restoring into a clean profile takes two invocations, because its phases need opposite things:

1. With the daemon still stopped, `finishup service recovery restore` installs the encrypted snapshot
   into the empty profile. This step holds the service's singleton exclusion, so no daemon may be
   running, and FinishUP never starts one for you. It reports `snapshot_installed` and stops there.
2. Start the service (`finishup service run`), then run `finishup service recovery restore` again. This
   invocation finds the installed marker, skips straight to the ceremony, and is where you enter
   the recovery secret and a distinct new vault passphrase.

The imported set is published as the active generation only after that ceremony authenticates it,
at the same commit point as the installation marker. Wait for the verified atomic switch. A wrong
secret changes nothing and is safe to retry, though repeated failures accumulate the same unlock
delay an ordinary passphrase attempt does. Agents show the exact command and suspend the original
operation, but never receive the set path or either secret.
Rotation and revocation also require a new vault passphrase because both re-encrypt the vault under
a new root. They are forward-only: a revoked set cannot open
post-rotation state, while an old copied snapshot paired with its old valid material remains
recoverable.

## 10. Permanent loss and honest next steps

If the BMK and every valid portable-recovery path are unavailable, the encrypted object content is
**not recoverable by FinishUP**. Preserve the catalog, bundle, backup, and structural evidence — do not
promise recovery, do not attempt brute force, and do not reset a key over the existing bundle. A new
task/key may be created only as a clearly separate history after you accept the loss and its
limitations; it can never validate or replace the old receipts.

## 11. Prohibited actions and safe support evidence

Never demonstrate a literal recovery secret in a command example, a support ticket, or a log. Share
only: the error reason code, package/object/recovery format identities, a nonsecret fingerprint hash
if your policy allows it, the backend classification, artifact/manifest digests, platform identity,
and which drill step you reached. Never share a key, secret, wrapped BMK bytes, artifact bytes, a
keychain label/account name, a path, database/object bytes, configuration/environment content, or a
raw exception/log line.

See also: [`backup-restore.md`](backup-restore.md) and
[`quarantine-recovery.md`](quarantine-recovery.md).
