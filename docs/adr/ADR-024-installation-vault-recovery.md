# ADR-024 — Installation-vault recovery, forward revocation, and agent handoff

**Status:** Maintainer-selected working decision (2026-08-23, issue #403). Binding for
implementation and public claims. No platform cell is advertised until its candidate artifact has
passed the release-bound recovery and native-prompt drills below.
**Related:** ADR-001 owns the single service/writer authority; ADR-003 owns durable staging and
atomic route changes; ADR-004 owns the IVK/BMK hierarchy and forbidden secret channels; ADR-007
owns platform/release claims; ADR-008 owns the local service, confidential ceremony, and user
presence boundary.

## Problem and honesty boundary

An existing installation vault may be inaccessible after both its passphrase and every usable
platform auto-unlock/keyring entry are lost. Initializing a new IVK over that state is destructive,
not recovery. Bundle-level `portable_recovery` unwraps one BMK and does not restore installation
authority, provider credentials, catalog lookup keys, privacy-audit keys, or other bundles.

FinishUP can recover an installation only when the ready vault previously provisioned valid
installation recovery material. Without that material and its matching human-held secret, the old
encrypted installation is permanently unrecoverable. Recovery never brute-forces, resets, merges,
or labels a new empty history as restored.

Revocation is forward-only. After a verified rotation, material for an older generation cannot
open the post-rotation vault or state newly protected by it. No implementation can make an already
copied old snapshot and its formerly valid secret undecryptable; documentation and status must not
claim otherwise.

## Selected recovery products

FinishUP supports both product shapes. One active recovery generation selects exactly one shape;
rotation may switch shapes, and previously exported shapes remain historical rather than being
advertised as current:

1. **Compact recovery set.** A small authenticated artifact seals the exact installation recovery
   root. It restores the current encrypted state already present on the original profile. A clean
   profile also needs a separately preserved, manifest-bound copy of the exact encrypted
   installation state.
2. **Self-contained recovery set.** The same sealed recovery root plus a consistent encrypted
   installation snapshot, one authenticated manifest, and all referenced ciphertext members. It
   restores the snapshot frontier into a clean supported profile without relying on an
   undocumented application/profile copy.

The recovery secret is always separate from either set. A set may use one of two secret forms:

- `generated_code`: a helper-generated, high-entropy, versioned recovery code displayed exactly
  once inside the protected local-human ceremony; or
- `argon2id_passphrase`: exact UTF-8 entered and confirmed locally by the human, with no Unicode
  normalization or case/whitespace rewriting.

Both feed the same versioned Argon2id recovery-KEK envelope with independent random salt and the
reviewed KDF policy. A generated code is not placed on the clipboard, written to a plaintext file,
returned to an agent, or echoed through ordinary stdout. A checksum or grouping used to reject a
typing error is not authentication and must not reduce the random secret entropy.

## Recovered installation boundary

The self-contained set includes installation-owned durable state needed to reopen the same
authority at its captured generation:

- the installation identity and immutable mode/recovery generation metadata;
- the encrypted vault sentinel, every BMK record, every provider-credential record, recovery
  metadata, installation-key epochs, and their authenticated vault index;
- the start catalog, task routes, maintenance records, privacy authority/audit state, operation
  recovery state, task bundle databases, ciphertext objects, projection generations, and
  frontier/receipt chains;
- the exact storage, object, schema, package, KDF, and recovery-format identities needed to decide
  whether the candidate package may restore it.

It excludes host and repository state: working trees, host logins/sessions, Codex/Cursor/plugin
installation, runtime sockets/pipes, process locks, caches, temporary files, logs, external
provider state, OS keyring entries, and user configuration outside the installation bundle. A
restored provider credential is reported only as presence for its exact stored binding; recovery
does not prove that the external provider still accepts it. Repository privacy grants and policy
identity are recovered as durable installation state, but recovery grants no new disclosure or
egress authority.

## Artifact and snapshot contract

Released bytes use append-only formats. `yoetz-installation-recovery/1` is a canonical,
authenticated envelope whose public header contains only bounded format/KDF/ciphertext metadata
and random identifiers. The encrypted body contains the installation identity, recovery
generation, exact IVK recovery root, allowed set mode, and the optional snapshot-manifest digest.
It never contains a plaintext secret, provider credential, BMK, derived key, path, keyring label,
repository value, or user content.

`yoetz-installation-snapshot/1` is manifest-last and content-addressed. Creation holds one
installation-wide maintenance lease, pins every catalog/task generation and frontier, snapshots
SQLite through its online Backup API, copies only the referenced ciphertext/object/vault members,
fsyncs the staged tree, verifies it from a fresh reader, and atomically publishes the final
directory. It never copies a live WAL/SHM file and never calls an incomplete directory a set.

Compact and self-contained artifacts carry exact compatibility identities. Their encoding and
cryptography are platform-neutral. Recovery is runnable only on the release-proven macOS arm64 and
glibc Linux x86-64 service cells. Windows archive/console code remains portability evidence, not a
Windows service claim, until ADR-007's complete Windows cell passes. Host-specific keyring entries,
paths, sockets, and pipes are never transferred.

## Provision, rotate, and revoke

Provisioning is available only while the current vault is `ready` and after action-bound local
human authorization. It uses digest-bound preview/execute:

1. acquire the installation-wide maintenance lease and freeze the structural inventory;
2. preview mode, secret form, member counts/bytes, captured generations/frontiers, destination
   safety class, compatibility identities, warnings, and a canonical plan digest;
3. collect or generate the secret only after the human confirms that exact plan;
4. stage the recovery artifact and, for a self-contained set, the complete snapshot;
5. reopen and verify the set using the still-live candidate secret, including vault sentinel,
   catalog identity, all vault records, object authentication, full ledger replay, provider
   credential presence, privacy-policy identity, checks, receipts, and another close/reopen cycle;
6. record the new recovery generation in the encrypted vault and publish the set atomically.

Rotation provisions a new generation and only marks it current after the same verification. The
prior material remains usable until the new generation commits.

Revocation performs a forward cryptographic rotation. It stages a new vault-encryption root,
rewraps/re-encrypts every vault record under that root, rebuilds and verifies the vault index,
provisions a new passphrase envelope, and switches vault directory, installation marker, and
recovery generation through one restart-reconcilable journal. The old vault, envelope, and recovery
material remain preserved for rollback/review and are never overwritten in place.

Historical catalog/privacy commitments cannot all be recomputed: workspace/external refs were
intentionally one-shot and are not retained. Therefore the keyed record locator and installation
MAC root remain stable and are sealed inside the new root-state bootstrap. Index authentication is
separately re-derived from the new vault root. Possession of a revoked old artifact can still derive
opaque historical commitments; it cannot authenticate the current vault index, decrypt the rotated
vault, read its structural rows, mint a service authorization proof, or protect/decrypt future vault records.
This is the exact forward-revocation boundary—not a claim that formerly disclosed ciphertext or
commitment keys can be made unknown again.

## Recovery ceremony

Recovery is a local-human YZH1/YZS1 operation and is available while the service is structurally
reachable but not `ready`. It never runs through MCP arguments, agent chat, ordinary control
payloads, argv, environment, configuration, stdin pipelines, shell history, clipboard, logs,
traces, issues, receipts, or support exports.

The ceremony binds the exact candidate set, current installation state, destination state,
recovery generation, target envelope choice, service generation, expiry, and plan digest. It opens
the artifact/snapshot through a protected local picker or trusted-console path, reads the recovery
secret through a no-echo protected field, and consumes only bounded one-shot handles. The user then
chooses a new human passphrase or a verified platform credential-store-backed generated envelope.
No ambiguous credential-store write may cause fallback to a different envelope.

The service decrypts only into a generated quarantined target. Before switching it verifies:

- artifact authentication, secret, installation/recovery generation, mode and manifest binding;
- current-state preservation and absence of an unsafe/ambiguous target;
- vault sentinel and every vault record, catalog and bundle integrity, object authentication,
  complete replay/frontiers, privacy-policy identity, provider credential presence-only state,
  check/receipt access, and close/reopen;
- compatibility/migration support and the generation-fenced atomic switch plan.

Wrong secrets, tamper, mismatched installations, revoked/stale plans, partial state, cancellation,
crash/restart, concurrent recovery, unsupported versions, and ambiguous targets fail closed without
mutating active authority. After a successful switch the prior encrypted state remains retained as
an inactive recovery generation until an explicit, separately authorized retention decision.

## Agent-safe continuation

Agents never receive a secret, recovery artifact/path, keyring identity, decrypted fact, or generic
recovery authority. Ordinary status may return only a closed recovery state, structural
availability, an opaque operation/continuation identifier, expiry, and one exact trusted next
command.

An allowlisted local agent may request a zero-secret handoff for the exact failed operation. That
request may launch an action-bound native local-human prompt only when the installed candidate's
platform adapter and capability evidence are allowlisted. Otherwise it returns the trusted terminal
command. The agent suspends the original operation, does not spin or create replacement requests,
and retries the same request identity only after the continuation reaches a terminal result.

An allowlisted native prompt displays the recovery action and nonsecret plan facts, authenticates local user
presence, owns picker/secret entry, and returns only a one-use challenge-bound attestation and a
bounded terminal outcome. macOS, Linux, and Windows each require their own artifact-bound adapter
and live drill; platform names or a generic GUI/TTY are never capability evidence. This change
ships the trusted-console fallback; no native-prompt cell is advertised by this ADR alone.

## Public status vocabulary

The public recovery state is exactly:

- `pristine_setup` — no existing encrypted installation; only initialization is eligible;
- `temporarily_locked` — the expected key exists and ordinary unlock may succeed;
- `auto_unlock_repairable` — an existing scoped entry is structurally repairable after local
  authentication;
- `recovery_material_required` — ordinary unlock paths are unavailable and provisioned recovery
  metadata says a recovery ceremony is structurally possible;
- `recovery_in_progress` — one exact staged recovery owns the installation lease;
- `recovered` — the active generation was reached through a completed recovery ceremony;
- `permanently_unrecoverable` — the current encrypted installation has no valid provisioned
  recovery generation and no ordinary key path; this is never inferred merely because the user has
  not yet selected an external artifact.

Every state is paired with a closed reason and next action. It reveals no path, label, artifact
existence beyond the installation's own provisioned metadata, secret fact, input-dependent text,
or provider/user content. Setup and recovery prompts explicitly distinguish creating a new
passphrase from entering an existing unlock/recovery secret.

## Platform and release proof

Windows becomes an advertised runtime only when ADR-007's complete Windows service/storage/keyring
cell passes; a console adapter alone is insufficient. Each macOS, Linux, and Windows candidate must
prove from the built artifact:

- owner-only local transport and peer identity, service singleton/restart, keyring and secret-memory
  behavior, trusted-console fallback, and action-bound native prompt;
- compact original-profile recovery and self-contained clean-profile recovery;
- cross-platform synthetic fixtures for every source/destination pair;
- wrong secret, tamper, wrong installation, revoked/stale generation, partial write, kill/restart,
  cancellation, concurrency, and rollback preservation;
- catalog/bundle/object authentication, full replay, provider credential presence-only state,
  privacy identity, reopen, check, and receipt;
- canary scans proving that vault/recovery secrets, wrapped key bytes, keyring identities, paths,
  provider credentials, and user content never reach structural storage, ordinary frames, process
  metadata, logs, traces, errors, exports, support evidence, agents, or generated receipts.

Deterministic mocks prove protocol behavior but never populate a release support cell. A missing or
unattended native prompt keeps that cell unavailable and the command fallback active; public claims
name only the exact live-drilled artifact/platform cells.
