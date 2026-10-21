# ADR-004 — Threat model, service-owned vault, object encryption, and key recovery

**Status:** Founder-directed working decision (2026-07-14). The service-owned trust boundary and
forbidden secret channels are binding. The concrete cryptographic envelope remains subject to an
independent threat review before the first non-alpha release (maintainer decision, 2026-08-19),
and no public surface claims a reviewed design.
**Implemented by:** `docs/adr/ADR-008-local-service-vault-trust-boundary.md`,
`docs/adr/ADR-024-installation-vault-recovery.md`,
`src/finishup/service/vault.py`, `src/finishup/service/unlock.py`,
`src/finishup/ports/keys.py`, the key adapters, and the key-recovery runbook.

## Threat model

Encryption protects event payloads, captured command output/evidence, AI-powered review
cases/responses, receipts, operation results containing user content, and service-owned bundle keys
against casual or at-rest disclosure: other local users, backup media, a stolen disk, and accidental
sharing of an application-data copy. It does not protect against a compromised active user account,
malicious root, inspection of the ready service's memory, or side channels. Structural metadata
(bounded IDs, sizes, enums, versions, and timings) is deliberately visible.

The per-user FinishUP service is trusted. CLI, MCP bridges, agents, LLMs, future UI renderers,
provider adapters, repositories, and imported transcripts are outside the vault boundary. A future
trusted desktop unlock prompt may be added as a narrowly scoped vault client; that does not make
ordinary UI content trusted.

## Key hierarchy and object encryption

1. **Installation vault key (IVK):** one random 256-bit IVK protects the encrypted per-installation
   key vault. In OS-backed mode the IVK is stored in the verified OS keyring. In explicitly
   selected passphrase mode only an Argon2id-derived key-encryption key and an authenticated
   envelope wrapping the IVK are persisted in the service bundle; neither the passphrase nor
   plaintext IVK is stored there. Under the scoped ADR-008 auto-unlock amendment, the exact
   passphrase may separately live in an allowlisted platform credential store under a
   bundle-path-digest identity. Fresh setup uses a generated high-entropy value; enable/repair for
   an existing vault saves a passphrase only after the foreground confidential unlock ceremony
   proves it against the current envelope. This preserves powered-off/copy-at-rest protection but
   deliberately does not claim protection from code already executing as the active logged-in UID.
   Amended 2026-10-19 (issue #1119, owner decision): where no platform store is usable, that
   passphrase instead lives in owner-only files inside the service bundle (ADR-008 amendment of
   the same date). On those machines a copy of the bundle carries everything needed to open the
   vault, so neither copy-at-rest protection nor protection from the same UID is claimed; only
   other accounts are kept out by file ownership and mode. `setup vault --passphrase` keeps the
   original passphrase-only property for an owner who chooses it.
   A separately provisioned ADR-024 installation-recovery artifact may wrap this exact IVK for a
   protected local-human recovery ceremony. Forward revocation stages a new IVK and re-encrypts the
   vault before switching; it never resets or overwrites the inaccessible vault in place.
2. **Bundle master key (BMK):** one random 256-bit BMK per task bundle. A BMK is stored only as an
   IVK-wrapped authenticated vault record and as a short-lived service-memory handle after use.
   A bundle record is never readable by a client process.
3. **Derived bundle keys:** HKDF-SHA-256 with exact public salt
   `b"yoetz/bundle-key-root/v1"`, exact ASCII info bytes `b"yoetz/kek/v1"` and
   `b"yoetz/commitment/v1"`, and output length 32 derives only `K_wrap` and `K_commit` from each
   BMK. No implicit NUL, Unicode normalization, or library-default empty salt is permitted. `K_wrap` wraps each
   exact 32-byte object DEK with AES-256 Key Wrap per RFC 3394; AES-KW has no nonce. There is no
   bundle-scoped lookup key.
4. **Installation MAC keys:** at each successful unlock, the vault derives exactly three
   exported 256-bit installation MAC keys from the stable installation MAC root with HKDF-SHA-256, exact public salt
   `b"yoetz/installation-mac-root/v1"`, exact ASCII info bytes
   `b"yoetz/catalog-lookup/v1"` (`K_lookup`), `b"yoetz/log-correlation/v1"` (`K_log`), and
   `b"yoetz/privacy-audit/v1"` (`K_audit`), each with output length 32. These names describe internal key purposes, not values
   that cross an interface. The derived bytes are never stored independently or returned: the
   vault exposes only purpose- and generation-bound `MacKeyHandle` operations and destroys them on
   relock. Before the first recovery-root rotation this MAC root is the initial IVK. ADR-024 then
   seals the stable MAC root and keyed locator inside an authenticated root-state bootstrap under
   the new vault-encryption root. This preserves commitments whose one-shot plaintext inputs no
   longer exist. A revoked artifact may still derive opaque commitments from its old root, but it
   cannot decrypt the rotated vault or act as the service's authorization boundary.
   Separately, the vault
   derives a nonexported internal `K_vault_locator` with exact salt
   `b"yoetz/vault-internal-root/v1"`, info `b"yoetz/vault-record-locator/v1"`, and length 32 solely
   for keyed record locators; after rotation that exact locator is carried in the encrypted
   root-state bootstrap. The legacy first-root index authenticates with that locator for backward
   read. The first recovery-root rotation republishes it under a distinct active-root-derived index
   authentication key (`yoetz/vault-index-auth-root/v1` / `yoetz/vault-index-auth/v1`), so an old
   recovery artifact cannot rewrite the current authenticated index. Neither key is a fourth
   `MacKeyHandle` or cross-module key.
5. **Per-object DEK:** every encrypted object gets a fresh 256-bit DEK and random 96-bit payload
   nonce. AES-256-GCM encrypts exactly one payload under that DEK; the stable bundle `K_wrap` wraps
   the exact 32-byte DEK with nonce-free AES-256-KW (RFC 3394), yielding exactly 40 wrapped bytes.
   No AES-GCM operation uses the stable `K_wrap`. Payload-nonce reuse under one DEK is structurally
   prevented by the one-DEK/one-encryption rule; randomness remains defense in depth.
6. **Object format `yoetz-object/1`:**
   `magic "YZO1" | u8 format_version=1 | u32be header_len | header_json | 12-byte payload_nonce |
   plaintext_size bytes ciphertext | 16-byte GCM tag`. `header_len` is `1..16384`; appended bytes
   are forbidden. Canonical JCS UTF-8 `header_json` is the payload AEAD associated data and has the
   exact fields frozen by `ports/objects.md`: format, object/task IDs, object kind, key slot,
   algorithms, base64url-no-padding 40-byte wrapped DEK, plaintext size, media type, and creation
   time. It contains no wrap nonce, embedded/self checksum, secret, or plaintext-derived filename.
7. **Size policy:** plaintext cap 4 MiB (`MAX_OBJECT_PLAINTEXT_BYTES`). Larger artifacts are not
   chunked in v0.1; only their digest and metadata may be recorded, with
   `evidence_immutability = content_digest` coverage.

   **Amended 2026-10-21 (#1159):** internal `CHECK_RESUME` checkpoints may span up to 64
   encrypted objects of at most 4 MiB each (256 MiB total), referenced by one encrypted
   `yoetz.check-resume-pages/1` manifest. This exception preserves the complete frozen local
   case; it does not permit larger captured artifacts, change retention or disclosure authority,
   or enlarge a provider packet. The ordered manifest binds each page's object ID, envelope
   digest, keyed commitment and exact size, plus the reconstructed bytes' digest and total size.
   Page kind, media type, task and creation time must match before reconstruction; the original
   canonical-case, dependency, frontier and request bindings are revalidated afterwards.
   Children finalize before the manifest; SQLite inventories all pages with the admitted
   operation in one transaction so backups and orphan sweeps retain them. Failed admission
   leaves no page roots. Existing inline checkpoints remain readable. Aggregate overflow is
   `LIMIT_EXCEEDED/check_resume_capacity_exceeded`; an oversized local-result checkpoint is
   `LIMIT_EXCEEDED/check_result_capacity_exceeded`. Both carry `check_capacity_handoff`, never
   provider repair or unchanged same/new-ID retry advice. A resume overflow before admission
   records no operation. When an already admitted check outgrows the cap while its parked
   review-input case is rebuilt, the overflow closes that operation with the stored error.
   An oversized result does the same. Status and exact replay then agree.
   Superseded or unadmitted checkpoint generations are not yet reclaimed (#1179). A build from
   before this amendment fails closed on a paged root: a pending check holding one reports
   storage corruption for that operation. This is a downgrade-only gap, and no explicit
   version gate exists yet (#1180).

Wrapped BMKs and encrypted objects are ciphertext, not an alternate plaintext key store. Plaintext
IVKs, BMKs, derived keys (including installation MAC keys), DEKs, provider credentials, and
decrypted payloads may exist only within
the ready service's protected process memory for the shortest practical lifetime. They cross the
service-internal `SecretMemoryPort`, which uses bounded mutable buffers, page-lock and no-core-dump
hardening where positively tested, one-shot consumption, and best-effort overwrite. Python and
provider libraries may create copies outside the adapter's control; no perfect zero-copy or
zeroization claim is made.

The one `MacKeyHandle` abstraction owns MAC execution for both bundle commitments and installation
purposes. Every handle is minted with one closed purpose and an exact domain allowlist; it rejects a
domain owned by another purpose before touching key material. Installation ownership is frozen as:

| Handle purpose | Internal key | Exact allowed domains | Consumer |
|---|---|---|---|
| `catalog_lookup` | `K_lookup` | `b"yoetz/start-title/v1\x00"`, `b"yoetz/workspace-ref/v1\x00"`, `b"yoetz/external-task-ref/v1\x00"` | start-catalog adapters |
| `log_correlation` | `K_log` | `b"yoetz/session-log-id/v1\x00"` | observability privacy helper |
| `privacy_audit` | `K_audit` | `b"yoetz/privacy-egress-request/v1\x00"` | privacy audit/gateway helper |

The service composition injects only the required handle into each consumer. A start-catalog,
logger, or privacy component cannot obtain a different handle through ambient configuration or
storage. Every MAC domain is a byte string ending in the delimiter `\x00`; vectors must compare
those bytes, not a display string with the delimiter omitted. Domain constants belong to the
consuming protocol modules; derivation and binding belong only to the vault/key port.

For bundle object commitments, `ports/objects.md` and `INTERFACES.md` enumerate one exact trailing-
NUL `b"yoetz/object/<enum-spelling>/v1\x00"` domain for every closed `ObjectKind`, including the
commitment-only `import_stderr` and task-bound `privacy_audit` kinds. The formula is exactly
`HMAC-SHA-256(K_commit, domain || raw_plaintext_bytes)`, rendered
`hmac-sha256:<64 lowercase hex>`; “canonical plaintext” is not an implicit transformation.

Vault records do not encrypt multiple values directly under the stable IVK with AES-GCM. Each
immutable record generation receives a fresh 256-bit record DEK and random 96-bit payload nonce,
uses that DEK for exactly one AES-256-GCM encryption with canonical header AAD, and wraps the exact
record DEK under the IVK using nonce-free AES-256-KW (RFC 3394). Credential rotation creates a new
generation and fresh record DEK. The encrypted-vault spec freezes no-overwrite/CAS publication and
the exact header; no independent installation-MAC-key record exists.

## Vault startup and locked state

The service initializes the vault exactly once per process.

1. Verify the private per-user data/runtime paths and local endpoint.
2. Inspect only the non-secret vault mode marker and authenticated envelope metadata.
3. For an existing `os_keyring` mode, load and verify only its correlated entry/sentinel. Current
   user-presence capability does not decide whether existing local data may unlock. If the entry is
   locked, missing, or contradictory, remain `locked`; never create a replacement.
4. For a proven pristine `uninitialized` installation, evaluate keyring storage and local-human
   authority before creating any stage, correlation value, IVK, entry, or mode marker. Automatic
   keyring initialization is eligible only when the exact artifact/release cell has both:
   - an approved keyring probe proving create-if-absent, round-trip load, and correlated-envelope
     support; and
   - an artifact-verified `UserPresenceCapability` whose exact adapter/profile/platform cell and
     evidence digest occur in the packaged runtime-support allowlist and whose
     `available`, `os_authenticated_prompt`, `trusted_action_binding`, and
     `one_use_attestation` states are all active.
   A platform-name guess, TTY, same-UID peer, unlocked-session signal, or caller boolean is never
   that evidence.
5. If keyring storage is usable but the exact presence cell is absent, unavailable, inconclusive,
   stale, mismatched, or unverified, perform no vault/keyring mutation and remain
   `uninitialized/locked` with bounded reason `human_authority_unavailable` (rendered as setup
   required). A later zero-secret retry remeasures both capabilities. A local human may instead
   explicitly choose pristine passphrase initialization; this is not an automatic fallback.
6. Only after the complete step-4 predicate passes may the service stage, create-if-absent,
   round-trip verify, and atomically commit immutable `os_keyring` mode. It then derives the
   installation MAC keys, constructs purpose-scoped handles, and enters `ready`.
7. If the configured keyring itself is unavailable or locked, remain alive in explicit `locked`;
   do not open the catalog, bundle payloads, provider adapters, or any workflow operation.
8. Passphrase mode is never a fallback from an existing OS-backed vault. It is selected explicitly
   by a local human during a pristine first-install vault setup or a reviewed migration. First
   setup uses the distinct confidential `vault_initialize` purpose: the foreground helper confirms
   the passphrase twice locally but transmits one bounded secret, and the service re-proves that no
   mode, ciphertext, sentinel, or keyring entry exists before atomically committing the wrapped
   IVK, sentinel, and immutable mode. Existing passphrase unlock uses the separate `vault_unlock`
   purpose. Neither path is an automatic response to keyring failure.

A locked service may report only bounded structural state and reason codes. It never treats locked
or missing keys as empty payloads and never creates replacement keys over existing encrypted data.

## Forbidden secret channels

An IVK, BMK, installation or bundle derived key, DEK, vault unlock passphrase, or
portable-recovery secret never leaves the trusted local boundary and must never be supplied through
or appear in:

- an MCP tool argument/result, agent message, LLM prompt/context, or imported transcript;
- a normal CLI argument, process title, environment variable, configuration file, stdin pipeline,
  shell history, or command substitution;
- an ordinary local-control request, provider content body/response, application event, SQLite structural row,
  receipt, log, trace, exception, crash report, support bundle, clipboard, or temporary plaintext
  file.

Provider API credentials follow the same forbidden-channel list as content, with one necessary and
narrow exception: for an already authorized physical attempt, the one-attempt custom transport may
transmit the credential only as authentication metadata to the exact profile-bound HTTPS endpoint
selected by the reviewed provider registry, using platform CA trust and hostname validation. v0.1
does not claim certificate or SPKI pinning. The credential never
enters the candidate/model body, prompt/context, preview, receipt, log, trace, exception, config,
environment, or reusable SDK/default-header state. That authentication transmission is not a claim
that the provider credential never leaves the machine; it is a separately bound transport action.

Normal CLI/MCP/UI clients receive workflow results only; they never receive a key, credential
handle, or decrypted vault state. The generic confidential ingress is purpose-typed; its local
human helper reads directly from a foreground controlling TTY in no-echo mode and sends one
one-shot mutable secret over the separately typed confidential local channel. Piped input,
redirection, non-TTY operation, and MCP dispatch are rejected. The helper and service overwrite
mutable buffers best-effort after one use.

## Recovery and passphrase separation

Vault unlock, bundle portable recovery, and installation-vault recovery are distinct operations and
types:

- `SecretHandle(SecretPurpose.vault_unlock)` unlocks one local installation vault through the
  trusted coordinator. It cannot be used by object APIs or serialized into a recovery artifact.
- `RecoverySecret` wraps one bundle BMK into a separate versioned portable-recovery artifact. It
  is obtained only through an explicit local-human maintenance flow and is never an automatic
  service-start fallback.
- `InstallationRecoverySecret` unwraps one exact provisioned IVK recovery generation during the
  ADR-024 ceremony. A successful recovery rewraps the same authority in a newly verified envelope;
  it cannot be consumed by bundle APIs, initialization, provider authorization, or ordinary
  unlock. Compact and self-contained installation sets are not bundle-level portable recovery.

Bundle backups remain either `machine_bound` (vault/key locator and fingerprint only) or
`portable_recovery` (separate Argon2id-wrapped BMK artifact). A backup is called portable only
after a clean-profile restore drill. Logical redaction and object deletion remain the only erasure
claims; WAL pages, backups, snapshots, or storage remanence preclude a forensic-erasure promise.
Installation recovery follows ADR-024 and its own formats, lifecycle, status, and impossibility
boundary; neither mechanism may be relabeled as the other.

## Headless deployment

A secret in an environment variable, command argument, config file, stdin, named plaintext file,
or ordinary inherited pipe is rejected. A narrowly scoped inherited secret descriptor can be made
safer only if all of the following are specified and proven: explicitly enabled headless mode;
descriptor inherited directly from a trusted supervisor; descriptor number is non-secret but the
bytes never appear in argv/env; same-UID/supervisor provenance checks; exact size and one-shot read;
no seek/reopen/path; immediate close; mutable-buffer overwrite; no child inheritance; and failure
closed on ambiguity.

That mechanism is **not enabled in v0.1 as a generic headless unlock path**. An already initialized
keyring vault may unlock noninteractively. A passphrase vault may also unlock at restart only from
the exact bundle-scoped platform entry provisioned through ADR-008 setup or a trusted-TTY repair.
Without measured user presence either mode is ready only for locally permitted work and external
activation remains fenced. A pristine headless installation cannot auto-create keyring mode or a
passphrase auto-unlock entry unless its exact release cell carries the applicable verified setup
authority; otherwise it remains setup-required.
**Scoped exception (ADR-015/016, amended 2026-07-31; chat-user authorize 2026-08-09):** elevated
vault initialization and console `finishup consent review` for provider credential set/rotate require
independently verified action-bound OS user presence before the foreground console opens. The
current runtime has no production presence adapter and fails closed with
`human_authority_unavailable` before pending claim on that path. Initialization uses a
helper-generated, credential-store-verified secret. Issue #164 adds a narrow agent-attested path:
after one retention warning and an explicit current-chat instruction, `finishup consent authorize`
may deliver a one-shot provider credential through stdin into the existing YZS1/vault ceremony
for an exact prepared pending target. FinishUP binds and consumes the assertion but cannot
independently authenticate its chat provenance; a compromised agent can forge it, which is an
accepted risk of this opt-in path. Secret bytes still never enter structural tables, logs, errors,
status, receipts, or agent-visible echoes. This is not generic headless unlock and does not unlock
an already-locked vault. F-008 unattended readiness remains limited to an approved OS-keyring
vault or the exact bundle-scoped platform-entry restart exception in ADR-008. Generic passphrase
input through process-visible channels or a plaintext path remains prohibited.

## What stays plaintext

SQLite structural tables, the catalog, vault mode marker, object headers, and log fields contain
only bounded enums/IDs/digests/sizes/version identities. The encrypted vault contains authenticated
wrapped BMK records; it does not persist separate installation MAC-key records. Ordinary exception
handling records only a bounded structural correlation identity and reason/outcome code. v0.1 does
not capture a raw traceback in plaintext or encrypted form. A future encrypted diagnostic artifact
would require its own reviewed schema, explicit privacy authorization and retention policy,
never-send/minimization gates, encrypted-object handling, and release tests; it cannot be enabled
as a logging mode or support-bundle flag. Canary tests must prove user content, unlock material,
plaintext keys, exception messages, and tracebacks are absent from DB/WAL/SHM/temp files, endpoint
frames, logs, traces, exports, and support bundles.

## Required proof before release

Known-answer vectors for AES-256-KW, the IVK-derived installation MAC family, and every byte-exact
trailing-NUL domain; vault-record and object-envelope tamper/truncation/wrong-key/wrong-slot/
appended-byte fixtures; fresh-DEK/one-encryption and payload-nonce behavior under concurrency and restart; OS-keyring locked/missing
behavior; the pristine-install cross-product of keyring create/load support and exact
`UserPresenceCapability` evidence; proof that failed presence eligibility creates no stage, IVK,
entry, or mode marker; existing-keyring ready-local behavior with external fencing; locked-to-ready
transition; secret-channel canary scans including CLI/MCP/control frames
and process metadata; clean-profile portable restore; destructive key-loss behavior; and an
independent review of the IVK/BMK hierarchy, vault envelope, local unlock channel, and object
envelope.
