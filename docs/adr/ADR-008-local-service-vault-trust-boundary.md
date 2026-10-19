# ADR-008 — Local service and vault trust boundary

**Status:** Founder-selected working decision (2026-07-14), amended 2026-07-25 to permit
bundle-scoped passphrase auto-unlock through an allowlisted platform credential store. Binding for
v0.1 specification work; independent security review remains required before the first non-alpha
release (maintainer decision, 2026-08-19), and no public surface claims a reviewed boundary.
Amended 2026-08-23 by ADR-024 for installation-vault recovery, zero-secret agent handoff, and
platform-native prompt cells; amended 2026-08-30 by issue #404 for exact external-evaluator
process authority.
**Related:** ADR-001 owns single-writer lifecycle; ADR-004 owns cryptography and recovery; ADR-006
and the privacy protocol own outbound data authorization.

## Context

The earlier draft treated `finishup mcp serve` as a long-lived application owner and allowed a
standalone CLI command to open the same local state when MCP was absent. That made the integration
surface the trust boundary, required each process to acquire keys, made safe passphrase operation
through MCP impractical, and produced different behavior depending on which client started first.

## Trust boundary

| Component | Trust and authority |
|---|---|
| Per-user local FinishUP service | Trusted local authority. Sole owner of vault keys, decrypted state, catalog/task writers, provider gateway, and application facade. |
| Confidential human helper or future trusted desktop prompt | Narrowly trusted for one exact YZH1 ceremony and, when required, delivery of one YZS1 initialization, unlock, recovery, provider-credential, or reauthentication secret. It has no workflow, storage, provider-dispatch, policy, or long-lived key authority. |
| CLI, MCP bridge, future ordinary UI | Untrusted control/rendering clients. They may submit validated requests and receive bounded results; they cannot open storage, access key handles, unlock the vault, or weaken policy. |
| Agent, LLM, plugin, repository, imported transcript, provider | Untrusted content or external execution. Never receives an unlock secret or vault capability. |

Trusting the service does not imply trusting every local process. The service authenticates the
peer UID on an owner-only Unix-domain endpoint and exposes only an exact method allowlist. It never
accepts a caller-selected endpoint, filesystem path, key locator, provider object, or arbitrary
method name.

## Selected architecture

The v0.1 default is one restartable service authority per user and installation. A user supervisor,
interactive setup, or the fixed untrusted-client launcher may start the foreground service process;
the launcher conveys no key, credential, provider, path, or policy authority. The service starts in
`starting`, attempts OS-keyring unlock, settles into either `ready` or `locked`, and only then
binds, authenticates, and publishes its local control endpoint. The service never publishes an
endpoint it cannot yet answer; until publication a client's connect is refused, which the
on-demand connector treats as still-starting rather than unavailable (#235). It remains reachable
while locked so a human can inspect structural status and initiate the dedicated unlock flow. Only `ready` admits workflows,
maintenance, imports, payload access, or egress.

Authenticated local connections, admitted work, and harness observation rows resolved by the ready
sweep hold a process-idle lease. Once no connection or admission is outstanding and no row has
resolved for 7,200 seconds, the daemon performs its bounded stop and exits. The process-idle stop
is deliberately longer than the default idle relock so the cheap in-process soft lock — which
re-readies on the next ordinary admission — is always the first containment reached, and a live
workspace that holds off the relock holds off the stop with it rather than reaching the harsher
containment first. A later fixed on-demand launcher start advances the generation and reconnects to
the singleton winner. A passphrase-backed successor first tries its exact bundle-scoped auto-unlock
entry when one was explicitly provisioned; otherwise it remains locked until a local-human unlock.

On a pristine first install, keyring storage usability alone does not select immutable keyring
mode. Before creating a staging artifact, IVK, keyring entry, or mode marker, the service requires
both an exact approved create-if-absent/round-trip keyring cell and an artifact-verified
action-bound `UserPresencePort` capability for the same installed release cell. The presence
capability's adapter/profile/platform identity and evidence digest must match the packaged support
allowlist, and its authenticated-prompt, trusted-action-binding, one-use-attestation, and available
states must all be active. No platform-name inference or caller boolean is accepted.

If the keyring is usable but that presence cell is absent, unavailable, inconclusive, stale, or
mismatched, the service performs no keyring/vault write and remains `uninitialized/locked` with
bounded `human_authority_unavailable` setup-required status. If the keyring itself is unavailable
or unusable, it likewise remains uninitialized/locked with its bounded keyring reason. A local
human may explicitly choose `service initialize-passphrase`, which uses a distinct
`vault_initialize` confidential purpose; neither branch silently falls back. The helper states the
16–1024 UTF-8 byte contract, masks accepted input with `*`, re-prompts invalid or mismatched input,
confirms the passphrase twice locally, and transmits one one-shot secret. The service accepts it only after
re-proving no committed installation identity/catalog/mode, vault ciphertext/sentinel, or ambiguous
staging state, then allocating a fresh installation ID. A successful keyring query that somehow
finds a correlated entry for that exact new identity blocks; a locked/unavailable backend is
recorded but does not block this explicit proven-pristine choice. The service then atomically commits
the passphrase envelope, empty-vault sentinel/layout, installation ID, and immutable mode.
Later unlock uses the distinct `vault_unlock` purpose. Initialization can never reset/recover an
existing vault or act as fallback for a missing keyring entry; crash ambiguity fails closed without
deleting or replacing data.

If an existing vault loses every ordinary unlock path, initialization remains forbidden. The
service classifies only bounded ADR-024 recovery status and may accept one exact installation
recovery ceremony when provisioned metadata and a valid external set are available. Recovery uses
a generated quarantined target and an atomic authority switch; it never opens workflows early,
replaces active files in place, or treats an absent secret as empty state.

**2026-07-25 auto-unlock amendment.** Passphrase mode may use one allowlisted platform credential
store entry named `yoetz.auto-unlock.v1`, scoped by the SHA-256 digest of the absolute service
bundle path. Interactive first-run setup generates a high-entropy passphrase into a mutable buffer,
round-trips it through that store, initializes the passphrase envelope through the existing
confidential ceremony, and overwrites the buffer best-effort. If the platform store is unavailable,
and that failure is guaranteed to precede any credential write, setup visibly falls back to the
existing two-entry human passphrase ceremony. If a write may have committed but its read-back cannot
be verified, setup fails closed before vault initialization and tells the user to restore platform
credential access and rerun setup; it never creates a different manual passphrase beside an
ambiguous stored value. Neither path puts the secret in argv, environment, config, stdin, logs,
ordinary control, or MCP.

At restart the trusted service alone may read that exact scoped entry and submit it directly to the
vault unlock path. Missing, unavailable, malformed/rejected, and authenticated-but-stale entries
remain locked and surface bounded `passphrase_required`,
`auto_unlock_backend_unavailable`, `auto_unlock_rejected`, or `auto_unlock_stale` reasons. The
service logs one structural outcome/reason and never the entry, bundle path, or derived material.
Foreign bundle entries are neither read nor deleted.

**2026-08 soft-lock re-ready amendment.** The same trusted-service-only auto-unlock path may run
again after a *soft* lock that cleared in-process keys but did not revoke the installation's
scoped platform entry: `idle_relock`, `user_session_locked`, and `system_suspend`.
On the next ordinary control admission while still locked for one of those reasons, the service
attempts one scoped passphrase load (or OS-keyring retry) and, on success, rebuilds the ready
generation. This keeps MCP/CLI usable after idle or session soft locks without a human prompt when
setup already provisioned auto-unlock. It does **not** unlock after `explicit_lock`, does not run
for hard reasons (`passphrase_required`, `auto_unlock_*`, `vault_uninitialized`, `unlock_failed`,
`keyring_locked` when the backend will not load), and never accepts a secret from MCP, ordinary
control, argv, env, config, or stdin. The trusted foreground helper may also submit the scoped
entry through the existing unlock ceremony so `finishup service unlock` stays silent when that entry
is valid.

`monitor_lost` is deliberately excluded (2026-08-05 correction). The three reasons above describe
conditions the service can observe recovering from, so re-readying restores a state it can keep
watching. Losing the session monitor removes the capability that produces session-lock and suspend
events for the life of the process: auto-re-ready there would make the lock momentary and then run
on with the session-lock relock in this decision silently no longer applying, while
`ServiceStatus` still reported `ready`. A monitor-loss lock therefore holds until a trusted
ceremony, and `session_monitor=lost` remains observable in status either way.

For an existing human-passphrase vault, `service auto-unlock enable|repair` requires the ordinary
trusted foreground-TTY unlock ceremony first. Only the exact passphrase that successfully unlocks
the current envelope is then saved under the scoped platform entry, and every mutable helper buffer
is overwritten best-effort. This intentionally extends the at-rest trust root from the Argon2id
envelope alone to the logged-in user's protected credential store. It does not widen privacy
policy, provider activation, or any egress authorization. A delete-only `disable` would make a
fresh generated-passphrase vault unrecoverable, so disable remains unavailable until an atomic
credential-store deletion plus human-passphrase rewrap ceremony is specified and implemented.

**2026-08-31 rotation amendment.** `service rotate-passphrase` reauthenticates with the current
passphrase, collects and confirms a replacement through the masked trusted console, and stages the
replacement under a distinct scoped credential-store account before atomically rewrapping the
unchanged IVK. Exact prepared `vault_passphrase_rotate` agent authorization performs the same
transition using a locally loaded active secret and locally generated replacement; neither secret
crosses the agent boundary. Successful completion promotes the staged entry. After an ambiguous
interruption, service startup tries active and staged candidates, promotes the one that
authenticates the envelope, and discards a stale stage only after active succeeds.

Keyring usability is not action-bound human authorization. Under the resolved F-010 decision,
the first-install gate above prevents a new immutable keyring-mode choice when no verified
`UserPresencePort` exists. Existing keyring vaults created by an earlier supported release or
restored through reviewed migration remain readable: they may become ready for locally permitted
work without current presence, but external activation, privacy widening, provider-credential
set/rotate, and other durable authority changes stay fenced. No TTY click, same-UID peer, or
ordinary keyring unlock substitutes for the missing capability. Alternate verified platform
adapters, a separately designed admin-authorization secret, or a different first-install/migration
design require a new ADR; they are not implicit v0.1 fallbacks.

Normal clients use `ServiceClient` over the ordinary control protocol. MCP is a stdio-to-local-
service bridge: its process owns MCP framing but no application, key, storage, or provider state.
The CLI is the same kind of client except for `service run` (the daemon entrypoint) and
`service unlock` (the dedicated human helper). A future UI uses the same normal protocol; a future
trusted unlock prompt must use the separately typed unlock contract.
ADR-024 permits an ordinary client or agent to request only a zero-secret recovery handoff. It may
receive a closed structural state, opaque continuation identity, expiry, and exact trusted command;
it never receives set paths, artifact bytes, secret facts, keyring identity, or a vault capability.
Only an allowlisted platform adapter may turn that handoff into a native local-human prompt.

The service may hold decrypted state and opaque key or provider-credential handles only in process
memory. Clients never receive them. All secret buffers cross the swappable `SecretMemoryPort`:
bounded mutable buffers, tested page-lock/no-core-dump hardening where the platform supports it,
one-shot consumption, and best-effort overwrite. Python and provider libraries can still make
uncontrollable copies; neither Python nor the OS can prove perfect zero-copy handling or complete
zeroization. On shutdown or relock, the service stops admission, closes provider and storage
handles, and clears those handles and buffers best-effort.

Locked startup never opens the encrypted catalog merely to obtain a generation. Under the
per-install singleton, lifecycle advances a fixed owner-only nonsecret generation record at
`config/paths.service_generation_path()` using canonical digest, atomic replace, file fsync, and
directory fsync before publishing endpoints. After unlock the catalog CAS verifies/copies that
already advertised generation; contradiction/rollback terminates rather than changing generation
behind connected clients.

## Control and unlock channel separation

The ordinary control channel carries canonical, bounded workflow/support envelopes and structural
service status. Its method registry contains no unlock method and its request models cannot carry
secret bytes.

Control failures are bounded reasons, not messages, and the reason must not misdescribe durable
state. A handler returning is the commit boundary: everything after it — projection binding,
client projection, and success-body validation — only shapes the response. An unexpected failure
there is reported as the retryable `response_projection_failed`, which states that the operation
stands and that the caller resolves it by replaying the same `request_id` once; if that replay also
fails the failure is deterministic and the caller reads `status view=operation` instead (ADR-043). The bridge's own text projection is not part of this window's failure modes: a
text that cannot be built never fails the call. Reporting it as the
generic non-retryable `internal_error` would assert something false about the ledger and steer a
caller away from the idempotent replay that recovers it. Deliberate bounded failures raised in the
same window — `privacy_projection_blocked`, `privacy_projection_unavailable`, and public
application errors — already describe real conditions and pass through unchanged.

The service exposes three fixed owner-only same-UID endpoints: ordinary control; YZS1 one-secret
ingress; and YZH1 multi-phase human control. YZH1 is the sole challenge/binding creator, returns
bounded structural previews, supports zero-secret keyring retry, coordinates provider credential
set/rotate/remove, accepts typed privacy decisions, and owns the exact ceremony for changing or disabling
idle relock. Durable policy widening, credential changes, and idle-security weakening
require internal strong reauthentication; a `confirm_every_request` decision already inside the
durable policy uses exact foreground digest-bound consent and creates no reusable authority. YZS1
accepts only a binding from one still-live YZH1 ceremony and never accepts a zero-length retry or
creates a challenge. Ordinary control/MCP schemas and their import graphs expose no route to either
confidential client. This is not a claim that arbitrary malicious same-UID code with socket access
cannot emulate a YZH1 client; that limitation is explicit below and in resolved decision F-011.

The confidential secret-ingress channel is separately typed by a closed nine-value `SecretPurpose`
registry: `vault_initialize`, `vault_unlock`, `portable_recovery`,
`provider_reauthentication`, `provider_credential`, `privacy_reauthentication`, and
`security_reauthentication`, plus `installation_recovery` and `vault_rewrap`. The seventh value is
used only by an exact idle-relock-policy target; the eighth accepts one provisioned installation
recovery secret, and the ninth accepts a new passphrase only after the old IVK and staged target are
fully authenticated. Neither recovery purpose can initialize a vault, unwrap a BMK, authorize a
provider, or weaken privacy policy. The channel accepts
only one-shot material for the exact live ceremony without placing bytes in the ordinary control
envelope.
Initialize is available only for a pristine uninitialized installation and accepts one passphrase
after the helper's local two-entry match; unlock is available only for an already committed locked
passphrase vault. Their handles are not interchangeable. The pure confidential protocol maps the
wire purpose to one one-shot `SecretHandle(SecretPurpose.vault_unlock)` consumed by the trusted
unlock coordinator; ordinary clients cannot construct it. The manual helper must prove a same-user,
foreground trusted console. On macOS/Linux it reads directly from `/dev/tty` with raw secret echo disabled,
requires stdin and stderr to be TTYs for the same user-visible terminal, and requires the process
to be in the foreground process group. On Windows it opens `CONIN$`/`CONOUT$`, requires real
console handles and current-process attachment, and reads with raw secret echo disabled through
Win32 console APIs. Both adapters write only `*` mask markers and backspace erasure; this exposes
entered length to a local terminal observer but not secret content.
Terminal ownership alone is not user-identity evidence. The helper rejects redirection, pipes,
environment/config/argument input, and noninteractive execution; establishes a
separately typed peer-authenticated connection; and erase mutable buffers best-effort after the
service consumes them. No MCP registry, `ServiceClient`, or public application method can reach
this channel. **Amendment (ADR-015/016, 2026-07-31):** `finishup consent review` may use this
trusted-console boundary for `vault_initialize`, `provider_credential_set`, and
`provider_credential_rotate` only after independently authenticated, action-bound OS user
presence. The current runtime has no production presence adapter and fails closed before console
open or pending claim. Initialization accepts only its helper-generated,
credential-store-verified passphrase; provider secrets are entered inside the confidential
ceremony. **Amendment (issue #164, 2026-08-09):** after an explicit current-chat instruction, an
allowlisted first-party agent may run `finishup consent authorize` for exact prepared
`vault_initialize`, `vault_passphrase_rotate`, `provider_credential_set|rotate`, and
`repository_privacy_grant` without the
trusted console. Vault initialization generates and credential-store-verifies its secret wholly
inside FinishUP; the agent supplies no secret material. The
agent assertion binds the pending digests but is not independently authenticated by FinishUP; a
compromised agent can forge it. One-shot provider credential bytes may enter the same YZS1 ingress
from authorize stdin after warning acknowledgement and are overwritten best-effort. Provider
credentials become opaque adapter-scoped handles in the service vault; provider adapters and
normal clients never receive reusable credential bytes.

**2026-10-19 credential-removal amendment (issue #1119).**
`provider_credential_remove` is an owner-only YZH1 ceremony for one exact
`ProviderCredentialTarget(action="remove")`, with a bounded preview and target digest binding.
It starts at `AuthorizationRequiredPhase`, using the same scoped OS-presence or vault-secret
reauthentication paths as rotation (`provider_reauthentication`); it then commits without a
`provider_credential` secret phase. The helper always requires the trusted foreground terminal,
even when scoped auto-unlock supplies reauthentication. The existing production presence scope
is unchanged; a platform adapter outside that scope cannot authorize removal. Locked vaults and
missing records refuse (`vault_locked`, `record_missing`). The vault consumes the exact single-use
proof before deleting with `expected_generation`; only confirmed deletion returns
`ProviderCredentialRemoveResult(status="removed")`. Matching unused provider handles are invalidated,
including on an ambiguous deletion, so they cannot start a later request. Already-started requests
cannot be recalled. The CLI confirms with default No; the full-screen interface hands over the
terminal. Binding and privacy policy stay unchanged. This ceremony is deliberately absent from
ADR-015 elevated bootstrap, `finishup consent`, delegated chat authorization and MCP.

Known limit (review of #1119, accepted for this release). Where scoped auto-unlock supplies the
reauthentication factor, the default for a generated-passphrase vault whose owner never learned
the passphrase, a process that runs as the same user and controls a foreground pseudo-terminal can
complete removal without a human. That is the same authority `provider_credential_set` and
`provider_credential_rotate` already have with the same factor. Removal discloses nothing; its worst
case is a deleted key that the owner enters again. Requiring an owner-entered factor or action-bound
OS presence would leave removal unusable for the default vault until production OS presence covers
credential ceremonies. That stricter rule should therefore land for set, rotate and remove together;
it is a follow-up on #1119.

`UnlockCoordinator` solely owns the persistent passphrase throttle: admission delay, in-progress
reservation, failure charge, success reset, crash re-arm, and repair. It calls cryptographic vault
verification only after reserving the attempt. `VaultService` never reads or mutates that throttle
and is the sole minter of `HumanAuthorizationProof`; presence adapters and coordinators can only
supply an exact source/challenge for the vault to consume. This division applies equally to
unlock, provider, privacy, and security reauthentication.

Peer UID checks and owner-only filesystem permissions protect local transport from other users.
They cannot distinguish a malicious process already running as the same user; that is outside the
stated threat model. TTY checks establish an explicit local-human ceremony, not a cryptographic
proof that automation is impossible, and public documentation must say so.

## Platform evidence and claim limits

The selected boundary is grounded in platform capabilities, but the existence of an API is not by
itself a FinishUP support claim:

- Apple documents Keychain as storage for passwords, keys, certificates, and other small secret
  data protected by access controls and data-protection classes
  ([Apple Platform Security](https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web)).
  FinishUP still has to verify the exact backend, accessibility class, user-presence behavior, and
  locked-session behavior in each advertised macOS release cell.
- The Freedesktop Secret Service protocol explicitly models locked items/collections and an
  implementation-specific prompt path for unlocking
  ([Secret Service API, Unlocking Objects](https://specifications.freedesktop.org/secret-service/latest/unlocking.html)).
  This supports a `locked` service state; it does not justify claiming that every Linux desktop or
  headless session has a usable, unlocked, or approved keyring.
- Linux Unix-domain sockets expose peer credentials through `SO_PEERCRED`
  ([unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)); macOS exposes the effective peer
  identity through `getpeereid`
  ([Apple manual page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)).
  Release tests must prove the exact adapter behavior, fail-closed handling, endpoint ownership,
  and replacement resistance on every advertised platform.
- Python's `getpass` documentation permits a warning followed by input from `sys.stdin` when
  echo-free input is unavailable ([Python documentation](https://docs.python.org/3/library/getpass.html)).
  That fallback violates this trust boundary. The confidential helper therefore opens `/dev/tty`
  itself, verifies the foreground controlling terminal, disables raw echo while rendering only
  length-revealing `*` mask feedback, and fails closed if
  any part of that ceremony is unavailable; it never delegates fallback selection to `getpass`.

These sources justify the architecture and its required probes, not broad statements such as
"the OS keyring is always secure" or "same-user local IPC is safe." Public claims remain limited to
exact, measured package/platform/backend cells recorded by the release evidence matrix.

## Options evaluated

### A. Persistent service owns vault and writers — selected

This gives one unlock ceremony, stable CLI/MCP/UI behavior, one privacy-policy enforcement point,
and one durable writer topology. The added local protocol and service lifecycle are justified by
the security and concurrency boundary they create.

### B. Separate key broker plus per-client application processes — rejected for v0.1

A key broker that exports keys violates the boundary. A broker that performs cryptography by RPC
requires every object operation to cross a second protocol while independent application
processes still compete for catalog and bundle writers. It is more complex without satisfying the
single-authority product model.

### C. Per-client keyring/passphrase unlock — rejected

CLI and MCP processes would handle keys or prompts, an MCP agent could influence the unlock path,
multiple clients would retain decrypted state, and service behavior would depend on client
lifetime. A noninteractive MCP process has no acceptable human prompt.

### D. Headless secret transport — evaluated, not selected

Unattended restart readiness does not require an agent- or process-selected secret transport.
v0.1 supports restart readiness for an already initialized verified OS-keyring vault and for a
passphrase vault whose exact bundle-scoped auto-unlock entry was provisioned by trusted setup or
repair. A pristine headless install cannot auto-select keyring mode or create passphrase
auto-unlock without verified local setup authority.

**Amendment (ADR-015/016, 2026-07-31):** elevated vault initialization and provider credential
set/rotate require action-bound OS user presence before `finishup consent review` may use
`TrustedForegroundConsole`. The current runtime has no production presence adapter and returns
`human_authority_unavailable` before pending claim. Vault initialization generates
the high-entropy passphrase inside the helper and round-trips it through the scoped credential
store before direct confidential submission. Provider secret entry occurs inside the same trusted
console ceremony. No agent-visible channel or general headless API carries approval authority or
secret bytes. This still does not unlock an already-locked vault unless the separately scoped
auto-unlock entry already exists.

### E. Native vault subprocess — stronger remaining option, not selected for v0.1

A small memory-safe native subprocess could own keys and perform cryptographic or credential
authorization operations over a narrow RPC, reducing accidental copies in the Python service. It
would not protect against the compromised active UID/root/live-memory adversaries excluded by the
threat model, and it adds a second lifecycle, protocol, packaging, and crash-recovery boundary.
v0.1 uses the in-process service vault behind `SecretMemoryPort`; the port intentionally permits a
future native implementation without changing CLI/MCP/application contracts. Requiring the native
vault before first release is the one materially stronger containment choice still available.

## Security invariants

1. Only the ready service imports concrete storage, key, object, provider, and application
   composition modules.
2. Normal clients never receive or submit a key, passphrase, recovery secret, decrypted object
   handle, or policy-bypass capability.
3. Locked is an available service state, not a startup crash and not an empty-data mode.
4. The service never silently changes vault mode or falls back from keyring to passphrase.
5. Loosening privacy policy and unlocking the vault require trusted local-human surfaces; MCP,
   agents, and LLMs can only report that authorization is needed.
6. The local control transport is never TCP, network-reachable, project-relative, or selected by
   caller content.
7. A second service, stale generation, or unauthenticated peer cannot open a writer or decrypt a
   vault record.
8. First-install initialization and later unlock have distinct purposes. Existing mode,
   ciphertext, sentinel, keyring state, or ambiguous staging forbids initialization; no mode reset
   or key replacement is inferred.
9. Service generation is durable before locked endpoint publication and requires no catalog/key;
   corrupt or rolled-back generation metadata fails closed.
10. Pristine automatic keyring initialization mutates nothing unless the same installed artifact
    proves both the approved keyring cell and exact action-bound user-presence cell. Existing
    keyring vaults may unlock without current presence only into ready-local, externally fenced
    authority.
11. Idle relock can be disabled only through a YZH1 `idle_relock_policy_change` ceremony and a
    vault-minted proof for its exact current/proposed target; ordinary/MCP/config input cannot do
    so.

## Locking and reauthorization lifecycle

- Explicit `service lock` stops admission immediately, cancels noncommitting work, lets already
  admitted shielded database commits reach a definite bounded outcome, closes provider and
  decrypted-state handles, and returns to `locked`. MCP does not expose this method.
- An advertised platform session-lock or system-suspend event takes the same path. Wake or user
  session unlock never itself flips the service to `ready`. After those soft locks (and idle
  relock), the service may re-apply the scoped auto-unlock or OS-keyring load on the next ordinary
  control admission, or the human may run the unlock ceremony; explicit lock still requires the
  human/keyring ceremony.
- Idle relock is enabled by default only when there are no connected clients, in-flight requests,
  queued commits, leases, provider calls, or harness observation rows resolved by the ready sweep
  for the complete configured interval. It never counts a long-running operation as idle, and a
  workspace whose harness hooks keep delivering observation rows is not idle: a resolved row is a
  same-user authenticated write of the same trust class as an admitted control call, and each row
  resets the clock at most once (retrying rows never count, so a wedged row cannot hold the vault
  unlocked). The default is 3600 seconds. The only v0.1 mutation path is a
  foreground YZH1 `idle_relock_policy_change` preview over the exact current/proposed value,
  followed by action-bound OS user presence or the distinct passphrase-mode
  `security_reauthentication` purpose. It may select 60..86400 seconds or explicit `disabled`;
  server-side `edit` does not exist. The service consumes the exact vault-minted proof atomically
  with the change. The exception lasts only for the current service generation, is never persisted,
  and restart restores 3600 seconds. Disabling idle relock never disables explicit, session-lock,
  suspend, or monitor-loss relock.
- Privacy-policy loosening is not authorized by a boolean CLI flag or ordinary control request.
  It requires a fresh OS user-presence assertion or a confidential vault reauthentication proof
  bound to the exact proposed policy digest and expiry. MCP/LLMs may request more context but
  cannot mint or relay that proof.
- If the service is absent, normal CLI reports `service_unavailable` and MCP returns a sanitized
  structured unavailability result; neither starts a hidden runtime. If it is soft-locked and
  scoped auto-unlock (or keyring load) succeeds, ordinary methods proceed without a human prompt.
  If it remains hard-locked, both report `vault_locked` and direct the local human to the separate
  unlock surface without accepting a secret.

## Consequences

Persistent local service, control protocol, client library, vault state machine, unlock helper,
and their crash/secret-boundary tests move into v0.1. Native launchd/systemd-user convenience and a
generic passphrase transport remain separate future decisions; neither may be approximated by
client-side direct access or a secret in argv/env/config/stdin. The reviewed bundle-scoped platform
auto-unlock exception above is the only passphrase path that may open the vault without a human
ceremony (restart, soft-lock re-ready, and the trusted helper's silent `service unlock`).
The v0.1 helper also owns the explicit first-install passphrase initialization ceremony: two local
no-echo entries, one transmitted `vault_initialize` secret, atomic vault commit, and fail-closed
crash recovery.
Automatic pristine keyring initialization is therefore an artifact-gated convenience, not a
keyring-only default. Any future admin secret, additional platform presence adapter, or migration
that changes the resolved F-010 authority model requires an explicit ADR amendment.
**Amendment (2026-10-14, issue #1073):** the packaged service on macOS now composes one
`UserPresencePort` adapter, Apple LocalAuthentication through the fixed `/usr/bin/osascript`
helper, and passes the same instance to `HumanControlService` and `VaultService`. It is scoped to
the `owner_receipt_view` reauthentication (ADR-009 round 5, ADR-016 decision 4 amendment). It does
not change the resolved F-010 authority: the vault remains the sole minter of
`HumanAuthorizationProof` and accepts only an attestation that adapter issued for the exact
challenge, keyring retry receives no capability, and pristine keyring initialization still needs
a qualified `user_presence_cells` row, which the adapter's `unqualified` release cell never
matches.

## External evaluator process amendment (2026-08-30, issue #404)

The ready service may launch an exact network-capable evaluator only as part of an already-admitted
privacy-gateway dispatch. For the Codex subscription cell, the digest-bound Codex app-server is a
small trusted-local-computing-base component for protocol transport, OAuth custody, and process
isolation; its model output and provider remain untrusted content. This authority does not extend to
CLI, MCP, TUI, repository, or agent processes.

Each dispatch gets one fresh session/process group and an empty owner-private working directory
under the dedicated evaluator home. The service supplies a scrubbed allowlist environment, exact
argv, strict configuration and deny overrides; it passes no vault handle, API key, proxy,
repository path, inherited session, or agent context. It accepts no child request for a tool or
user action. Timeout or failure interrupts the exact turn when possible, terminates only the group
it spawned, escalates to a group kill when necessary, and verifies group disappearance. A valid
answer without verified cleanup is not success.

Login/status/logout are separate content-free structural operations. Codex owns its dedicated
home's credential file. FinishUP may create the exact nonsecret config and retain the home path, but
must not read, parse, hash, copy, export, log, or place credential bytes in the vault. Rollback
removes only the FinishUP binding; disconnect first requires Codex to confirm logout and otherwise
fails honestly.

## Owner-only file custody where no platform store is usable (2026-10-19, issue #1119)

**Owner decision (2026-10-19).** First-run setup must not ask a non-technical user to invent a vault
passphrase. On machines without a usable platform credential store (WSL 2, headless Linux, a
container), the generated auto-unlock passphrase is therefore kept in owner-only files instead.
This replaces the earlier rule that no file fallback exists. The owner chose this knowing it
weakens the at-rest boundary on those machines.

- **Custody.** `AutoUnlockPassphraseStore` keeps its entries, slots and every staging, promotion
  and proof-based recovery rule. Only the backend changes: `OwnerOnlyFileCredentialStore`
  (`finishup.adapters.keys.owner_file_store`) stores each slot as one file named by its digest
  account under `<bundle>/auto-unlock/` (directory `0700`, files `0600`).
  - Every operation opens the custody directory once (`O_NOFOLLOW`), verifies that descriptor
    (directory, euid-owned, `0700`), and resolves entry names against it, so a swapped path
    component cannot redirect a read or write.
  - Reads refuse anything that is not a regular, euid-owned, owner-only, single-link file.
    Symlinks are refused (`O_NOFOLLOW`).
  - Writes are atomic and complete: an exclusive temp file receives every byte, is fsynced,
    renamed into place, and the directory is fsynced.
  - Only the custody directory is created, and only inside an existing bundle root.
  - Entry names are store-chosen digests; no user-controlled text reaches a path.
- **Selection.** Existing file entries win, so an installation keeps its custody when a platform
  store appears later. Otherwise an allowlisted platform store is used, including the first one
  inside keyring's chainer wrapper. The file is used only when neither applies.
  `service auto-unlock status` and `auto-unlock enable|repair` report
  `custody: platform_store | owner_file`; setup and the terminal interface name the custody they
  actually used, and the agent-chat `vault_initialize` and `vault_passphrase_rotate` danger texts
  state both custodies and the same-user trade-off.
- **Recovery snapshots never carry it.** ADR-024 self-contained snapshots skip
  `<bundle>/auto-unlock/` (and the empty `auto-unlock-init.lock`) instead of refusing the bundle,
  so recovery provisioning keeps working and an exported recovery set never holds the
  passphrase beside the envelope it opens.
- **What it protects.** The file custody protects the vault against other accounts on the
  machine. It does **not** protect against software running as the same user, which can read the
  file. On those machines the vault's at-rest protection is equivalent to the account's file
  permissions. A backup or copy of the state folder includes the key. User docs say this plainly.
- **Choice and reverse path.**
  - `finishup setup vault --passphrase` creates a new vault from a passphrase the owner types,
    and keeps no copy of it.
  - For an existing vault, `service rotate-passphrase` changes the passphrase but still keeps the
    new value in the current custody. The atomic delete-plus-rewrap `disable` ceremony this ADR
    already requires stays unimplemented; a follow-up under issue #1119 owns it.
- **Unchanged.**
  - The vault-root key never uses this backend; `os_keyring` mode still requires an approved
    platform store.
  - Secrets still never travel through argv, environment, config, stdin, logs, ordinary control
    or MCP.
  - A pre-existing entry still blocks initialization rather than being adopted.
  - The agent-chat `vault_initialize` lane (ADR-015) now succeeds on these machines through the
    same helper-generated secret.
