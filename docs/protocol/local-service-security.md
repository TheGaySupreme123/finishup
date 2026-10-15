# Local service, vault, and confidential-input security

This page explains what the persistent local FinishUP service protects, what its `locked`/`ready`
states mean, which clients are untrusted surfaces, how a human unlocks it safely, and the limits of
same-UID and process-memory protection. It is written to be understandable without any private
architecture document.

## The binding promise

**One local service owns writers, keys, credentials, and decrypted state. Ordinary clients never
do.** CLI, MCP, and a future UI are communication surfaces to that one persistent, per-user service
— they never open the encrypted catalog or a task bundle directly, never hold a key handle, and
never unlock the vault themselves.

## Trust boundary

| Component | Trust and authority |
|---|---|
| Per-user local FinishUP service | Trusted local authority. Sole owner of vault keys, decrypted state, catalog/task writers, the provider gateway, and the application facade. |
| Confidential human helper (`service unlock`, `service initialize-passphrase`, `service recovery`) | Narrowly trusted for one exact ceremony and, when required, delivery of one one-shot secret. It has no workflow, storage, provider-dispatch, or policy authority. |
| CLI, MCP bridge, future ordinary UI | Untrusted control/rendering clients. They submit validated requests and receive bounded results; they cannot open storage, access key handles, unlock the vault, or weaken policy. |
| Agent, LLM, plugin, repository, imported transcript, provider | Untrusted content or external execution. Never receives an unlock secret or vault capability. |

## Service states

The service starts in `starting`, binds and authenticates its local control endpoint, attempts an
OS-keyring unlock, and enters either `ready` or `locked`.

- **`ready`** admits workflow operations, maintenance, imports, payload access, and egress.
- **`locked`** is a normal, reachable service state — not a crash and not an empty-data mode. A
  locked service reports only bounded structural status and reason codes; it never treats locked or
  missing data as empty, and it never creates a replacement key over existing encrypted data.

## Endpoints and clients

The service exposes three fixed, owner-only, same-UID Unix-domain endpoints beneath the per-user
runtime directory: ordinary control (workflow/support requests and structural status; carries no
unlock method and its schemas cannot carry secret bytes), a one-secret confidential ingress (accepts
only one-shot material for an already-live ceremony; never creates a challenge itself), and a
multi-phase human-control channel (the sole creator of challenges/previews/bindings — zero-secret
keyring retry, provider-credential set/rotate, typed privacy decisions, and the idle-relock-policy
ceremony all go through it). Ordinary MCP and control schemas expose no connector to either
confidential channel. **This is not a claim that arbitrary malicious code already running as the
same user cannot emulate a raw client of these sockets** — that is an explicit limit of the
same-UID threat model, stated plainly here rather than implied away.

## First-install: keyring versus passphrase

Automatic OS-keyring initialization is a two-capability gate, not a keyring-only default. On a
pristine installation, the service creates no staging artifact, key, keyring entry, or mode marker
unless **both** of the following hold for the exact installed release cell: a usable, verified
keyring create-if-absent/round-trip capability, **and** an artifact-verified, action-bound
`UserPresencePort` capability whose authenticated-prompt, trusted-action-binding,
one-use-attestation, and available states are all active. A platform-name guess, a TTY
acknowledgment, or a caller-supplied boolean is never accepted as that evidence.

If keyring storage works but the presence capability is absent, unavailable, inconclusive, stale,
or mismatched, the service performs no keyring or vault mutation and remains `uninitialized/locked`
with the bounded reason `human_authority_unavailable` (shown to the user as "setup required"). If
the keyring itself is unavailable or unusable, the service likewise remains `uninitialized/locked`,
with its own bounded keyring reason. **Neither branch silently falls back to the other.**

A local human may instead explicitly run `service initialize-passphrase`. The helper confirms the
new passphrase twice locally but transmits exactly one one-shot `vault_initialize` secret to the
service. The trusted prompt states the 16–1024 UTF-8 byte, no-control-character contract and
shows `*` mask feedback while raw echo remains disabled. Backspace removes a mask marker; this
reveals entered length to the local terminal but not content. It re-prompts after invalid input or
a confirmation mismatch, overwriting every rejected buffer before
the next attempt. The service accepts the secret only after re-proving that no installation
identity, catalog, mode, ciphertext, sentinel, or ambiguous staging state already exists. A
committed passphrase-backed vault never probes or falls back to the keyring at startup; foreign or
stale keyring entries are ignored, not deleted. Later unlock of an existing passphrase vault uses
the distinct `vault_unlock` purpose.
An allowlisted first-party agent acting on an explicit current-chat instruction may instead prepare
and authorize `vault_initialize`. That path carries only the bounded attestation: FinishUP generates
the high-entropy passphrase locally, verifies its scoped credential-store round trip, submits a
mutable copy through confidential ingress, wipes process buffers, and returns structural state.
No secret or caller-selected randomness crosses chat, MCP, argv, environment, config, or logs.

A ready passphrase vault can be changed with `service rotate-passphrase`: the current passphrase
reauthenticates the exact action, and the replacement is masked, confirmed, validated, and staged
in the scoped credential store before the service atomically rewraps the unchanged IVK. An
allowlisted agent with an exact prepared `vault_passphrase_rotate` authorization can request the
same transition without receiving either secret; FinishUP loads the current value and generates the
staged replacement locally. After success it promotes the stage. After an ambiguous interruption,
startup tries active and staged and keeps only the candidate that authenticates the envelope.
**Initialization is never available as a reset or recovery path for an existing vault** — an
existing-vault user experiencing a missing keyring entry, a wrong passphrase, or a tamper failure
is never told to run initialization; that failure routes to
[`../runbooks/key-recovery.md`](../runbooks/key-recovery.md) instead.

When a ready vault previously provisioned ADR-024 installation recovery, loss of every ordinary
unlock path routes to `finishup service recovery status` and then its exact reported import/restore
command, not initialization. Recovery authenticates the
external set and human-held secret, restores the same IVK authority into a generated quarantined
clean-profile target (or leaves the original encrypted vault byte-for-byte in place), stages a new
envelope, proves catalog/vault/object/replay access, and switches only after close/reopen succeeds.
Without valid provisioned material, FinishUP cannot recover the installation.
MCP can never unlock the service. Agents can report bounded state and the exact trusted local
command only; recovery artifacts, paths, and secrets remain outside agent-visible channels.

The installed Cryptography Argon2id implementation is required before a passphrase-vault service
can start. If that exact packaged KDF module is unavailable, `finishup service run` fails closed before
opening retained state, with `passphrase_kdf_unavailable` and the remedy to reinstall FinishUP. It does
not substitute another KDF, initialize a replacement vault, or remove retained data.

### Existing-keyring vaults are a distinct case

An already-committed keyring-backed vault created by an earlier release, or restored through a
reviewed migration, remains readable: it may become `ready` for locally permitted work **without**
current presence evidence, so a user's existing data stays usable across ordinary restarts and
platform sessions. This is explicitly narrower than creating new keyring mode — it is
**ready-local only**: external activation, provider-credential set/rotate, privacy-policy widening,
and other durable authority changes remain fenced until presence is freshly validated. No TTY click
or same-UID identity substitutes for that missing capability.

## Idle, session, suspend, and explicit relock

The service relocks on an explicit `service lock`, an advertised platform session-lock or
system-suspend event, and on idle timeout. The default idle-relock interval is 3600 seconds and
applies only when there are no connected clients, in-flight requests, queued commits, leases,
provider calls, or harness observation rows resolved by the ready sweep for the complete
interval — a long-running operation is never counted as idle, and neither is a workspace whose
harness hooks keep delivering observation rows. A resolved row is a same-user authenticated write
of the same trust class as an admitted control call; each row resets the clock at most once, and
retrying rows never count, so a wedged row cannot hold the vault unlocked. Wake
or session unlock never itself changes the service back to `ready`. After idle, session-lock, or
suspend soft locks, the trusted service may re-apply the same scoped platform
auto-unlock entry (passphrase mode) or OS-keyring load that restart uses, on the next ordinary
control admission. Explicit `service lock`, monitor loss, and hard unlock failures still require
the human/keyring ceremony (`finishup service unlock`), which prefers the scoped platform entry when
provisioned. Monitor loss is excluded because the capability that produces session-lock and
suspend events is gone for the life of that process: re-readying automatically would leave the
service running with session-lock relock silently no longer applying.

The **only** way to change the idle interval (to 60–86400 seconds) or disable it entirely is an
exact, foreground `idle_relock_policy_change` ceremony over the human-control channel, followed by
either a fresh OS user-presence assertion or, in passphrase mode, the distinct
`security_reauthentication` purpose. No ordinary command, configuration value, or MCP call can
weaken this. The resulting exception applies only to the current service generation — restart
always restores the 3600-second default — and disabling idle relock never disables explicit,
session-lock, suspend, or monitor-loss relock.

The owner's full receipt (`local_human_view`) uses the same channel: `finishup receipt --owner-view`
opens an `owner_receipt_view` ceremony bound to that one receipt request and to the command's own
control connection, which completes only with a fresh OS user-presence assertion or, in
passphrase mode, the `privacy_reauthentication` purpose. The service obtains the presence itself:
on macOS it raises an Apple LocalAuthentication dialog (Touch ID or the device password) through
the fixed `/usr/bin/osascript` helper, and only that helper's exact approval for the bound
challenge counts; Linux and WSL 2 have no presence provider. The service names each admitted control
connection itself, refuses a connection whose hello nonce is live or was used before, holds one
in-memory grant for 60 seconds under that admitted connection, consumes it only on the matching
receipt call on that connection, and revokes it when the connection closes. A terminal, a
pseudo-terminal, a client kind or a hello presentation field never substitutes for it.

## Forbidden secret surfaces

An installation vault key, bundle master key, derived key, per-object key, vault-unlock passphrase,
or portable-recovery secret never leaves the trusted local boundary and never appears in: an MCP
tool argument or result, an agent message or LLM prompt/context, a normal CLI argument, process
title, environment variable, configuration file, stdin pipeline, shell history, an ordinary control
request, a provider content body, an application event, a SQLite structural row, a receipt, a log,
a trace, an exception, a crash report, a support bundle, or a temporary plaintext file. The
confidential helper opens `/dev/tty` itself, verifies the foreground controlling terminal, enables
no-echo input, and fails closed if any part of that ceremony is unavailable — it never falls back
through `stdin`, an environment variable, a configuration value, or a piped/redirected/noninteractive
invocation.

External provider credentials follow the same rule with one narrow, separately bound exception: for
an already-authorized physical attempt, a fresh one-shot transport callback — bound to the exact
endpoint, profile, final request-body digest, and deadline — injects the authentication header
directly into that one HTTPS request to the exact profile-bound endpoint, using platform CA trust
and hostname validation. v0.1 makes no certificate or SPKI-pinning claim. No SDK client or
default-header object ever retains the real credential.

An agent may initiate only a zero-secret recovery handoff. It receives a closed recovery state, an
opaque retry identity, expiry, and the exact trusted local command. An allowlisted candidate may
open a native action-bound prompt; otherwise the human runs the command in a trusted terminal. The
agent never receives the set path, artifact bytes, secret, prompt input, keyring identity, or
decrypted result, and it retries only the original suspended operation after terminal completion.

## Limits of same-UID and process-memory protection

Peer-UID authentication (`SO_PEERCRED` on Linux, `getpeereid` on macOS) and owner-only filesystem
permissions block *other local users* from reaching the service's endpoints. **They cannot
distinguish a malicious process already running as the same account.** A compromised active user
account, a root process, or inspection of the ready service's own memory are outside this threat
model entirely — encryption at rest protects against a stolen disk, another local user, or
accidental sharing of a data directory, not against those adversaries. Secret buffers use
best-effort page-locking and overwrite where the platform supports it; CPython and provider
libraries can still make uncontrollable copies, so no perfect zero-copy or guaranteed zeroization
claim is made.

## Headless and native-vault status

There is no passphrase-based headless unlock in v0.1 — no inherited file descriptor, no
`--password-fd` shortcut, and no environment-variable secret path. An already-initialized,
verified OS-keyring vault may unlock noninteractively; a pristine headless installation cannot
auto-select keyring mode without the exact verified presence cell described above, and a
passphrase-locked headless service simply remains locked. Native `launchd`/`systemd-user`
installation and autostart integration are deferred; an external per-user supervisor may run the
documented foreground `finishup service run` entrypoint without ever receiving a secret, and a
service-manager reporting "started" is never itself evidence that the vault is `ready`. The service
vault runs in-process behind a swappable secret-memory abstraction in v0.1; it does not claim a
native, memory-safe subprocess boundary.

## Diagnostics never capture raw content

Ordinary exception handling retains only a bounded structural correlation ID and reason/outcome
code. v0.1 does not capture a raw traceback, exception message, local variable, or source/path
excerpt in plaintext or encrypted form, even to an owner-only file. A future encrypted diagnostic
artifact would require its own reviewed schema, explicit privacy authorization, and retention
policy — it is not a logging or support-bundle mode that exists today.

## Troubleshooting

| Symptom | Bounded reason | What it means | What it does not mean |
|---|---|---|---|
| Fresh install stays locked with setup required | `human_authority_unavailable` | Keyring works but presence evidence is missing/stale/unavailable | Not keyring corruption; not a bug |
| Existing vault reachable without presence prompt | (no error — `ready`, activation fenced) | Existing keyring data may load for local work | Not full external authority |
| Vault locked after restart | (expected) | No valid scoped auto-unlock entry was available; keyring mode loads at restart when usable | MCP cannot unlock it for you |
| Idle-relocked mid-session | (expected) | Default 3600s idle timer elapsed with no active work — no control calls and no observation rows resolved; next ordinary call re-applies scoped auto-unlock when provisioned | Not a crash; not a permanent lock when auto-unlock is healthy |
| Hard-locked after soft lock | `passphrase_required` / `auto_unlock_*` / `keyring_locked` / `explicit_lock` | Auto-unlock missing, stale, keyring load refused, or human locked the service | Run `finishup service unlock` or `finishup service auto-unlock repair` on a local terminal |
| Every ordinary unlock path lost, recovery was provisioned | `recovery_material_required` | The same encrypted installation may be recovered through ADR-024 | Run `finishup service recovery status` locally and follow its reported next command; an agent may only hand off this command/prompt |
| Every ordinary unlock path lost, no recovery generation exists | `permanently_unrecoverable` | FinishUP has no key path for the old encrypted installation | Preserve the old state; create only a clearly separate history |
| Locked after losing the session monitor | `monitor_lost` | The session-event source became unavailable, so session-lock relock can no longer apply to this process | Run `finishup service unlock` on a local terminal; `session_monitor` stays `lost` in status until restart |

Troubleshooting always uses these bounded reason codes — never a raw file path, account name, or
internal exception string.

## What this page must never imply

Locked or missing data is never "deleted" or "empty." The OS keyring is never described as an
automatic fallback for a passphrase vault, or vice versa. MCP can never unlock or recover the service. A
boolean flag or TTY acknowledgment never proves human presence. A service manager reporting the
process as running never means the vault is `ready`. Encryption is never described as protecting
against a compromised active account, root, or live-memory adversary. Idle relock is never
described as changeable through an ordinary command, config value, or MCP call, and a disabled idle
deadline never means session-lock or suspend relock is also disabled.

## See also

- [`docs/adr/ADR-001-writer-topology.md`](../adr/ADR-001-writer-topology.md) — persistent-service
  and single-writer lifecycle decision.
- [`docs/adr/ADR-004-threat-crypto-key-recovery.md`](../adr/ADR-004-threat-crypto-key-recovery.md)
  — the threat model and key hierarchy.
- [`docs/adr/ADR-008-local-service-vault-trust-boundary.md`](../adr/ADR-008-local-service-vault-trust-boundary.md)
  — the full trust-boundary decision.
- [`data-egress-and-privacy.md`](data-egress-and-privacy.md) — what the unlocked service is and is
  not allowed to disclose.
- [`../runbooks/key-recovery.md`](../runbooks/key-recovery.md) — locked/missing/portable key
  recovery procedures.
- [`../../SECURITY.md`](../../SECURITY.md) — how to report a vulnerability in this boundary.

## Claims and evidence

Every promise on this page maps to an ADR, an owning spec, and an executable test in
`docs/public-claims.json`; a statement here is never stronger than that mapped evidence. This page
itself is checked by `tests/conformance/claims/test_local_service_security_doc.py` and by the
private-boundary secret scan in `tests/packaging/test_private_boundary_and_secret_scan.py`. No
private architecture document, sample secret, or internal-only reference appears above.
