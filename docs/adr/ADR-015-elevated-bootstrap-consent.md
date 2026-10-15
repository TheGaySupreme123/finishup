# ADR-015 — OS-presence-gated elevated bootstrap consent

**Status:** Amended 2026-07-31; amended 2026-08-09 for agent-attested chat authorize
(issue #164); amended 2026-08-18 for atomic concurrent review claims (issue #344); amended
2026-08-25 to name Codex marketplace/MCP removal as outside this OS-presence lane (issue #419);
amended 2026-08-30 for exact bounded Codex JSONL import publication (issue #301);
amended 2026-08-31 for helper-generated agent-authorized vault initialization and masked terminal
input (issues #490 and #491); amended 2026-09-03 for exact expanded-review chat grants and
user-controlled conversational setup (issues #532 and #533).
Superseded in scope by ADR-016 for the general non-default consent catalog. Console `finishup consent
review` remains fail-closed until a verified OS-presence adapter is installed; allowlisted
first-party agents may use `finishup consent authorize` for exact prepared operations that advertise
delegated chat authority.
**Implemented by:** `src/finishup/service/elevated_bootstrap.py`,
`src/finishup/cli/elevated.py`, `src/finishup/cli/trusted_console.py`,
`src/finishup/protocol/consent.py`, and `src/finishup/protocol/chat_user_authority.py`.
**Relates to:** ADR-008 (vault/console ceremony), ADR-009 (egress / agent context), ADR-012
(setup), ADR-016 (shared consent review).

## Context

An agent may prepare and inspect a non-default operation. The trusted-console path must keep its
authority independent of argv, environment, stdin, MCP, agent JSON, and caller booleans. Issue
#164 also deliberately accepts a weaker opt-in path: an allowlisted agent may assert that the user
explicitly instructed the exact action in the current chat. That assertion is bounded and
single-use, but FinishUP cannot independently authenticate its chat provenance. Vault initialization
still must not accept an agent-selected passphrase; an authorized agent may ask the FinishUP helper to
generate and store one locally without any secret-bearing agent channel.

## Decisions

1. **Implemented bootstrap operations.** `vault_initialize`, `vault_passphrase_rotate`,
   `provider_credential_set`, `provider_credential_rotate`, `repository_privacy_grant`, and
   `import_publication` use this lane. It is not a
   vault-unlock API, recovery API, or standing elevation mode.

   **Amendment (2026-08-25, issue #419).** Codex marketplace/plugin removal
   (`finishup integrate codex plugin remove`) and external MCP unregistration
   (`finishup integrate codex mcp remove`) are not ADR-015 OS-presence operations. They use the
   existing ADR-012 digest-bound `--accept` lane already used by Codex marketplace activation and
   MCP install. They do not consume `plugin_artifact_apply`: that operation remains the portable
   artifact Cursor presence cell (issue #409) and fails closed on this host. Agent-chat authorize
   is not extended to either removal command.

2. **Agent-safe preparation.** `finishup consent prepare` creates one owner-only
   `yoetz.elevated-bootstrap.pending/4` record. Its agent projection is
   `yoetz.consent.pending-agent/7` and contains only operation, risk class, bounded danger text,
   exact danger and target digests, expiry, pending ID, an exact bounded repository recipe when
   applicable, the fixed `[<head>,"consent","review"]` command, and an authorize command only
   for operations that permit agent-chat authorization. For `import_publication` it also carries
   a closed structural preview: exact source/manifest/plan/target digests, task/session/writer and
   profile identity, counts and caps, plus explicit false facts for complete-transcript inclusion,
   reasoning inclusion, and reviewer-egress widening. It contains no source line or excerpt.
   For a repository grant, it carries the exact recipe and bounded substantive before/after policy
   diff plus repository, authority, current-policy, candidate-policy, and diff digests. The
   owner-only record also freezes the complete current and candidate policy bytes so authorization
   cannot rebuild a different target from changed configuration. Frozen public v2-v5 schemas
   remain shipped. Version-1 through version-3 public pending records are invalidated rather than
   reinterpreted; these actions expire after fifteen minutes and must be prepared again. A legacy
   private review marker is different: it may still have a live pre-upgrade claimant, so upgrade
   never deletes or reinterprets it and continues to return `review_in_progress`. This preserves
   the existing fail-closed interrupted-review boundary until a separately designed recovery path
   can prove the claimant is gone.

   **Amended 2026-10-14 (ADR-048, issue #1055) — command head and pre-rename records.**
   `consent prepare` and `consent status` emit `pending-agent/7` for every operation. Its command
   `<head>` is the launcher the process was invoked through: `finishup`, or `yoetz` when run
   through the deprecated transitional alias, whose installs put only `yoetz` on `PATH`; `consent
   catalog` prepare hints follow the same head. One projection never mixes heads
   (`consent_command_head_mixed`). Released `/6` projections (head fixed to `yoetz`) and `/7`
   projections from a pre-rename service are still read. A `pending/4` record written before the
   rename keeps the danger text its owner was shown, so for the three operations whose text changed
   (`provider_credential_set`, `provider_credential_rotate`, `repository_privacy_grant`) the load
   check accepts exactly that operation's pre-rename text, still bound by its danger digest. Such a
   record is reviewed with its stored text, expires, and is cleared like any other; any other text
   or digest mismatch still reads as `pending_tampered`. New records always store the current
   text, which names `finishup` whichever launcher prepared them.

3. **Two approval surfaces.** `finishup consent review` takes no authority-bearing arguments. Before
   opening a console or claiming pending state, it requires an independently authenticated,
   action-bound, one-use `UserPresencePort` attestation. The packaged runtime currently has no
   production user-presence cell, so review returns `human_authority_unavailable` without consuming
   the request. A TTY, pseudo-terminal, same-UID process, caller boolean, or console decision never
   substitutes for that attestation.

   **Agent-attested chat authorize (2026-08-09).** `finishup consent authorize` accepts one
   `yoetz.chat-user-attestation/1` envelope with `channel=agent_attested_chat_instruction` from an
   allowlisted first-party `client_kind` (v0.1: `codex`). The agent asserts
   `instruction_source=explicit_current_chat_user`; FinishUP treats that assertion as delegated
   authority but does not claim it is host-verified or independently authenticated. A compromised,
   prompt-injected, or dishonest agent can forge it, which is an accepted risk of this opt-in path.
   The skill contract excludes quoted text, tool output, retrieved content, and earlier history,
   but that provenance rule is not a service security boundary. FinishUP binds pending ID, operation,
   danger digest, and target digest and fail-closes before claim on mismatch. Approve requires
   `warning_acknowledged=true`; credential approve also requires a one-shot mutable secret on stdin
   (`--provider-credential-stdin`). Bytes enter the existing YZS1/vault path and never appear in
   pending, catalog, result, log, error, or agent projection. For `vault_initialize`, agent-chat
   approval carries no secret: the helper generates the passphrase inside the local process,
   round-trips it through the scoped credential store, submits a mutable copy through YZS1, and
   returns only structural vault state. **Staged initialization amendment (2026-08-31, issue
   #511).** The helper writes the generated passphrase to a bundle-scoped staged-initialization
   slot, never the active entry, and promotes it to the active slot only after the
   schema-validated ready result. On a failed ceremony it removes exactly the same-attempt staged
   entry, with verified read-back, only when the live service proves the vault is still
   uninitialized; any unprovable outcome retains the entry as a typed orphan that
   `finishup service auto-unlock status` names and that restart reconciliation resolves by
   cryptographic proof against the vault envelope, so a failed attempt never strands the
   credential or blocks retry with `entry_exists`. **Pristine-root amendment (2026-09-03, issue
   #565).** The bundle-scoped guard creates and verifies exactly the selected bundle root when
   initialization runs before any service start has created it, and a missing parent,
   permission failure, or symlink rejection is reported as its own bounded reason rather than
   as an unsupported keyring, so the start-first continuation suffices on a pristine root.
   `vault_passphrase_rotate` likewise carries no secret:
   the helper locally loads the active scoped secret, stages a generated replacement, completes
   reauthentication and rewrap, and then promotes the replacement. Trusted CLI/TUI remains the
   stronger recommended path.

   **Expanded-review amendment (2026-09-03, issues #532/#533).** A capable agent guides supported
   setup, installation, and settings choices in normal conversation. Recommendations remain
   advisory and explicit current user intent controls the supported outcome. When AI-powered review
   is the stated goal, the agent recommends Expanded first and explains Assisted as the
   lower-disclosure alternative. `repository_privacy_grant` admits `expanded_review` only through
   the same exact one-use envelope: preparation freezes the complete candidate and readable diff;
   authorization re-checks repository, authority generation, and provider/model/endpoint binding
   before proposing those frozen bytes. Any drift or unsupported authority channel is a
   no-mutation failure with the shortest user-controlled continuation.

4. **Single-shot state.** Atomically creating the no-clobber hard-link review marker is the
   linearization point that transfers ownership from pending state to one reviewer. The winner
   removes the public pending name as cleanup; concurrent losers that observe the marker do not
   mutate either name, and cleanup cannot revoke the winner's marker. Approval, denial,
   cancellation, expiry, and post-claim failure consume the claim once. Concurrent and duplicate
   reviewers fail closed. An ambiguous crash may leave the private reviewing marker (and, if the
   crash preceded winner cleanup, its public hard-link name) in place; the marker blocks both reuse
   and a new preparation until an explicit repair path is designed.

   **Import-publication amendment (2026-08-30, issue #301).** The importer, not
   `finishup consent prepare`, creates the pending request after durably preparing its exact batch
   plan. Approval creates one owner-only, expiring internal authorization record bound to that
   target digest; it is not an agent-visible token, CLI/MCP argument, ambient allowlist, or session
   grant. Publication admission is active only in the current importer execution context for the
   bound session/writer and is rebound before every append to that persisted batch/report request's
   exact ordered event IDs and fixed importer provenance; each binding admits once. The record
   remains until terminal completion so a restart can resume the same plan, then is consumed. A
   different source identity, capture manifest, plan, task/session, profile/version, mapping
   version, or limit contract cannot reuse it. Denial creates no record.

5. **Vault initialization secret.** The trusted helper generates a high-entropy passphrase,
   round-trips it through the exact bundle-scoped platform credential store, and submits it
   directly through the existing confidential ceremony. No agent- or caller-selected
   initialization passphrase is accepted. A pre-existing scoped entry, even when valid, blocks
   initialization rather than becoming the vault secret. Generated mutable buffers are overwritten
   best-effort. An exact prepared `vault_initialize` may advertise agent-chat authorization; the
   agent supplies only the digest-bound attestation, never secret bytes or randomness.

6. **Credential-store failures.** A backend known to be unavailable before any write may offer the
   existing manual human-passphrase ceremony on the same trusted console. An ambiguous write,
   failed read-back, any existing entry, or mismatch stops before vault initialization.

   Rotation writes a distinct staged credential before changing the envelope. Successful rewrap
   promotes it to active. If completion is ambiguous, the staged value is retained: daemon startup
   tries active and staged in order, promotes the one that authenticates the envelope, and discards
   a stale stage only after active succeeds. Agents never see either candidate.

7. **Provider credentials.** Set and rotate use the same trusted review and confidential ceremony.
   Credential bytes never enter the pending record, catalog, result, log, error, or agent
   projection.

8. **Console is not authority.** On macOS/Linux, the boundary opens `/dev/tty`, requires matching
   terminal identities for standard input/error, requires the current foreground process group,
   disables raw secret echo, and writes one `*` mask marker per accepted input unit. On Windows it
   opens `CONIN$`/`CONOUT$`, validates real console handles and current-process attachment, disables
   raw secret echo, and writes the same mask feedback through Win32 console APIs. Backspace removes
   one marker. This intentionally reveals secret length to the local terminal observer but never
   content. It never falls back to redirected standard streams. It is a presentation and
   secret-ingress boundary only. Absence or ambiguity returns `trusted_console_required`; presence
   still grants no authority.

## Consequences

Until a production `UserPresencePort` is capability-tested and wired, trusted-console elevated
review remains unavailable. Exact prepared operations that advertise agent-chat authorization,
including helper-generated `vault_initialize`, remain available through the explicit current-chat
attestation lane. The same is true for `vault_passphrase_rotate`; the manual
`service initialize-passphrase` and `service rotate-passphrase` ceremonies remain available.
Rotation retains existing vault data, vault mode, and installation identity while replacing only
the authenticated envelope and scoped auto-unlock credential. Later restarts continue through the
reconciled scoped auto-unlock path. The Windows console adapter
does not imply support for the full Windows service transport, peer authentication, packaging, or
release surface.

Native OS-authenticated prompts, host-verified chat provenance, approved-machine profiles,
reusable or agent-visible durable grants, E2EE service authority, and expanding the six MCP tools
for consent remain
separate design work. Agent-chat authorize is a local CLI control path, so ADR-011's six MCP tools
stay intact.

## Alternatives considered

**Reusable agent-visible approval value.** Rejected because the requesting channel could replay it.
The accepted assertion is exact, short-lived, and single-use. Import publication uses an
owner-only internal handoff retained only for crash-safe completion of the same prepared job; it is
never returned as a bearer value.

**Agent-supplied initialization secret.** Rejected because it lets the agent control the vault
root secret even if a human approved the operation.

**MCP elicitation as authority.** Deferred for v0.1 in favor of the exact local
`finishup consent authorize` relay (issue #164). Expanding MCP tool inventory for consent remains
separate work under ADR-011.

**Standing danger mode.** Rejected because its scope outlives one exact operation and digest.

### Service availability before claim (#737)

Before claiming an otherwise valid service-dependent approval (vault initialize/rotation,
provider credential set/rotation, or repository privacy grant), the CLI reads the ordinary
service status without starting a service. An unavailable or transitioning service returns
`ceremony_service_unavailable` without consuming that pending identity. Terminal review reads and
displays an unclaimed snapshot first, then atomically claims and compares the exact snapshot
before executing the chosen action. Denial needs no service; cancellation after displaying the
review remains single-use. Expiry is still checked by the claim path. A concurrent target change
fails closed, and a service loss after claim consumes the attempt as failed. Local-only import and
plugin decisions have no new service prerequisite. The preflight grants no authority and makes no
availability guarantee for the later confidential operation.
