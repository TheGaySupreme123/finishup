# ADR-016 — Human review for non-default actions

**Status:** Working decision; amended 2026-07-31 to require action-bound OS user presence before
console review; amended 2026-08-09 for agent-attested current-chat authorize (issue #164); amended
2026-08-18 for atomic concurrent review claims (issue #344); amended 2026-08-21 to assign portable
plugin artifact and host-activation mutation to `review_only` (issue #149, ADR-023; implementation
owned by #150); amended 2026-08-25 to keep Codex marketplace/MCP removal on the ADR-012
digest-bound `--accept` lane rather than `plugin_artifact_apply` (issue #419); amended 2026-08-30
for exact bounded Codex JSONL import publication (issue #301).
Amended 2026-09-03 for user-controlled conversational setup and exact expanded-review grants
(issues #532 and #533). Amended 2026-10-14 for the first service-wide `UserPresencePort`
adapter, macOS LocalAuthentication scoped to the owner receipt view (issue #1073, PR #1069).
**Implemented by:** `src/yoetz/service/elevated_bootstrap.py`,
`src/yoetz/cli/elevated.py`, `src/yoetz/cli/trusted_console.py`,
`src/yoetz/protocol/consent.py`, `src/yoetz/protocol/chat_user_authority.py`, and
`guidance/agent-instructions.md`.
**Relates to:** ADR-015 (bootstrap path), ADR-008 (vault/console), ADR-009
(egress/privacy).

## Context

Yoetz needs one understandable rule for actions outside the ordinary cooperative workflow while
keeping the stronger trusted-console authority and secret entry boundaries clear. Human review is
per-operation and digest-bound; host sandboxing and egress policy remain separate containment
controls. The optional agent-chat lane deliberately delegates authority to an agent assertion and
documents that Yoetz cannot independently authenticate its chat provenance.

## Risk classes

| Class | Examples | Human UX | Secret path |
|---|---|---|---|
| `default_safe` | MCP `start`/`publish_work`/`check`/`respond`/`status`/`receipt`; privacy tighten | No consent ceremony | None |
| `secret_ingress` | vault initialize; provider credential set/rotate | Trusted console review, or agent-attested current-chat authorize for credential set/rotate only | Trusted confidential ceremony; chat authorize may supply one-shot credential after warning |
| `secret_reauth` | idle-relock weakening; some privacy widening | Trusted review plus owning reauthentication | Trusted confidential ceremony only |
| `review_only` | exact Codex JSONL import publication; backup/restore/migrate execute; skill or harness configuration | Trusted review or, for the exact prepared import only, agent-attested current-chat authorize | None |
| `privacy_widen` | repository privacy grant; privacy policy widen; disclosure approve | Trusted local privacy TUI, or agent-attested current-chat authorize for exact recipe grant | Owning ceremony when required |

## Decisions

1. **Catalog authority.** `yoetz consent catalog` and `status` list every non-default operation,
   risk class, prepare hint, binding requirements, and `implemented` flag. Operations marked
   `implemented=false` cannot be prepared.

2. **Agent-safe contracts.** Catalog, pending projection, prepare result, review result, and status
   publish current v6 contracts in `schemas/consent/`; the frozen v2-v5 bytes remain shipped for
   compatibility. They contain no reusable approval value, generated passphrase, or credential.
   The v5 pending projection added the closed, content-free `import_publication_preview`. V6 adds
   a closed `repository_privacy_preview` with the recipe, keyed repository commitment, authority,
   current-policy, candidate-policy and diff digests, plus every bounded substantive before/after
   change. The readable diff is the decision surface; its digest is integrity evidence, not a
   substitute for disclosure.
   The v4 durable pending shape invalidates legacy public pending files. It does not delete a
   legacy private review marker, because that marker may still be owned by a live pre-upgrade
   claimant; replacement remains fail-closed as `review_in_progress` under the existing
   interrupted-review limitation.

3. **One pending request.** One owner-only request with a 15-minute TTL may exist. The trusted
   reviewer atomically claims it by creating a no-clobber hard-link review marker. Marker creation
   is the ownership transition; only the winner cleans up the public pending name, while concurrent
   losers are read-only. Every terminal decision and every post-claim failure is single-shot.

4. **Verified presence before console review.** The fixed `yoetz consent review` command takes no
   authority-bearing arguments. An independently authenticated, action-bound, one-use
   `UserPresencePort` attestation must succeed before the helper opens a foreground console or
   claims pending state. The current runtime has no production adapter and therefore returns
   `human_authority_unavailable`. Redirected, headless, pseudo-terminal, and same-UID automation
   cannot authorize mutation.

   **Amendment (2026-10-14, issue #1073, owner decision).** The service-wide `UserPresencePort`
   gains its first production adapter, `MacOSLocalAuthenticationPresence`, and it serves exactly
   one reauthentication: the owner receipt view (`owner_receipt_view`, ADR-009 decision 3,
   round 5). The packaged service composes it on macOS only, with a `PresenceScope` naming that
   purpose; Linux, WSL 2 and every other platform compose none and keep their fail-closed
   continuation (`owner_view_unavailable`, or `owner_view_requires_terminal` with no foreground
   terminal). The presence is independent of the requesting terminal, as this decision requires:
   the service, not the client, starts Apple LocalAuthentication
   (`LAPolicyDeviceOwnerAuthentication`, reuse disabled) through the SIP-protected
   `/usr/bin/osascript` with a fixed program, and only that helper's exact `approved` token for
   the exact bound challenge becomes a one-use attestation the vault consumes. A client names
   the source it asks for and can assert nothing; a TTY, a pseudo-terminal or same-UID
   automation that cannot produce the owner's fingerprint or device password still cannot pass.
   Cancellation or failure is `presence_refused`, no answer within the 60-second dialog
   deadline is `presence_timeout`, and no dialog (not macOS, no LocalAuthentication, no desktop
   session, or any unreadable helper result) is `presence_unavailable`; none grants anything.
   Prompts that do not approve back off (5 seconds rising to 5 minutes,
   `reauthentication_rate_limited`; one cancelled within 2 seconds does not escalate but still
   delays the next by 5 seconds), and a ceremony opened while another is active is
   `ceremony_busy`, so an agent cannot make the owner's command read as a locked vault. The
   backoff lives in the service process and a restart clears it: it slows repeated dialogs, it
   does not cap them, and an agent that causes misses can delay the owner's own dialog by up to
   5 minutes (ADR-009 round 5 lists both lockouts and their ways out).
   This decision's console review is unchanged: `yoetz consent review` does not use this
   adapter and still returns `human_authority_unavailable`, and the adapter authorizes no vault,
   credential, privacy-policy, setup, keyring or plugin operation.

5. **Agent-attested current-chat authorize (issue #164).** When the user explicitly asks the agent
   in the current chat for help
   with an exact prepared setup action, `yoetz consent authorize` may complete
   `provider_credential_set`, `provider_credential_rotate`, `repository_privacy_grant`, or one
   importer-prepared `import_publication` under a
   `yoetz.chat-user-attestation/1` envelope. The envelope is an agent assertion, not independent
   proof; a compromised agent can forge it. Catalog rules expose that limitation directly through
   `agent_attestation_is_independent_proof=false` and
   `compromised_agent_can_forge_attestation=true`.

   **Expanded-review amendment (2026-09-03, issue #533).** The exact-recipe grant now admits
   `expanded_review`. Preparation freezes the complete current and candidate policy bytes and
   derives the same substantive diff used by the policy classifier. The target and danger digests
   bind those bytes, the provider/model/endpoint, repository commitment, authority generation,
   recipe, and expiry. Authorization uses only the frozen candidate and separately re-checks the
   live repository, authority snapshot, and configured provider binding. Drift, denial, expiry,
   replay, unsupported client, or malformed preview fails closed before policy/provider mutation.

6. **No standing danger mode.** There is no session-wide bypass or broad grant. Easy review means
   short bounded text and one console decision or exact agent assertion, not reduced target checks.

7. **Path safety is independent.** Consent cannot waive shared-temp, sync-folder, symlink,
   ownership, or broad-permission refusals.

8. **Secrets remain confined.** Implemented secret-ingress operations enter the existing YZH1/YZS1
   confidential service ceremony. Chat-user authorize may deliver one-shot provider credential bytes
   through stdin into that ceremony after warning acknowledgement; results stay presence-only.
   Agent-facing projections never echo secret bytes. Vault initialization secrets remain
   helper-generated and console-only.

9. **Separate schema-only package update path.** A compatible package update may run the
   service-owned `package_upgrade_migration` at the controlled READY boundary. It is limited to
   the registered schema-12-to-13 bundle transition, takes its machine-bound backup first, and
   carries no user-content, observation, consent, provider, disclosure, or egress authority. It
   is not a public `migrate_execute` approval and cannot consume, replace, or weaken that review
   contract. If the package path cannot prove the exact predecessor, backup, holder, migration,
   replay, or terminal result, it fails closed and directs the operator to the explicit recovery
   procedure.

   Explicit backup, restore, and ad-hoc `migrate execute` remain `review_only`: they require their
   own exact plan digest and trusted review. Skill mutation, harness registration, idle-relock
   weakening, and generic `privacy_policy_widen` remain catalogued but unimplemented until their
   owning mutation boundaries consume this single-shot review safely. `repository_privacy_grant`
   is the implemented exact-recipe privacy path for chat-user authorize.

   **Amendment (2026-08-30, issue #301).** `import_publication` is implemented as a one-use
   `review_only` operation. The first import call durably stores its encrypted source and exact
   publication plan, exposes only the bounded structural preview through consent status, releases
   its lease, and returns `PRIVACY_AUTHORITY_REQUIRED`. Approval creates no bearer token: an
   owner-only internal record binds the source identity, capture manifest, plan, target task and
   session, profile/version, mapping version, counts, and limits. Replaying the identical import
   resumes publication; target drift fails closed. The record survives restart until terminal
   completion and is then consumed. This is intake authority only and does not widen reviewer
   egress, add an MCP tool, or authorize another import.

   **Amendment (ADR-023, 2026-08-21, issue #149):** the skill/harness-configuration slice of
   `review_only` is the accepted owning boundary for standalone portable plugin artifact
   install/remove and host-activation apply. #150 must implement the operation-specific catalog,
   prepare, and consume path before any such mutation exists; this amendment does not mark the
   current generic skill/harness operations implemented. Once implemented, the path consumes this
   class's single-shot trusted review of the exact plan digest under all existing rules — one
   pending request, atomic claim, verified presence before console review. An ordinary TTY
   confirmation, `--accept`, a same-UID process, or a host marketplace prompt is not and cannot
   silently become `UserPresencePort` authority. Issue #409 adds one production path for the
   pinned macOS Cursor cell only: a fresh Apple LocalAuthentication
   `deviceOwnerAuthentication` prompt whose displayed reason names the exact operation, preview
   digest, and pending review. The pending is matched before the prompt and atomically consumed
   after successful authentication; cancellation, unavailable policy, timeout, non-macOS hosts,
   stale/mismatched authority, or subprocess failure still returns
   `human_authority_unavailable` before mutation. The
   agent-attested current-chat authorize lane (decision 5) is deliberately **not** extended to
   them. The ADR-012 setup wizard's already-authorized digest-bound composition is a separate,
   unchanged authority and does not route through this class.

   **Amendment (2026-09-13, issue #719).** The `plugin_artifact_apply` presence cell is selected
   per platform (`select_artifact_user_presence`) for both standalone consumers, the Cursor and
   Claude Code native lifecycles. macOS keeps the #409 LocalAuthentication adapter unchanged.
   Linux, including a distribution running under WSL 2, uses `LinuxArtifactUserPresence`: after
   a banner naming the exact operation, preview digest, and pending review, the invoking
   account's operating-system password is read once through the ADR-008/ADR-015 trusted
   foreground console with echo disabled and verified by Linux-PAM through the fixed `login`
   service with a null password refused, followed by account management. The console is ingress
   only; the operating-system credential check is the authority, so a pseudo-terminal, redirected
   stdio, or same-UID process that cannot produce the password still cannot authorize, and
   decision 4 is unchanged. Cancellation, EOF, an empty or wrong password, a locked or expired
   account, a missing or refusing PAM stack, no verified console, an echoed, repeated, or unknown
   prompt, and the 130-second deadline all return `human_authority_unavailable` before the pending
   is claimed. Every other platform keeps failing closed with that reason. `preview` names the
   selected cell as `authorization.human_presence`. This remains scoped to
   `plugin_artifact_apply`; it is not the service-wide `UserPresencePort` and authorizes no other
   operation.

   Issue #150 implements the artifact half as the exact `plugin_artifact_apply` operation. Its
   target digest is the complete portable artifact preview digest, its risk class is
   `review_only`, and agent-chat authorization is disabled. Preparation and single-shot
   consumption exist. Issue #409 wires the scoped macOS LocalAuthentication adapter into the
   standalone Cursor CLI; it does not create a service-wide `UserPresencePort`, authorize another
   operation, or make generic portable-plugin mutation available. Generic `skill_install`, Cursor
   host-activation apply, and catalogued-but-unimplemented harness MCP registration remain
   unimplemented as `review_only` consumers.

   **Amendment (2026-08-25, issue #419).** Codex marketplace activation already ships as the
   ADR-012 digest-bound `--accept` composition, not as `plugin_artifact_apply`. Codex marketplace
   removal (`preview_removal` / `apply_removal`) and external MCP unregistration
   (`preview_unregistration` / `apply_unregistration`) use that same lane: exact preview digest
   plus explicit `--accept` or the interactive confirmation already used by
   `yoetz integrate codex mcp install`. They do not prepare or consume `plugin_artifact_apply`,
   because that cell is the macOS Cursor portable-artifact presence path and would fail closed
   here. Cache purge is default-off (`--purge-cache`). Agent-chat authorize is not extended to
   these commands. Cursor standalone activation apply is unchanged.

10. **User-selected supported outcomes (issue #532).** Normal conversation is the primary
    agent-guided setup, install, and settings-change experience. The agent explains consequential
    choices and recommends an option with its trade-off, but an explicit current user choice is
    final for the supported product-policy outcome. The agent cannot silently substitute a recipe,
    provider, model, privacy level, install target, or ceremony. Only factual technical limits,
    unavailable authority, policy ceilings, target drift, never-send and credential/destructive
    invariants, or honest proof boundaries may block; the response names the concrete boundary and
    shortest user-controlled continuation. When the user explicitly asks for AI-powered review, the
    agent recommends Expanded first for review depth and explains Assisted as the lower-disclosure
    AI-powered review alternative before preparing the one exact combined action.

### Linux PAM deadline isolation (issue #719)

Linux PAM deadline implementation (issue #719): the trusted console process retains password
input and terminal restoration, while a disposable Python worker performs the native PAM calls.
The bounded password travels through an anonymous pipe only. The parent kills and reaps its
worker on timeout or cancellation; a blocked PAM module cannot defer the parent deadline.
No PAM prompt or error output is forwarded. Empty, overlong, and NUL-containing passwords are
refused before launching the worker.

## Consequences

Agents guide choices in ordinary conversation, prepare and inspect one combined request, then
either complete it via agent-attested `yoetz consent authorize` on a capable first-party host or
give the shortest exact trusted-local continuation when that authority capability is absent. Until an approved
OS-presence adapter is installed, console review fails closed; chat-user authorize remains available
for the operations that advertise it. Approval of one operation does not grant another operation,
another digest, another installation, or a later session.

Native biometrics, host-verified chat provenance, approved-machine profiles, monthly grants,
E2EE service authority, and authority-bearing MCP tools (beyond the six ADR-011 tools) require
separate ADRs and threat reviews. The one scoped exception is the macOS LocalAuthentication owner
receipt view (decision 4 amendment, ADR-009 round 5), whose threat analysis is recorded there.

## Alternatives considered

**Agent-held bearer grant.** Rejected because it is reusable. The accepted agent assertion is
deliberately delegated but exact, expiring, and single-use.

**Approve once per session.** Rejected because secret and irreversible operations require distinct
targets and digests.

**Ordinary MCP/chat secret entry.** Rejected. Agent-attested one-shot stdin after warning
acknowledgement is the narrow #164 exception; ordinary MCP tool arguments still must not carry
secrets.
