# ADR-009 — Central privacy, disclosure, and data-egress control

**Status:** Working decision revised 2026-08-30 for issue #404 vendor-runtime egress. Ratification requires an independent
privacy/security review plus executable no-bypass, never-send, approval-resume, and zero-egress
evidence.
**Implemented by:** `src/finishup/domain/privacy.py`,
`src/finishup/application/egress.py`,
`src/finishup/application/privacy_policy.py`,
`src/finishup/ports/privacy.py`, the privacy adapters/configuration/audit modules, ADR-006,
ADR-011 structural subject-state capture, `PRIVACY.md`, the technical privacy protocol, policy
schemas, fixtures, and tests.

## Context and trust boundary

FinishUP is the policy authority. CLI, MCP, future UI, plugins, provider adapters, integrations,
agents, and LLMs are clients or constrained effectors; none may decide what data is disclosable.
Network egress and local disclosure are distinct: an MCP response may enter an agent/LLM context,
and a local model still receives user content through FinishUP's AF_UNIX-only path. A pre-existing
model runtime is a separate trusted disclosure sink unless its exact support cell proves enforced
no-network isolation; AF_UNIX delivery alone does not prove what that process does later (F-013).

Every candidate disclosure follows one enforced path. After audit reservation succeeds, each
terminal branch ends in a durable privacy receipt; the sole exception and its fail-closed boundary
are fixed in decision 9:

`candidate context → deterministic classification → effective policy → local
minimization/redaction/secret scan → optional durable human preview/approval of the exact prepared
case → single-use authorization → bounded gateway → bound sink/provider → durable privacy receipt`

## Decisions

1. **Four LLM-disclosure profiles:** `local_only`, `confirm_every_request`, `minimal_external`, and
   `trusted_provider`. These values govern LLM inference and its content-disclosure rules; they are
   not a bundled consent switch for telemetry, diagnostics, updates, or capability testing.
   `local_only` constructs no external LLM-provider transport, disables the `llm_inference`
   network channel, and permits a local model only when separately configured and explicitly
   trusted under resolved decision F-013. It may coexist with a separately authorized bounded
   non-LLM policy row, but
   no such channel may carry task/user content. v0.1 ships production transport for
   `update_checks` only among the non-LLM channels (structural package identity against an
   allowlisted PyPI URL). The remaining three non-LLM channels (`product_telemetry`,
   `crash_diagnostics`, `capability_testing`) still have no production transport: proposed
   enablement is rejected and makes no I/O; adding one later requires an exact adapter/use-case
   owner, ADR review, and fresh human transition.
   `confirm_every_request` requires an exact durable preview
   of the already minimized/redacted/scanned outbound case and a local-human decision for each
   external request. `minimal_external` automatically permits
   only the smallest context allowed by its policy. `trusted_provider` permits explicitly listed
   categories only for one bound provider plus, when declared, exactly one fallback provider —
   each an exact binding approved in the same ceremony (ADR-006 fallback endpoint amendment,
   2026-09-04) — endpoint profile, workspace/task scope, and purpose; it never means
   unrestricted access.
2. **Global ceiling plus independent network channels:** `network_egress_permitted` is an explicit
   global boolean ceiling. `false` requires every network channel disabled; `true` authorizes
   nothing by itself. Beneath that ceiling, policy and consent are separate for exactly
   `llm_inference`, `product_telemetry`, `crash_diagnostics`, `update_checks`, and
   `capability_testing`. Enabling one never enables another. All four non-LLM channels are limited
   to their reviewed bounded structural or synthetic schemas and cannot carry ordinary or
   sensitive task/user content.

   **Revised 2026-08-03 — `update_checks` transport and product default.** v0.1 ships a bounded
   structural transport for `update_checks` only: a fixed allowlisted HTTPS GET of the `finishup`
   distribution identity on PyPI (`https://pypi.org/pypi/finishup/json`), with `trust_env=False`,
   size/timeout caps, and response use limited to the latest version string. Interactive TUI
   surfaces (first-run finish, resume tip, `/doctor`) and interactive setup/`/connect` may surface
   an advisory plus the exact upgrade command `uv tool upgrade finishup`; work receipts never carry
   update metadata. The product durable seed and named recipes default `update_checks` **on** with
   `network_egress_permitted=true` solely because that channel is on, while `llm_inference` and the
   other three non-LLM channels stay off and profile remains `local_only`. Config.toml generation-1
   bootstrap remains fail-safe all-denied and is not continuing disclosure authority. Operators may
   opt out in first-run setup or privacy custom section 5. **Amended 2026-08-12:** the first-run
   setup answer may replace only the `update_checks` value in its recommended or named privacy
   recipe before the exact candidate is rendered. `None` preserves the recipe default, and Custom
   continues to ask section 5 itself. The answer is not authority: the resulting candidate still
   requires the existing exact confirmation and service proposal/decision ceremony. The remaining
   three non-LLM channels stay unsupported: setup marks them read-only off, proposed enablement
   returns `channel_unavailable` without persistence or I/O, and forced enabled state yields a
   pre-dispatch `channel_unavailable` decision receipt with no DNS/socket I/O. Absence of a channel
   is not silently replaced by a generic HTTP client.

   **Amended 2026-10-14 (ADR-048, issue #1055) — the transitional `yoetz` identity.** The
   allowlist holds exactly two URLs: `https://pypi.org/pypi/finishup/json` and, for an install that
   came from the deprecated transitional `yoetz` distribution (the `yoetz` distribution is installed
   at exactly the running version), `https://pypi.org/pypi/yoetz/json`. Such an install upgrades
   through that same name, so its check asks about that identity and its advisory names
   `yoetz upgrade`; every other install asks about `finishup`. Each request still carries only that
   one package identity, under the same channel gate, caps and response use. Each identity has its
   own cache file in the state directory (`package-update-cache.json` for `yoetz`, which released
   Yoetz readers also read and treat as a `yoetz` poll, and `package-update-cache-finishup.json`
   for `finishup`), so each keeps its own 24-hour TTL and makes at most one request per TTL; an
   entry recording the other identity is never answered from, and an entry with no package member
   is a pre-rename `yoetz` poll. The second URL leaves the allowlist when the alias is removed.
3. **Local disclosure sinks:** `local_model`, `agent_context`, `local_human_view`, and
   `trusted_human_control` are not network-egress channels. They receive only policy-approved
   minimized content and are covered by the never-send fence. The trusted human surface may render an
   approval preview and exact policy diff, but it never exposes cryptographic material or
   service-vault credentials.
   A local-model runtime receives plaintext and belongs to the trusted local computing base unless
   its exact artifact/profile supplies independently enforceable sandbox evidence; FinishUP's adapter
   makes no claim about another process's ambient network authority.
   `HumanAuthorityCapability.source=unavailable` fences external-provider activation, credential
   mutation, and durable policy widening; it is not a second use-time authorization gate for an
   already reauthenticated exact local-model policy row. Local-model use remains independently
   gated by deterministic classification, exact installed profile, service/vault/policy generation,
   and one-shot `consume_local` authorization.

   **Revised 2026-07-16 (see ADR-010, F-018/F-019).** The original single `agent_context` sink
   conflated two audiences with different risk, and its structural-only default therefore withheld
   finding prose from the local human as well as from the agent, on the zero-egress install every
   user starts with. That default protected nobody in the common case and broke the
   `check → respond → recheck` loop the product exists for. Two changes correct it without weakening
   the fence:

   `local_human_view` is now a separate sink for the owner reading their own unlocked vault, which
   is not a third-party disclosure. It admits every non-never-send category at
   `public_structural|ordinary_user_content`. *Superseded 2026-10-14 (round 3):* this sink was first
   selected by human-readable rendering to an attached controlling terminal. A pseudo-terminal an
   agent controls passes that test, so no presentation fact selects it any more; every ordinary
   client result is `agent_context`, and `local_human_view` is reached only through the
   reauthenticated one-use `owner_receipt_view` grant described under decision 3's receipt
   amendment. The client never selects its own sink.

   `agent_context` is now conditioned on a computed closed `DisclosureProvenance`
   (`self_authored`, `engine_derived_from_self_authored`, `other_writer`, `imported`). Material the
   requesting writer authored at the frozen frontier, and kernel prose derived solely from it,
   project at the policy's data classes without a category grant: that content is already in the
   host's context, so withholding it discloses nothing new and costs the loop. Other-writer
   material, imports, and provider-derived AI-powered review prose — including every reviewer
   challenge —
   still require the explicit `agent_context_categories` grant.

   ADR-022's derived observation writer is `engine_derived_from_self_authored` for this provenance
   decision: a hook observation records the requesting agent's own action, not another writer's
   independent authorship. This classification was a forward contract written before any
   production resolver existed; see the 2026-09-29 revision below for what ships.

   **Revised 2026-09-29 — the provenance resolver ships (issue #914).** Production now composes
   `LocalPrivacyEnforcer` with a ledger-authorship resolver, so an agent reads back the evidence it
   published. The resolver consumes only authorship the service read from accepted event envelopes
   at the page's frozen frontier (writer chain, session, ingestion sequence, ledger-recorded
   publication channel, observation stamp); it never reads a field of the request being projected.
   A cooperative writer can record only the `cooperative_mcp` or `local_cli` channel; import and
   observation channels are service-only. It attributes status
   evidence rows, whose prose comes from one source event: a row is `self_authored` only when that
   event was written by the requesting writer, in the requesting session, at or before the frontier,
   through `cooperative_mcp` or `local_cli`, without the observation stamp. Import channels are
   `imported`. Hook-observed rows are written by the observation coordinator's own writer and stay
   `other_writer`: the shipped resolver does not implement the forward
   `engine_derived_from_self_authored` classification above, per the issue #914 owner decision that
   matching session or host is not authorship and that host-captured prose must not be widened into
   the default ceiling. Reconciling that forward contract is left to a maintainer decision recorded
   on #914. Every other leaf is ambiguous and keeps the category ceiling, including every finding.
   Attach opens a new session with a new writer, so rows published before it are not
   self-authored for the attached session. A row whose source event a later redaction targets,
   by event or by the event's payload object, is withdrawn from attribution even on a pinned read,
   so the exemption never re-discloses redacted prose. The never-send scan still runs first, `sensitive_confidential` stays absolute, and each
   projection still writes its receipt. The receipt's approved categories show the inclusion but
   not the reason: the `self_authored` provenance is recorded only in the internal audit subject,
   and surfacing it in `privacy receipts get` needs a design-gated egress-receipt schema change,
   left as a follow-up.

   **Revised 2026-10-13 — names of undeclared files a deliverable may read (tb4n5).** The owner
   allowed showing the agent, locally, the names of files it itself created. No structural record
   proves that (a file staged before the task, an ignored file force-added later, or one another
   process wrote all appear as created; no observation records a shell-written path), so no new
   provenance value is added and the exception fails closed: the status leaf
   `/closure_readiness/undeclared_references/<n>/paths/<m>` carries the ledger authorship of the
   accepted, unredacted publication that spelled that exact name (`attempted_items` or
   `requested_items`; a later `redaction_recorded` naming its event ID or its payload object ID
   revokes it), keyed on that leaf (`ProjectionProvenanceContext.leaf_authorship`, admitted
   only for that leaf family and only as `repository_excerpt`), and the ordinary `self_authored`
   rule decides: only the writer that published the name, in this session, through a cooperative
   channel, gets it back. Every other name keeps the ceiling, with a typed continuation in the Stop
   gate (ADR-035). The review packet never carries the names, nor the digest of a payload that held
   them (ADR-035).

   **Revised 2026-07-24 — default agent-context disclosure of verification output.** Under the
   default LOCAL_ONLY bootstrap policy, `agent_context` may include FinishUP-authored verification
   projection content for the requesting agent's own task: `finding_summary` and
   `obligation_text` (receipt document sections, human_text, check findings/obligations). These
   remain `ordinary_user_content` at the data-class layer; the default policy allowlist is widened
   rather than reclassifying leaves as public structural. Observation-derived repository/transcript
   excerpts and vault material stay blocked. Stricter owner policies may still block JSON receipt
   projection (fail closed as `privacy_projection_blocked` → `PRIVACY_AUTHORITY_REQUIRED`);
   markdown/text degrade with omission markers. Provenance is computed from the
   ledger, never asserted by a caller; ambiguity or an unresolvable ref denies; it is recomputed per
   projection and never cached across frontiers.

   Both local client sinks take the same reserve/complete receipt path: `local_human_view` is a
   looser ceiling, never an unaudited one. Provenance widens only `agent_context`, only for the
   requesting writer, and never past `sensitive_confidential` or the never-send set, which remain
   absolute at every sink under every provenance. Serving static reviewed guidance documents is not a
   sink at all, because they carry no user content and are identical for every installation.
   An exact same-request delivery retry may reuse a completed `publish_work` projection and its
   original receipt only for the same writer, request digest, and local sink. This is continuation
   of the already-audited disclosure, not a new projection: the cached body is restricted to public
   structural fields and omission markers, while the current route is revalidated and the outer
   control correlation is freshly stamped. Any plaintext event summary prevents caching and uses
   the ordinary reserve/complete path again.
   **Amended 2026-10-14 — receipt prose ceiling (N5 privacy).** The maintainer explicitly
   requested this scoped repair, acknowledging the privacy/egress design gate. A `full_local`
   profile is a local storage/rendering choice, never agent disclosure authority.

   Amended again 2026-10-14 (round 2, maintainer request): withholding narrows to the repository
   names the ceiling covers and large omission lists coalesce. Amended 2026-10-14 (round 3,
   maintainer request): no presentation fact selects `local_human_view` any more; the owner's full
   receipt is a reauthenticated, one-use `owner_receipt_view` grant (ADR-016 decision 4), `./` and
   absolute spellings are the same name, and an expanded field is bounded visibly.

   Receipt prose is FinishUP-authored and keeps its ordinary category policy in an `agent_context`
   projection: section titles, sentences, codes, counts, IDs and coverage remain readable. The one
   thing it can carry that the excerpt ceiling covers is a repository file name the check found and
   no participant published (an undeclared-reference name, ADR-035), which a `full_local` receipt
   spells. Each such name span is offered as its own `repository_excerpt` candidate. Unless the
   policy grants repository excerpts, or the requesting writer published that exact name in this
   session through an accepted, unredacted cooperative publication, the whole path token becomes
   `(receipt prose withheld: repository_excerpt)`; the rest of the sentence stays. A span is the
   quoted path the receipt prints, the bare path when it has a directory, or a basename with an
   extension. Any name, a top-level one without an extension included, is also a span behind a
   leading `./` (also `.//` or `././`), quoted or not, and empty or `.` segments inside the name
   still spell the same file. Behind an absolute prefix (`/`, `~`, `~user`, `$VAR` or `${VAR}`,
   optionally behind `file://`) any directories may come before the name's last component: an
   absolute path that ends in a withheld file's base name counts as that file, which can only
   withhold more. Unquoted, the prefix's directories stop at whitespace, at quotes and backticks, at
   `<` `>` `|` `,` `;` and brackets, and at a `:` that starts another path (`:/`, `:~`, `:$`, `:./`
   or `:../`), so the next path in a list starts afresh; a `:` inside a directory or a port
   (`host:8080/`) is kept. The whole prefixed token is withheld. A path in single quotes, double
   quotes or backticks may run through directories with spaces or the other quote characters
   (`"/r/Bob's/a.npz"`), and the whole quoted token is withheld when the name ends the quoted text;
   a name earlier in the quotes (`"/r/x/b.npz /r/y/a.npz"`) is found too, and its own path is
   withheld. An absolute path through a directory with spaces is not recognised as one path when it
   is unquoted, since prose gives it no token boundary, or when anything follows the name inside the
   quotes (`"/My Docs/a.npz:12"`); nor is an unquoted one through a directory holding a stop
   character (`/r/Bob's/a.npz`), or a quoted one through a directory holding its own closing quote.
   A name glued to other characters and then a `/` (`/r/a.npz~/x`), or followed by a `:` and a bare
   relative path (`/r/a.npz:rel/x`, or grep's `/r/a.npz:12:rel/x`), reads as a directory of a longer
   path and stays readable: the prefix never gives a directory back, which keeps each search linear.
   A different relative directory (`../`, `x/`), a longer name, a suffix, a plain word such as
   `Summary` (or a top-level name written without a prefix or quotes), and a different letter case
   stay readable: spellings are compared exactly, because folding case or Unicode would conflate
   distinct files on a case-sensitive filesystem. Every bound in the span pattern is fixed, so a
   search stays linear in the prose it reads. The rule applies to JSON, markdown and text and to
   every profile, `full_local` included: a format or profile is not a disclosure grant.

   The token can be longer than the name it replaces. A field that would then pass its wire bound
   (32,768 characters for `human_text`, at least its original length for a document field) or the
   16 KiB per-item privacy bound is cut deterministically at a whole token and ends with a visible
   `[receipt text truncated after withholding: N characters not shown]` marker; only text already
   past the withholding is dropped, and the audit still records every per-name decision.
   `privacy_projection.omitted_pointers` names each affected result field. Past the 512-pointer wire
   bound the list coalesces deterministically to containing fields, so a large receipt still renders;
   the local disclosure audit keeps one decision per name and field
   (`<field pointer>/@repository_name/<name index>`). The digest and object ID identify the unchanged
   stored owner receipt. An earlier stored receipt meets the same rule when reread, with name
   provenance read at the current ledger head, so redacting the publication that spelled a name
   withdraws it. A denied ordinary prose category keeps its existing omission behavior; JSON still
   fails closed when that denial would need an object marker inside the receipt document.

   Every client result is agent-facing (`agent_context`): the CLI, the terminal interface, MCP tools
   and hooks alike. A terminal, a human-readable rendering, a client kind or the user ID is a
   presentation fact an agent can reproduce (a pseudo-terminal passes every terminal test), so none of
   them selects the owner's view, and the service ignores them as authority. The owner's full receipt
   (`local_human_view`) needs an explicit request, `finishup receipt --owner-view` or *Your full receipt*
   in the terminal interface, and a human-control `owner_receipt_view` ceremony: the owner
   reauthenticates with operating-system presence or the vault passphrase for that exact receipt
   request. The grant belongs to the command's own control connection as the service admitted it:
   the service mints an opaque identity for every admitted connection and never takes one from the
   client, refuses any connection whose hello nonce is already live or was used before, mints the
   grant only for the one live connection the ceremony target names, consumes it only on a receipt
   call on that connection, and revokes it when the connection closes. The grant is one-use and
   expires after 60 seconds. There is no standing grant, and the agent-attested consent lane cannot
   stand in for it. Anyone holding the terminal can type into the prompt, a pseudo-terminal
   included; the boundary is a passphrase or presence check the agent cannot pass. On macOS the
   packaged service composes one operating-system presence provider, Apple LocalAuthentication
   (Touch ID or the device password), scoped to this ceremony (round 5 below). Linux and WSL 2
   compose none: there only a vault passphrase the owner types completes the ceremony. A vault
   without one, or whose passphrase is kept in the platform credential store (setup's
   system-keychain choice, never shown to its owner), fails closed with `owner_view_unavailable`;
   an owner who chose a stored passphrase can still type it with `--use-passphrase`. A command with no foreground terminal to prompt on
   (for example a headless session) fails with `owner_view_requires_terminal`. Either way it shows
   nothing and points to the next step. Linux and WSL 2 use the same code but were not exercised
   for this change. A process running as the owner's account that can already read the vault
   passphrase (for example from an auto-unlock keyring entry) is outside this boundary, as for
   every passphrase reauthentication (ADR-008).

   **Amended 2026-10-14 (round 5, owner decision on issue #1073: Touch ID before release).** The
   owner asked for an operating-system presence path on the existing reauthentication so a
   system-keychain installation can open its full receipt. Setup's system-keychain choice creates
   a passphrase vault whose passphrase is generated and kept in the Keychain for auto-unlock, so
   its owner never learned it and could not answer the passphrase prompt.

   - *Where the check runs.* The service process runs it, never a client. A client's
     `SelectAuthorizationSourceAction` names `os_user_presence` and carries nothing else; the
     human-control service then binds a fresh reauthentication challenge and asks its composed
     `UserPresencePort`. Only the provider's own one-use attestation for that exact challenge
     reaches the vault, which mints the proof the owner-view effect consumes. A TTY, a
     pseudo-terminal, a client kind or a hello field still grants nothing.
   - *The macOS provider* (`MacOSLocalAuthenticationPresence`) starts the SIP-protected
     `/usr/bin/osascript -l JavaScript` with a fixed program on stdin, no shell, a three-variable
     environment and working directory `/`. The program creates a fresh
     `LAContext` with authentication reuse disabled and evaluates
     `LAPolicyDeviceOwnerAuthentication`. The dialog text is fixed per purpose; its only variable
     part is a confirmation code (the first eight hex digits of the service-computed target
     digest), which the owner's own command prints too, so nothing user-controlled reaches the
     dialog. The program's own deadline is 60 seconds; the service kills and reaps it at 75
     seconds, or at once when the ceremony is cancelled, its client disappears, or the service
     stops. Only the exact token `approved` yields an attestation, held in service memory, bound
     to the exact challenge and consumed once within 30 seconds. Every other result is typed:
     `unavailable` (no dialog can be shown: not macOS, no LocalAuthentication, no desktop session,
     or a nonzero, garbled or unknown helper result) becomes `presence_unavailable`;
     `cancelled` or `failed` becomes `presence_refused`; `timeout` becomes `presence_timeout`.
     None of them carries operating-system text, and none grants anything.
   - *Scope.* The provider prompts only for `owner_receipt_view`, and the service offers it
     (`PresenceScope`) only for that purpose on a ready vault of either mode. It does not stand
     in for provider credentials, privacy widening, idle relock, installation recovery,
     passphrase rotation or keyring retry. Keyring first-install still needs a qualified
     `user_presence_cells` row; this provider's capability names the release cell
     `unqualified` and never matches one.
   - *Passphrase vaults.* A passphrase stays offered beside the dialog. The command asks for the
     dialog first. When the service reports that it cannot show one (`presence_unavailable`;
     where the service runs decides this, not where the command runs) and the vault offered its
     passphrase, the command asks once for the passphrase in a fresh ceremony. A cancelled,
     failed or unanswered dialog is not retried. The command never asks for a passphrase that is
     kept in the platform credential store (setup's system-keychain choice generates one its
     owner never saw): there it ends with `owner_view_unavailable`, naming `--use-passphrase`,
     which an owner who chose that passphrase uses to type it. `--use-passphrase` also skips the
     dialog, for an owner connected over SSH whose service would raise the dialog on the Mac's
     own screen. Offering presence beside an owner-chosen passphrase adds no secret an agent can
     learn; its cost is the residual risks below.
   - *No held lock.* The ceremony releases the human-control mutex while the dialog waits, as it
     already does while a secret is entered, so `cancel`, `service stop` and a disappearing
     ceremony client end the dialog at once instead of waiting out its deadline. One prompt runs
     at a time, and a second action on the same ceremony is refused while it is up. A ceremony
     opened while another is active fails with the closed `ceremony_busy` code, never with the
     locked-vault `state_forbidden`, unless the active one is past its five-minute binding
     expiry: such a ceremony can never complete, so the next open ends it and proceeds. A
     throttled passphrase is `reauthentication_rate_limited` on every ceremony.
   - *Backoff.* After a prompt that did not approve (refused or unanswered, or cancelled after it
     was up for at least 2 seconds), the next prompt waits 5 seconds, then 15, 30, 60, 120 and at
     most 300 seconds per consecutive miss. An approval resets it, and so do 10 minutes without a
     miss. A prompt cancelled sooner does not lengthen the wait, since the owner may never have seen
     it (2 seconds is the service's estimate, not a signal from the helper), but the next prompt
     still waits the first step: after a dialog that did not approve, the service raises no other
     for 5 seconds however quickly it was cancelled. Within the wait no dialog is raised and the
     ceremony fails with `reauthentication_rate_limited`. The backoff lives in the service process,
     so a restart clears it: it slows repeated dialogs, it does not cap them. The durable passphrase
     throttle is separate: 30 seconds after the third wrong passphrase, doubling to 5 minutes, and a
     restart does not clear it. The owner view tells the two apart by the source it chose and never
     offers a restart or `--use-passphrase` for a throttled passphrase (`passphrase_rate_limited` on
     the CLI; the terminal interface says the same).
   - *Why a helper process, not ctypes.* The same Apple executable and program shape already
     serve the `plugin_artifact_apply` cell (ADR-016, issue #409), so this adds no dependency and
     no new native surface. ctypes against `libobjc` and LocalAuthentication would need a
     hand-built Objective-C reply block running native code inside the long-lived service, and a
     wedged prompt could not be killed without killing the service; a child process can.
   - *Residual risks, stated.* An agent that can run the command from a pseudo-terminal can make
     the dialog appear but cannot answer it: that takes the owner's fingerprint or device
     password. An agent shell without a terminal, such as Claude Code's Bash tool run directly,
     is refused with `owner_view_requires_terminal` before any dialog, but the agent can wrap
     the command in a pseudo-terminal (for example with `script`), and then the dialog appears
     as it does under Codex. An owner who approves a dialog they
     did not ask for gives that command the view, so the dialog says what it shows, shows the
     code the owner's own terminal prints, and says to cancel unless they just asked. An agent
     can also open its own ceremony just before the owner runs the command. The service runs one
     ceremony at a time, so the owner's command then fails with `owner_view_busy` and names its
     own confirmation code (on macOS it prints that code before anything opens), and the dialog
     on screen shows a different one: the owner cancels it. The code is the first eight hex
     digits of a digest of the exact request and its connection, so it is request-specific but
     short; it is a cross-check, not a secret. The dialog appears in the desktop session the
     service runs in; a service started outside one (for example over SSH) is expected to report
     that no dialog can be shown. Two lockouts remain, each bounded. A client that opens a
     ceremony and goes silent holds the one slot until its binding expires (five minutes) or
     the service restarts; meanwhile the owner sees `owner_view_busy`, which names
     `finishup service restart`. An agent that raises dialogs and lets each be refused, time out or
     stay up for 2 seconds before cancelling can push the owner's next dialog behind the
     backoff (at most 5 minutes); `finishup service restart` clears it, and `--use-passphrase`
     confirms with an owner-chosen passphrase instead. One that cancels each dialog sooner does
     not lengthen the wait but can still raise a dialog every 5 seconds; the owner cancels any
     dialog they did not ask for. A program running as the owner's account
     that can read the credential-store entry can confirm with that passphrase instead of the
     dialog (`--use-passphrase`), so the dialog protects against agents that cannot read the
     owner's keychain, not against everything that runs as the owner. Same-account code
     tampering with the installed runtime is outside this boundary, as for every presence and
     passphrase check (ADR-008).
   - *Evidence.* Unit and integration tests drive the real adapter, scope, ceremony, vault proof,
     daemon handler and ceremony client with a stub helper; no real Touch ID prompt has been
     exercised. The manual check on a real Mac in the test-instance runbook (*Owner view with
     Touch ID: manual check on a real Mac*) has not been run. The owner asked for a Codex check
     of this round; it has not been run. Three independent Claude review rounds ran instead
     (2026-10-14 and 2026-10-15), and this round addresses their findings.

4. **Data classes:** structural public data, ordinary task/user content, sensitive/confidential
   content, and secrets/cryptographic material are distinct. Classification combines source-owned
   structural labels, scope validation, and deterministic secret scanning. Unknown or conflicting
   classification fails closed for disclosure.
5. **Non-overridable never-send set:** encryption keys, recovery/unlock secrets, passwords,
   candidate/user-discovered API keys, authentication tokens, cookies, private certificates,
   keyring contents, unrelated
   environment variables, credential files, hidden authentication configuration, unselected raw
   database contents, unrestricted logs/stderr/transcripts, and files outside the selected scope
   can never be placed in an approved external, local-model, or agent-context case. No profile,
   local-human click, provider trust label, plugin, or request override can weaken this set.
6. **Policy composition:** the machine policy is an installation ceiling, not a standing grant for
   every repository. The effective decision is the intersection of that ceiling with repository,
   task, and request overlays. Lower scopes may tighten immediately. External LLM admission under
   any policy additionally requires an exact current repository row beneath the ceiling; absence or
   mismatch denies before provider construction, credential-handle minting, authorization, or
   dispatch. Machine-scoped structural channels such as update checks remain independently governed
   by their channel rows and do not acquire this task-content authority. Except for the exact
   prepared current-chat consent-lane path described below, loosening any effective permission
   requires a locally authenticated human on a trusted control surface, reauthentication, an exact
   diff, and a durable decision. Generic MCP/agent/LLM calls can request more context but cannot
   approve or persist the expansion.
   *Amended by ADR-016 decision 5 (issues #164/#533) and the "Human required?" table below:* the
   user's explicit current-chat instruction, relayed by a capable agent through the consent lane for
   one exact prepared, previewed, expiring consent target, is a second reauthenticated loosening
   path; that relay is an agent attestation FinishUP cannot independently authenticate, and it never
   overrides the never-send set.
   Answering a `confirm_every_request` disclosure is deliberately *not* one of these loosening
   operations and does not require passphrase mode or strong reauthentication: it decides one exact
   prepared case already bounded by the committed policy, and it can neither widen the policy nor
   authorize any other case. It requires a ready vault and the trusted foreground surface, nothing
   more. Requiring passphrase mode made the decision unreachable on a keyring installation, which
   is the ordinary configuration, so the posture existed with no way to answer it.
   Policy commit and external/local consumption share one generation-CAS linearization point.
   Tightening-first prevents I/O and closes the unconsumed branch with a no-dispatch receipt;
   consume-first admits one attempt that may send, must be best-effort closed/nonselectable, and
   records its actual terminal or unknown receipt. Tightening never claims to retract bytes already
   admitted.
   **Desired-state TOML (ADR-014):** `finishup privacy export-desired` / `apply-desired` may declare
   nonsecret policy intent in a sidecar TOML document. Apply classifies against the effective
   store: equivalent is a no-op; tighten routes to the existing tighten gate; widen never commits
   from the file alone and requires the ordinary propose→decide path. The generation-1
   `[privacy]` bootstrap seed in service `config.toml` remains fail-safe only and is not
   continuing disclosure authority.
7. **Human approval is resumable authority:** content-bearing previews and decisions are encrypted
   durable `ObjectKind.privacy_audit` objects in the owning task bundle. Taskless v0.1 decisions and
   machine policy diffs are closed nonsecret structural catalog rows; a future taskless
   content-bearing channel requires its own installation-scoped encrypted audit-object contract.
   Agent-context result projection instead uses a dedicated structural subject with keyed
   internal/projection commitments and field decisions; it never duplicates result plaintext.
   Each task-bundle privacy object is an explicit installation-catalog live root without a fabricated
   task-ledger inventory row. v0.1 retains it for the supported installation-data lifetime and has no
   individual privacy-audit-content deletion operation; ordinary ledger redaction/GC cannot clear
   the root.
   Approval binds exact request/case digest, excerpts/categories, provider/model/endpoint,
   purpose, scope, policy version, byte/token ceilings, expiry, and one dispatch. A declared
   fallback endpoint does not stretch one approval across two destinations: each fallback
   attempt is its own physical attempt bound to the exact fallback provider/model/endpoint
   with its own authorization, dispatch identity, credential handle or runtime authority,
   and receipt. Denial and expiry
   are terminal, durable outcomes. Restart never converts a pending or expired proposal into
   approval. Under `confirm_every_request`, every physical attempt—including an otherwise eligible
   retry of identical bytes—requires a fresh exact foreground preview and decision; consumed or
   outcome-unknown authority cannot authorize another attempt. Crash/resume before authorization
   consumption continues the same approved dispatch and does not invent a retry. Automatic
   profiles may mint retry attempts inside their existing policy and total retry budget, but each
   still receives a fresh authorization, dispatch identity, credential handle, and receipt.
8. **Provider and integration confinement:** provider adapters receive only an
   `ApprovedOutboundCase`; composition gives them no repository/database/environment/transcript or
   other ambient handle, and the outbound gateway is the only component holding a network-capable
   transport. v0.1 permits only reviewed bundled adapters in the closed registry and forbids
   third-party/dynamic adapters. This is a dependency/capability contract, not an OS sandbox: a
   malicious in-process Python adapter could use the service account's ambient authority. Bundled
   adapters are reviewed/tested not to fetch additional context, follow redirects, inspect process
   state, or widen content. A final-body/profile/MAC/credential failure before consume revokes the
   unconsumed authorization and writes a no-dispatch decision receipt; only consumed work can
   create an attempt receipt. Tightening revokes pending grants and best-effort closes affected
   admitted transports.
9. **Unified durable audit:** every successfully reserved terminal outbound decision and every
   physical outbound attempt, including taskless update or capability channels, produces a durable
   structural `EgressReceipt` through `PrivacyAuditPort`. `awaiting_human`, `approved`, and
   `receipt_pending` are nonterminal audit states, never receipt outcomes. Initial reservation
   failure is the sole no-receipt exception: it returns bounded `audit_failed` before prompt,
   authorization, or dispatch and fabricates no receipt identity. A later transition failure for an
   existing reservation may be durably completed `audit_failed/audit_failed`; post-consumption
   receipt failure stays `receipt_pending` until recovery records the real attempt outcome.
   It records provider/model/endpoint profile, policy version/digest, authorization scope,
   categories approved/blocked, byte/token counts, redaction/minimization counts, consent source,
   outcome/reason, and a keyed commitment to the exact final provider/application request body
   bytes—never plaintext. v0.1 freezes `audit_store_version=1` and commitment object
   `{algorithm: "hmac-sha256/yoetz-privacy-egress-request-v1", commitment:
   "hmac-sha256:<64 lowercase hex>"}`; it has no `key_slot_ref` because K_audit has no v0.1
   rotation/slot interface. A dispatch receipt also requires exact `request_body_bytes`; a
   pre-dispatch receipt forbids it. HTTP/TLS framing, transport-generated metadata, and credential-bearing
   authentication fields are outside that commitment; provider credentials enter only through a
   separately bound vault handle at the transport boundary and cannot alter the approved body.
   Resolved decision F-012 permits this separately provisioned vault credential to leave only as
   one-attempt authentication metadata to the exact profile-bound HTTPS endpoint selected by the
   reviewed registry, using platform CA trust and hostname validation; v0.1 does not claim
   certificate or SPKI pinning. Candidate/user-discovered credentials remain never-send.
   Catalog-backed audit is permitted; content-bearing task audit
   uses encrypted bundle objects referenced directly from the privacy catalog, while structural-only
   taskless audit requires no content object. No new task event family is required. A v0.1 non-LLM
   `channel_unavailable` decision is pre-dispatch: it has no dispatch
   ID/time, request commitment, or network I/O and is distinguishable from an attempted or
   ambiguous transport failure.
   Backup pins the privacy-root generation/digest and carries a canonical structural audit sidecar
   plus every rooted encrypted object. Route move proves the complete current root set before CAS
   and invalidates nonterminal disclosure authority under the new owner generation; clean restore
   likewise preserves terminal evidence but restores no live disclosure authority.
   A dangling/tampered catalog root quarantines the audit row and fences content disclosure rather
   than being swept or repaired with an invented ledger row.
10. **Zero-egress definition:** true FinishUP zero-network egress is the composite policy state
    `profile=local_only`, `network_egress_permitted=false`, all five channels disabled, and no
    network-capable runtime path. The product default is **not** that state: it is `local_only`
    with structural `update_checks` permitted (opt-out) and no task-content egress. Zero-network
    for package identity checks requires the operator to disable `update_checks` (and therefore
    the ceiling when no other channel is on). In the true zero-network state the FinishUP-owned tested
    process set permits only the
    exact service/confidential AF_UNIX endpoints; a separately approved exact local-model AF_UNIX
    endpoint; and exact release-cell platform IPC needed for OS credential storage, user presence,
    or session-lifecycle security events.
    The last category includes measured Linux AF_UNIX routes to allowlisted session-bus Secret
    Service peers/methods and, separately, system-bus `org.freedesktop.login1` peers/methods, or
    measured macOS native security/presence/session notifications; it never permits
    arbitrary AF_UNIX, arbitrary bus names/methods, or a local proxy. FinishUP denies AF_INET, AF_INET6,
    DNS, proxies, redirects, external provider
    construction, telemetry, diagnostics upload, update checks, and capability calls. The
    `local_only` profile alone is not a zero-network claim because a separately authorized
    structural non-LLM row (today: `update_checks`) may raise the ceiling without enabling LLM
    disclosure; the remaining three non-LLM rows stay unsupported/off.
    Evidence names the exact platform/release profile, FinishUP service/client/confidential-helper
    processes, lifecycle interval from startup through `locked|ready` and tested operations, and
    allowlisted local IPC peers. It proves those FinishUP paths, not the ambient authority of the OS
    credential agent or a separately running model process; public wording is conditional on the
    resolved F-013 trust boundary.
11. **Setup is an application use case:** a wizard or UI reads effective policy and submits a
    proposed policy transition through the FinishUP use case. It cannot write configuration or policy
    storage directly. Its first question, `network_egress`, controls the global
    `network_egress_permitted` ceiling; answering yes still leaves all five channels denied until
    they are chosen independently. Setup explains concrete allowed/blocked examples, all five
    channel decisions, local-model permission, provider/endpoint binding, content categories,
    preview mode, telemetry, and scope. CLI and TUI derive an optional trusted workspace locator from
    their actual process working directory; the MCP bridge derives it from the configured/session
    working directory. The locator is never accepted from public or model-controlled
    `workspace_ref`. The service resolves symlinks, uses Git's canonical common repository root for
    Git workspaces and the resolved directory otherwise, creates an installation-keyed
    repository-privacy commitment, and immediately discards the raw path. Branches and linked
    worktrees therefore share authority; independent clones and unrelated repositories do not.
12. **Safe failure:** policy block, human denial/expiry, classifier uncertainty, scanner finding,
    provider refusal/timeout/invalid output, or audit failure cannot be treated as an AI-powered
    review success. For `semantic_required`, the check returns local-check results with
    `incomplete_check`; for optional AI-powered review work, the result records the exact gap and
    follows its local-check verdict rules. A request is never dispatched unless the audit
    reservation is durable, and success is never acknowledged unless its terminal receipt is
    durable. Waiting and approval remain resumable state rather than fake completed receipts.
13. **Useful review context remains user-controlled:** a closed `ReviewContextProfile` is stored
    independently from the four LLM-disclosure profiles. `structural` selects only typed metadata;
    `goal_aware` adds category-separated detail from the bounded accepted-event history frozen with
    the check; `assisted` adds bounded problem-local recorded evidence, test/failure, diff, and
    source excerpts; `expanded` and `custom` admit broader explicitly allowed recorded material.
    The history is capped at 64 newest material events and 512 KiB of canonical payload, with exact
    `not_recorded`, `not_selected`, and older-window accounting. Exact command text remains
    independently selected and is not part of `goal_aware` or `assisted`. Every selected item
    still passes category/class/scope policy, minimization, redaction, never-send scanning, provider
    binding, caps, authorization, and receipt. The selection profile grants neither live filesystem
    access nor permission beyond the effective privacy policy.
14. **Two defaults are intentionally different:** an unconfigured installation's durable seed is
    `local_only`, structural `update_checks` on (opt-out), other network channels off, global
    ceiling true only because update checks are on, and no local model. Config.toml generation-1
    remains fail-safe all-denied. When a technical user deliberately runs external AI-powered review
    setup, the upstream CLI recommends the inspectable `assisted` recipe for an exact endpoint
    profile with a current data-use record that states customer-content training `prohibited`,
    retention `none|bounded` with any bounded ceiling at most 30 days. Provider human-access posture
    and documented safety, support, legal, and abuse-monitoring exceptions remain prominent
    disclosure facts. Known-broad, unknown, or stale posture removes the badge. The recipe sets the
    editable `require_current_provider_data_use_evidence=true` runtime guard. A technical user may
    turn it off only through a trusted loosening/custom transition, after which the policy carries
    no upstream no-training recommendation. The user reviews and commits the expanded policy once.
    Within that standing exact-repository policy, checks, retries, reviewer challenges, agent
    responses, and rechecks run without per-request human prompts. `confirm_every_request` remains
    the optional high-ceremony alternative. A new repository proposal may need both to widen the
    machine ceiling and to insert the first repository row. Those changes are one transition bundle,
    one complete trusted preview, and one authority-digest-bound CAS commit; no intermediate state
    may authorize every repository. **Amendment (ADR-049, issue #1073, 2026-10-14):** the policy
    also carries the owner's `conversation_review` setting. A first AI-powered review grant made
    through setup carries `local_agent_opt_in` unless the owner answered otherwise: every task
    starts with local checks, and within the standing policy an agent's one `decision_recorded`
    1.1.0 switch turns AI-powered review on for that task without a per-request prompt.
    `local_owner_approval` restores a per-request decision for every such review, `local_only`
    refuses agent opt-in, and `ai_powered` is the behaviour above (every task reviewed). The
    setting never widens what may be sent; widening it is a trusted decision and narrowing it
    applies at once. A policy without the field keeps its bytes and reads as before.
15. **Structural subject-state hashing is a local non-disclosure support effect:** ADR-011 permits
    one explicit trusted local CLI command to read bounded Git/worktree bytes only into streaming
    hashers and return a versioned `SubjectStateRef`. It returns no source, diff, filename, path,
    branch, remote, Git output, or component digest; writes no ledger/audit row; opens no network;
    and cannot be invoked through MCP with an arbitrary path. Intermediate bytes are discarded
    before rendering. This narrow content-withholding fingerprint is not a local disclosure sink,
    does not authorize AI-powered review or live artifact inspection, and does not weaken
    never-send. An unsupported, partial, unsafe, changing, or over-limit capture returns no
    comparable state.
16. **Live harness observation retention (first-party Codex, ADR-010 amendment 2026-07-22):**
    Observation consent is independent of egress consent. One workspace-level confirmation records a
    private workspace commitment (never a raw path). The normalized workspace locator is an
    authenticated encrypted task object; plaintext state retains only its commitment and object
    identity. Locator normalization selects a safe Git root and performs lexical path cleanup; it
    does not apply Unicode normalization. The exact filesystem-encoded spelling feeds the
    commitment, so canonically equivalent names that identify distinct directories never share
    consent. A legacy grant under another spelling requires an explicit regrant. Revocation stops
    new ingestion, deactivates the locator and check-policy trust
    bindings, and retains already encrypted task evidence.

    Retain bounded task-relevant visible user/assistant/subagent messages, tool inputs/results,
    task-linked terminal results, selected changed-file/diff material, approved-check output,
    lifecycle structure, and composition readiness. Reject hidden reasoning, system/developer/
    platform prompts, credentials, detected secret spans, unrelated files, and ambient logs before
    persistence. Secret-bearing spans — including selected changed-file excerpts and
    approved-check output — are classified by the shared fail-closed scanner; high-confidence
    secret shapes are redacted in memory before encoding or authenticated encryption. Matches
    persist only redaction metadata, never the original bytes. Scanner failure, high-confidence
    finding-capacity exhaustion, or an explicit canary match records `content_capture_unavailable`
    and stores no excerpt or output object. Heuristic-only assignment matches stay in the
    encrypted local store and are redacted only at egress (amended 2026-10-07, issue #982).
    SQLite, observation envelopes, cursors, local outboxes, status, hook context, and logs contain
    only allowlisted structure, encrypted object identities/commitments, sizes, classifications,
    and relations. A locked vault, absent service, or failed encryption keeps the structural
    envelope with `content_capture_unavailable`; it never creates a plaintext fallback spool.

    This boundary protects stolen object files, SQLite files, backups, and copied local state when
    vault keys are unavailable, and tampering must fail authenticated decryption. It does **not**
    claim protection from root, kernel compromise, or a compromised same-user FinishUP/Codex process
    while the vault is unlocked; immutable Python buffers are not promised zeroized. Public copy
    must describe authenticated encryption at rest and secret exclusion, never “cannot be hacked”
    or absolute host immunity.

    Exact project check policy bytes propose no authority. One trusted-local confirmation binds the
    raw `.finishup/checks.toml` digest; any byte change suspends all listed commands. Approved checks
    use exact argv, `shell=False`, sanitized environment, bounded output/time, and an enforcing
    sandbox. Network-requiring checks fail closed unless a separately reviewed authorization and
    sandbox prove the permission. Output bytes pass the same fail-closed secret scanner before
    encryption; compound environment assignments such as `AWS_SECRET_ACCESS_KEY` and bounded
    `*_TOKEN` forms are redacted, while near-miss non-secret identifiers are left unchanged.
    AI-powered observation advice remains additive and passes only minimized approved packets
    through
    the existing privacy gateway. Observation, trust, verification management, and local advice
    diagnostics are local control, not network-egress channels and not additional MCP tools.

    **Revised 2026-08-30 (issue #302).** Secret-scanned and encrypted observation bytes may be
    materialized as ledger evidence only for the narrow ADR-020 eligibility set. That records byte
    identity, retention, redaction, and observation provenance; it does not authorize disclosure.
    Materialization never opens captured objects for AI-powered review. Any later description or
    typed digest metadata selected for an AI-powered review case still traverses this ADR's
    independent classification, policy, minimization, secret scan, authorization, and receipt path.
    Raw captured bytes remain unavailable to that path unless a separately designed, consented
    reader is added. Observation intake therefore cannot become implicit local or network egress.

17. **Repository authority migration is bounded narrowing, not package consent:** package upgrades
    preserve accepted machine-policy bytes. Catalog migration records only the pre-upgrade legacy
    route frontier and bounded entitlements; it does not infer repository identity from
    model-controlled workspace references. When an eligible legacy route next arrives with a trusted
    repository locator, the service atomically clones the accepted machine policy into that exact
    repository row, binds the route to the repository-privacy commitment, and consumes the entitlement.
    If there was no eligible legacy route, exactly one bounded first-repository carry-forward may do
    the same. This needs no new prompt because it narrows already accepted authority and never widens
    or rewrites the machine row. Later repositories inherit nothing. Fresh `local_only` installations
    enter repository-grant mode immediately; migration is a no-op for their disclosure authority.
    Repeated startup and replay are idempotent. Missing locators, older control shapes, stale authority
    digests, expiry, denial, crash rollback, or exhausted entitlements leave the prior rows unchanged
    and external LLM admission blocked.

18. **Project coordination stays local disclosure (2026-09-05, issue #494 / ADR-027):**
    A first-class `prj_` project is a grouping object, not a fifth egress scope. The
    `AuthorizationScopeKind` enum and `AuthorizationScope.contains()` relation remain the
    four-kind chain `machine → workspace → task → request`; project membership cannot widen
    egress authority. A fact enters local coordination only when its source workspace's own
    observation consent is active. General or cross-repository coordination additionally needs
    an explicit generation-bound coordination grant, checked at admission and delivery, while
    cross-repository semantic dispatch remains outside this series. This explains why project
    membership is not inserted into `privacy_policy_versions` or `privacy_audit_records` and why
    the existing never-send, category, provenance, and task-scope restrictions remain unchanged.

### Human involvement under the recommended recipe

An agent may guide the owner to a trusted ceremony but cannot stand in for it. Both a nonterminal
per-request decision and an explicitly reported missing standing repository grant use the exact
command carried by their distinct continuation kinds and preserve the original check request
identity. Repository setup uses the trusted CLI/TUI entrypoint `finishup --privacy`; the one-use
decision carries a proposal id and expiry. Recovery uses `status(view=operation)` or exact replay of
the original request, never a fresh check. Ordinary chat assent alone is never authority. The
delegated consent lane accepts only the user's explicit current-chat instruction relayed by an
allowlisted capable agent for one exact prepared, previewed, expiring target; denial, expiry,
cancellation, stale authority, or incomplete review remains pre-dispatch.

The repository continuation is permitted only after the trusted policy store returns a valid,
exactly bound authority whose observed `grant_state` is `missing`. The operation records that
suspension discriminator transactionally; status never infers it from later mutable authority.
Missing route commitment, unbound or mismatched identity, coordinator closure, policy failure,
invalid effective policy, unavailable reconciliation, and reconciliation failure are terminal
no-dispatch policy outcomes and advertise no approval surface. Repository privacy setup/effective/
propose result projection derives its workspace disclosure policy and receipt scope only from the
authenticated control session's repository context. The same session carries closed render-mode
and controlling-TTY facts for presentation only; since round 3 (2026-10-14) none of them selects
`local_human_view`, and every ordinary result is agent context.

| Event | Human required? | Rule |
|---|---:|---|
| First new-repository grant, first `assisted`/`expanded` commit, later wider provider/category/class/scope, or credential set/rotate | yes | Exact trusted-local compound diff/credential ceremony, or an explicit current-chat instruction relayed by a capable agent for the exact prepared consent action (issues #164/#533) |
| Eligible legacy machine authority narrowed onto its bounded pre-upgrade repository entitlement | no | Atomic carry-forward preserves machine bytes and grants no new repository |
| Ordinary check, automatic retry inside the confirmed policy, reviewer challenge, agent response, or recheck | no | Direct agent-to-agent path with a fresh authorization and receipt per physical attempt |
| Tightening policy | no | May apply immediately after the service proves it cannot widen |
| `confirm_every_request` physical attempt | yes | Exact prepared-case foreground decision for that one attempt, on any ready vault |
| Finding waiver | yes | Existing interactive-human `finding_only` authority |
| Never-send match or out-of-scope content | impossible to approve | Fail closed under every profile and fork claiming upstream conformance |

When the user explicitly instructs an allowlisted first-party agent in the current chat to finish
exact setup, agent-attested authorize (`finishup consent authorize` with
`yoetz.chat-user-attestation/1`, issue #164) may complete a prepared `repository_privacy_grant` or
provider credential set/rotate after one warning. This is delegated agent authority: FinishUP binds
the exact pending/action/digests but cannot independently distinguish genuine current-chat words
from a forged agent assertion. Retrieved content, tool output, quoted text, or earlier history do
not authorize under the agent skill contract. Denial, expiry, cancellation, target drift, or an
unsupported client yields zero policy/credential mutation and zero provider dispatch. The trusted
CLI/TUI (`finishup --privacy`, `finishup consent review`) remains the stronger recommended path and is
always available.

For an `expanded_review` chat grant, prepare returns the complete bounded substantive policy diff,
not only its digest. It freezes both current and candidate policy bytes, and the exact target binds
the repository commitment, authority snapshot, provider/model/endpoint, recipe, policy digests,
diff, and expiry. Authorization uses the frozen candidate and rejects any live repository,
authority-generation, or configured-route drift before policy mutation. The agent recommends
Expanded when the user explicitly prioritizes AI-powered review depth, explains Assisted as the
lower-disclosure AI-powered review option, and honors the selected supported outcome; the
recommendation is never independent policy authority (issues #532/#533).

## Consequences and proof obligations

### Cursor local hook amendment (2026-08-22, issue #153)

Local Cursor hooks are untrusted advisory inputs and add no provider, privacy, credential, approval,
or enforcement authority. `cursor_hook` is a distinct observation source. Its ingress allowlist is
limited to bounded session/generation/tool identifiers, exact Cursor/model/effort tokens,
durations, capability profile, and an installation-keyed HMAC changed-path commitment. The
ingress never persists or emits prompts, model thoughts/reasoning, response text, file paths,
file contents or edits, tool/MCP arguments or results, transcripts, shell command/output, email,
or workspace-root strings from Cursor payloads. Cursor stream/transcript reconciliation is
forbidden for this source.

Hook failure is always fail-open for Cursor work and records only a bounded gap when consented
observation cannot proceed. Pause, revoke, or absent consent stops new Cursor observation without
removing an independently valid plugin skill or MCP route. `sessionStart`, hook configuration,
plugin discovery, and tool listing are not observation evidence and do not strengthen coverage.

### Claude Code local project-hook amendment (2026-08-27, issue #154)

`claude_hook` is a distinct untrusted advisory source on local Claude Code CLI project sessions.
The native renderer registers only `SessionStart`, scoped-FinishUP `PostToolUse`, scoped-FinishUP
`PostToolUseFailure`, `Stop`, and `SessionEnd`; it never registers permission-changing, prompt,
agent, HTTP, or content-expansion hooks. The ingress accepts only the exact
`mcp__plugin_finishup_finishup__<workflow-operation>` names, a bounded session/correlation token,
closed lifecycle action, fixed capability-profile identity, and host-derived success bit.

Transcript/cwd/file paths, prompts, assistant messages, tool input/output, MCP results, raw errors,
commands, environment, permission mode, credentials, and all unknown fields are discarded before
the common observation boundary. No Claude content capture or transcript reconciliation exists.
Hook failure and the host's three-second timeout are fail-soft; declaration, delivery, consent, and
accepted evidence remain separate. Local-control schema `2.2.0` appends only the `claude_hook`
envelope/coverage row and retains `2.1.0` byte-for-byte for Cursor peers. Claude trust or plugin
enablement grants no FinishUP observation/egress/provider authority.

The privacy policy is more than an AI-powered review provider toggle and cannot be represented by
one `network=true` capability. Releases must prove the global ceiling; policy-intersection behavior;
valid `local_only` policies with one bounded but v0.1-unavailable non-LLM channel; channel
independence; agent-context and local-model fences; exact approval binding/restart behavior; no
secret-bearing configuration/environment/arguments; reviewed bundled-adapter composition (without
claiming OS sandbox isolation); keyed terminal-receipt commitments; the initial-reservation
no-receipt exception; FinishUP-process local-only AF_UNIX behavior without overclaiming a separate
model runtime; and no plaintext canaries across databases, objects, logs, traces, prompts, receipts,
errors, or transports. Public copy must reserve “zero network egress” for the composite
ceiling-plus-channel state, not infer it from `local_only` alone. The runtime plaintext release gate
binds one per-run synthetic canary to the privacy integration suite and retains that suite's
encrypted/structural state under the isolated XDG data tree. It then recursively scans only the
explicitly selected XDG data, config, cache, and runtime trees under the same fixed file,
aggregate-byte, member-count, and no-symlink caps as release evidence. A planted runtime-tree
negative control must be detected without exposing the canary, and the subsequent clean scan must
emit a nonempty canonical redacted report; a finding, missing surface, over-limit surface, or absent
report fails the release gate. The setup/conformance matrix additionally proves every
`ReviewContextProfile`, the recommended recipe expansion, problem-local selection, agent-context
delivery of reviewer findings, current provider data-use recommendation metadata, and automatic
no-prompt behavior after standing policy authorization. A data-use record is evidence for
recommendation wording, not technical proof of a provider's downstream behavior. Repository-identity
evidence additionally proves symlink normalization, Git-common-root sharing across branches and
linked worktrees, non-transferability to independent clones, and non-Git resolved-directory
behavior. Migration evidence proves bounded entitlement snapshot/consumption, the no-route one-time
carry-forward, exact replay, stale CAS, crash rollback, no machine-byte rewrite, and no prompt for
narrowing. A missing or mismatched grant must produce zero provider constructions, credential
handles, authorizations, and dispatch attempts. Raw paths must remain absent from policy/catalog
bytes, logs, receipts, errors, and agent projections.

Installed-wheel proof remains a separate acceptance gate: two consecutive real AI-powered checks in
one approved repository must show distinct one-use authorizations, credential handles, dispatch
identities, AI-powered review provenance, and terminal privacy receipts, while a second repository
remains blocked. Router downstream/fallback authority and issue #141's foreground disclosure
continuation remain out of scope for this decision. ADR-011 capability evidence additionally proves
structural capture is read-only, bounded, network-free, path/content withholding, fail-closed on
ambiguity, and incapable of strengthening publication/authorship/artifact-observation coverage.

## Vendor-runtime egress amendment (2026-08-30, issue #404)

`external_runtime_oauth` is still external task-content egress. Child-process transport does not
bypass classification, minimization, never-send scanning, composed machine/repository/task/request
policy, optional exact human review, one-use authorization, or the terminal privacy receipt. The
strict route and an unapproved repository both stop before runtime factory construction or child
launch.

Codex composes its upstream OpenAI request internally, so the gateway commitment covers the exact
final disclosed FinishUP case bytes at the boundary FinishUP controls. The terminal AI-powered review
provenance adds the exact runtime/launcher/config/instruction/schema/selection/output commitments
and states `upstream_body_observability=unavailable`. Neither the case digest nor its HMAC may be
labeled an upstream request-body digest. Receipt counts are zero when structural readiness fails
before case disclosure, even if a content-free account/model probe launched.

The external runtime receives a secret-free attempt authority, never a vault credential handle.
Once `turn/start` is acknowledged, any ambiguous transport/crash/restart result or unverified
process-group cleanup closes as `transport_failed/outcome_unknown`; its authorization remains
consumed and a fresh attempt is forbidden. Pre-acknowledgement retries are capped by ADR-006 and
each is a separate authorization, dispatch, process, and receipt. Runtime evidence retains no
credential path or bytes, email, raw account/workspace identity, prompt transcript, reasoning,
stderr, or event log.

## Fallback endpoint amendment (2026-09-04, issue #582)

The `llm_inference` channel row may carry `fallback_provider_binding`: a second exact five-field
`ProviderBinding`, external transport, that must differ from the primary and is valid only behind
an external primary. The row's authorized destinations are exactly the primary plus that one
fallback. Egress admits a candidate only when its binding is exactly one of the two — never a
prefix, wildcard, or provider-id match — and the registry admits each authorized binding on its
own, so a fallback whose factory is absent or fails to build is reported unavailable without
fencing the primary, and the reverse holds. Adding or changing the fallback is a widening of
exactly that destination and takes the ordinary propose → decide ceremony; the diff vocabulary
gains `("channel", "fallback_provider")`, rendered "Fallback provider and model" in the
Destination group right after the primary. Removing it is a tightening. Effective-policy
intersection keeps a fallback only when both scopes name the identical one; disagreement tightens
to the primary alone rather than disabling a channel both scopes allow. Policy JSON emits
`fallback_provider_binding` only when present, so single-endpoint policy digests are unchanged.
`finishup privacy setup` reads both bound endpoints and shows the fallback as "Fallback destination
(after the primary cannot serve)". Which endpoint an attempt reaches is decided by ADR-006's closed
engagement rule; this amendment only makes both destinations exact, approved, receipted, and
independently revocable.

The fallback binding is carried by privacy-policy schema 1.1.0. The released 1.0.0 schema remains
byte-identical; current policy readers accept existing 1.0.0 documents and current writers emit
1.1.0. This wire version change does not alter the canonical domain policy digest.

## Admitted-attempt reconciliation amendment (2026-09-17, issue #755)

Point 9's "post-consumption receipt failure stays `receipt_pending` until recovery records the real
attempt outcome" needed an actual recovery for the cancellation case. A foreground runtime rebind
may cancel an in-flight background advisory attempt. `asyncio.CancelledError` is a `BaseException`,
so it propagated past the gateway's admitted-attempt window, skipped the receipt entirely, and left
a consumed authorization `receipt_pending` with no caller anywhere invoking recovery. A physical
provider attempt could therefore complete with no terminal receipt in the audit catalog.

The reconciliation belongs in the gateway's admitted-attempt window, not in the advisory worker. A
dispatch receipt must carry the exact final application request body byte count and its keyed
`request_commitment`, and the audit deliberately retains no plaintext and no commitment before the
receipt exists, so the gateway is the only component that can construct the receipt the admitted
attempt owes. Accordingly:

1. Immediately after the consume CAS and before the provider call, the gateway builds the
   `transport_failed/outcome_unknown` receipt that attempt would owe and parks it beside the
   `receipt_pending` row through `PrivacyAuditPort.park_attempt_reconciliation`. Parking asserts no
   outcome: the row stays nonterminal, and a real result overwrites the parked material.
2. Cancellation inside that window records the parked receipt through a shielded `complete_egress`
   and then re-raises, so cancellation still propagates promptly and the rebind is never blocked
   beyond one bounded local write. Nothing re-enters the provider.
3. `PrivacyAuditPort.reconcile_started_attempts(consumed_before, limit)` is the bounded, idempotent
   startup sweep for rows whose dispatcher died before that write. It runs once, before any
   supervisor can admit a new physical attempt, and only over attempts consumed strictly before the
   current service start, so a live in-flight dispatch is never closed.
4. The advisory lane records provenance rather than authoring receipts.
   `PrivacyCoordinator.recover_started_request(request_id)` reports the terminal
   `SemanticEgressAttemptUnknown` for the exact request identity a cancelled dispatch minted — the
   cancelled dispatch never observes the prepared case digest — and the cancelled advice row stores
   that reservation plus the provider identity. A cancelled row without this provenance does not establish whether authority was consumed: a
   bounded reconciliation may itself time out or fail. Inspect the privacy audit for that attempt.

The invariant is unchanged and now holds: a consumed authorization ends in exactly one terminal
receipt. Local-sink (`local_disclosure_pending`) cancellation is not covered by this amendment.

**Atomic consume (2026-10-18, issue #1118 unit 1).** Point 1 left a window between the consume CAS
and the parking write: a crash there left a consumed row with no owed receipt. The gateway now
builds the owed `transport_failed/outcome_unknown` receipt before the consume and passes it as
`PrivacyAuditPort.consume(..., owed_receipt=)`; the catalog writes the `receipt_pending`
transition and the parked receipt in one transaction. A failure of that transaction consumes
nothing, so nothing is dispatched and no attempt receipt is owed. The separate
`park_attempt_reconciliation` port method is removed. Recovery (point 3) is unchanged.

## Task statement review section amendment (2026-09-30, issue #908)

The agent-transcribed task statement is different content from the agent's plan summary even
though both are `task_description`, so an approval given for the plan (`goal`) never covers it.

- Privacy-policy wire 1.2.0 adds the review section `task_statement` (the agent's transcription
  of the user's request, or the task title when none was supplied). Review presets are versioned
  with the wire: from 1.2.0 the `goal_aware`, `assisted` and `expanded` presets include it,
  `structural` never does, and `custom` only when its owner lists it.
- No silent widening: a policy approved under the 1.1.0 presets stays valid, keeps its exact
  1.1.0 bytes and digest, and sends no statement. Checks under it carry
  `task_statement_unavailable` with `task_statement_not_authorized`. Moving to a 1.2.0 preset is a
  `sections` widening, so it needs the trusted approval ceremony, whose screen says in fixed words
  that the agent's transcription of the user's request will be sent and that the host-captured
  prompt is not used. A 1.0.0/1.1.0 document that names the section is corrupt.
- `finishup --privacy` and the policy draft print whether the current and proposed policies send
  the task statement; `finishup privacy show` on a terminal adds the same sentence after the policy.
- The statement item passes the same classifier and never-send scanner as every other item and is
  bounded like one excerpt (16 KiB of canonical JSON, head and tail kept, elision marked).
- The host-captured user prompt (`host_captured_user_prompt`) is a reserved source. No path
  records it, captured prompt text never enters a packet, and the explicit, off-by-default
  prompt-capture choice under Expanded that it would need is not implemented yet; it remains on
  issue #908.

## Expanded excerpt count amendment (2026-09-30, issue #907 Phase 1b)

The Expanded preset approved 16 KiB per excerpt and 128 KiB of excerpts, but it also fixed the
count at 16, so the count bound every real review and the bytes never did. This amendment is folded
into the unreleased privacy-policy wire 1.2.0 (the #908 version), so one re-approval covers both.

- `MAX_REVIEW_EXCERPTS` is a protocol maximum of 64 that only bounds work. Wire 1.2.0 bounds
  `review_selection.max_excerpts` by it; wire 1.0.0/1.1.0 still bound it by 16
  (`PRE_1_2_MAX_EXCERPTS`). A selection with more than 16 excerpts can be expressed only as 1.2.0.
- The 1.2.0 `expanded` preset sets `max_excerpts` to 64. Its byte limits, the `assisted` preset (16)
  and the channel ceilings (262,144 bytes and 65,536 estimated tokens) do not change, so the approved
  byte budget binds instead of the count.
- No silent widening: an Expanded policy approved under the 1.1.0 preset keeps its exact bytes, its
  digest and its 16-excerpt limit. Moving to the 1.2.0 preset is a `max_excerpts` widening. The
  trusted ceremony shows it and says in fixed words that each excerpt still stays within the
  unchanged byte limits. A 1.0.0/1.1.0 document with more than 16 excerpts is corrupt, and a
  released boundary's 1.1.0 schema refuses the 1.2.0 Expanded document.
- The policy stays authoritative at egress. A prepared review packet with more `excerpt` rows,
  more bytes in one excerpt, or more excerpt bytes in total than the effective policy approved is
  never sent. *Amended 2026-10-27 (#1230):* egress first leaves out whole excerpts (see
  "Disclosure-time capacity fit" below) and refuses it as `blocked_by_policy` / `policy_denied`
  only when it still does not fit. An unreadable packet is refused. Resuming a stored proposal
  rechecks those limits and the channel `max_bytes` and `max_tokens` against the policy in force
  at resume and refuses, never shrinks, a proposal the owner may already have been shown.
- More excerpts must not turn a runnable review into a refused one. Before egress, the case is
  planned below the channel ceiling (`max_bytes`, `max_tokens` at the egress estimate, and never
  above the 262,144-byte disclosure bound, even when a ceiling is unset). If
  its prepared packet would exceed it, the case is rebuilt with a smaller excerpt byte budget: a
  narrowing, so it needs no consent. The dropped excerpts are disclosed as `content_unselected`.
  The planner sizes what the channel releases after local minimization, so items in a category or
  data class the destination withholds never cost an eligible excerpt its place.
  There are at most four rebuilds, the result is deterministic so a recovered review keeps its
  case digest, and egress still decides every dispatch.
- `finishup privacy show` on a terminal and `finishup --privacy` show the current limits beside those the
  current recipe offers. The policy draft prints the limits it would approve. The terminal
  interface says a newer version of the owner's recipe exists instead of "already recommended".
  `privacy show --json` does not carry the proposed limits: that would need a control-result
  schema change.
- The ceremony's count note says the byte limits are unchanged only when no byte limit widens on
  the same screen. Otherwise it points at the limits shown there.
- Way back: approving the earlier preset again (with `finishup privacy propose`, or by choosing Assisted
  in `finishup --privacy`) is a narrowing that needs no widening approval. An Expanded policy returned
  to the 1.1.0 preset encodes as the exact 1.1.0 bytes it had before.
- Token budgets and raised channel ceilings are not part of this amendment (issue #924).

## Heuristic secret matches amendment (2026-10-03, issues #920/#961)

The never-send floor remains absolute for concrete credentials, private-key markers, canaries, and
scanner uncertainty. The assignment detectors for names such as `token` and `secret` are a lower
confidence class because ordinary parser and authentication source uses those names. When a sink
policy permits a bounded transform, a heuristic-only span is replaced with `[REDACTED]` inside its
own item; the clean item identity and surrounding evidence remain available through the same
policy, authorization, final-body scan, and receipt path. The receipt records the redaction count
and original item digest separately from the transformed provider bytes. No matched bytes, source
prose, or raw detector output is exposed in the notice or receipt.

This behavior is identified by the `observability-sensitive-content-v3` scanner profile and its
recorded profile digest. Proposals persist that identity with their prepared bytes, so a resumed
outcome cannot present an older prepared case as if it had the new transform semantics; a new
evaluation uses the current profile.

This is a minimum-span transform, not an opt-out. A concrete credential in the same item or any
mixed case still blocks the whole case before provider construction. An ambiguous or untransformable
heuristic, a scanner finding-capacity/saturation condition, a scanner profile mismatch, a stale
policy or route, or a final rendered-body match fails closed. The final-body scan continues to
include the heuristic class as a backstop. A corrected check builds a new prepared case and may
include a directly targeted safe replacement; it never reuses prohibited bytes or silently carries
an old proposal into approved content. JSON/history items are redacted at their value span so the
structured payload remains parseable, while the original digest remains bound to the transformed
item. Recovery reports the bounded transformation or withholding identity without reconstructing
plaintext.
The public check result, CLI/TUI, MCP, hook-relayed response, and receipt projections carry the
same bounded class/reason. A receipt's secret scan records `candidate`, `prepared_case`, or
`rendered_body` only when that stage ran; `not_run` carries a closed reason and cannot be represented
as a clean passed scan.

The detector precision rule ignores only unquoted source expressions with syntax evidence: a
`const`/`let`/`var` declaration for a token call or member call, an explicit member assignment
such as `parser.token = Token.EOF`, a lower-case object property such as `token:
Token.ConstKeyword`, or a lower-case Python `token = node.token` assignment inside a valid
function. Bare dotted assignments such as `TOKEN=opaque.value` or `token=opaque.value`, call-shaped
values such as `password=functionName()`, quoted lookalikes, mixed-language text, and malformed
source remain heuristic matches. The owner-controlled privacy policy is unchanged. The deferred
heuristic opt-out remains out of scope here; the 2026-10-07 credential-heuristic opt-out amendment
below adds it.

Amendment (2026-10-07, issue #982, owner decision): keep raw data for local and deterministic
checks, redact only at egress, and narrow the heuristic. Capture and at-rest paths (hook content,
changed-file excerpts, approved-check output, Codex rollout import) redact only high-confidence
findings and still withhold on a canary, high-confidence saturation, or scanner failure;
heuristic-only matches are kept in the encrypted local store and every egress path re-scans and
replaces them. The assignment heuristics no longer match values that cannot be credential
material (comparisons, next-line keys, unquoted source expressions, literals and type names,
receiver attributes, documentation placeholders, and for `*token` names short, numeric,
digit-free identifier or non-token-character values). Markup, bracket and placeholder shapes are
judged for `*token` names only: a password, secret or API-key value skips the heuristic only for a
real source shape (a call or subscript on a name, `|>`) or a digit-free documentation placeholder
(`<your-api-key>`, `${MY_PASSWORD}`, `gw_...`), because human-chosen secrets take any punctuation
(adversarial review, 2026-10-07). Typed declarations (`password: str = "..."`) and JSON-escaped
keys (`\"password\": \"...\"`) are detected. Unquoted values stay greedy across encoded escapes so
a secret containing a backslash is never shortened. The exact rules are in `docs/INTERFACES.md`. Check-time change capture (ADR-031) is egress-shaped and keeps redacting
heuristic spans before storage.

## Partial withholding and encoding-stable redaction amendment (2026-10-06, issue #976)

TB4 run tb4f1 lost every implementation-stage review in two tasks to a FinishUP false positive: a
heuristic span redacted to `[REDACTED]` re-matched the token-assignment detector once the item was
JSON-encoded into the prepared case (`\n` became part of the "value"), and the prepared-bytes rescan
blocked the whole packet with `never_send_detected`. Decisions:

- The assignment detectors treat the JSON escapes `\n`, `\r` and `\t` as whitespace: an unquoted
  value ends at one and the separator may span one. A JSON-escaped quoted value (`\"…\"`) is a
  quoted value. The name/value separator is searched from the assignment name, so a JSON member's
  `:` is never read as the separator. The exact-marker exemption accepts `[REDACTED]` in any of
  these forms, so redaction is a fixed point across encoding. Real assignments in encoded text are
  still detected and redacted.
- Precision repair (2026-10-21, #1138): the exact fixed markers also remain exempt when the
  prepared packet is nested as JSON text in the final reviewer conversation. Whitespace escape
  widths must match the closing quote's encoding depth; literal backslash tails and other suffixes
  do not gain an exemption. Concrete-secret detection, policy, consent and egress authority stay
  unchanged.
- At egress, a low-confidence (heuristic) match replaces only the value, in place, with the fixed
  placeholder `[withheld-by-yoetz:possible-credential]` (`EGRESS_CREDENTIAL_PLACEHOLDER`); the rest
  of the line, item and file is still sent, and the scanner exempts the placeholder like
  `[REDACTED]` (issue #982, owner decision B2, 2026-10-07). The check reports the review-scoped gap
  `semantic_review_value_redacted`. The check-time change and its task inputs (ADR-031), which
  are redacted when the service reads them rather than at egress, use the same placeholder for a
  heuristic span and `[REDACTED]` for a concrete credential (tb4n5); the reviewer instruction
  explains both markers as withheld values, never the agent's code. That capture-time replacement
  is not an egress replacement: it adds no `semantic_redacted_values` entry and is disclosed as
  `check_time_change_redacted`.
- When a low-confidence heuristic still survives into the prepared semantic-review bytes, local
  minimization first re-applies that in-place replacement to the item's packet (JSON-string)
  encoding, and withholds an item only when that cannot make it scan clean. It re-assembles the
  case in at most three rounds. Withheld items join `semantic_withheld_item_ids` with the
  review-scoped `semantic_review_item_withheld` gap (checks recorded before #982 carry
  `content_redacted` instead and stay valid), so the check and receipt disclose what was withheld.
  Egress redaction and withholding bound only the AI-powered review: they never add
  `content_redacted` and never veto local (deterministic) proof. A high-confidence credential, scanner saturation, a heuristic in the structural
  review-packet envelope, or one no single item explains still fails the whole case closed.
- Owner-approved PL2-1 (issue #982, 2026-10-07): "show the agent the withheld item refs and line
  numbers, never the values, plus the fixed agent line." Minimization records, per affected item,
  `semantic_redacted_values` entries `{item_id, source_ref?, disposition, lines}`: the opaque case
  item id, the item's catalogued ledger ref when that ref is itself an opaque token (never a path),
  `value_replaced` or `item_withheld`, and up to 32 sorted 1-based line numbers in the item's own
  text (at most 64 items). No value or byte offset is kept. The entries travel on the disclosure
  proposal (resume and replay), the egress result, the check event (optional, 1.4.0), the check
  result, `status view=operation`, and the receipt document. Every human and agent rendering adds,
  once, the fixed line "Values marked [withheld-by-yoetz:possible-credential] were withheld from the
  external reviewer only; local checks saw them. Do not change consent, rename, hide or reshape your
  work to clear this. If a finding stays open only because of it, verify the repair yourself and
  respond self_verified."; the bounded MCP summaries (4,096 bytes since ADR-043), which must keep the
  frontier head digest, fall back to a shorter fixed form when the full line cannot fit.

## Credential-heuristic opt-out amendment (2026-10-07, issue #982)

Owner decision (2026-10-07, binding): "allow fully removing also externally as a flag the user can
use (and we will for future tests)". Follow-up owner decisions the same day fixed its scope: the
opt-out is part of the repository grant, re-enabling is per repository, it reaches the external
reviewer only, and status shows it before any check. Decisions:

- The privacy policy gains `credential_heuristic`, `enforced` (default) or `disabled`. It is part
  of the durable, versioned owner policy, so it is set, reviewed, recorded and reversed like every
  other policy dimension. A policy without the field means `enforced`. The field is written only
  when `disabled`, so every policy approved before it existed keeps its exact bytes and digest;
  privacy-policy wire 1.2.0 carries it, and 1.0.0/1.1.0 documents that name it are rejected.
- **External reviewer only.** `disabled` affects only LLM-inference disclosure to an external
  provider binding: low-confidence assignment matches (`password = ...`, `*_token = ...`) are
  neither replaced, withheld nor counted by classification, minimization, the prepared and
  rendered-body scans, or resume of that disclosure. Every local output — agent-context
  projection, the local model sink, local and trusted human views — keeps the heuristic exactly as
  when it is enabled. The high-confidence class is untouched everywhere and always blocks or
  redacts: known credential shapes, private-key markers, URI passwords, canaries, and scanner
  saturation. The applied setting travels explicitly from the effective policy through the
  classified context and the approved case to the gateway; there is no global switch.
- **Part of the repository grant.** Composition takes the setting from the current repository's
  own grant: a repository is "off" only where its own grant says off. The installation-wide row
  keeps a visible default that a new grant is drafted from; it is never a ceiling for this field,
  and a repository-bound proposal never moves it. Any other composition (two installation rows,
  or a narrower task or request row) keeps `enforced` unless both sides are `disabled`, so a
  narrower row can turn the filter back on but never off. Status, provider status and the
  terminal interface read one server-side derivation of the `repository`/`machine_default` pair;
  a repository without a grant reads `enforced` unless a pending migration would carry forward a
  disabled frontier, in which case it reports that outcome (or `unknown` when it depends on which
  task checks first).
- Turning it off is a widening (`global` / `credential_heuristic` in the policy diff) that applies
  only through the separately reauthenticated trusted-terminal decision; no MCP tool, hook or
  agent path can apply it. `finishup privacy credential-heuristic disable` proposes it on the current
  repository's grant; in a repository without a grant it walks the ordinary grant-creation
  ceremony with the filter off and records the setting in the grant the owner approves. It never
  creates a grant silently. `enable` is the symmetric reverse: a tightening of the current
  repository's grant that applies at once and touches no other repository. `--machine-default`
  changes the installation-wide default the same way (off needs the trusted decision, on applies
  at once). Desired-state TOML and `privacy propose`/`tighten` carry the same field through the
  same gates.
- Visibility: the status result (status-result 1.4.0, additive) carries `credential_heuristic`
  with the `repository` state and the `machine_default` (`enforced`, `disabled` or `unknown`),
  shown by MCP `status` and `finishup status` before any check runs; `finishup privacy show`,
  `finishup provider status` and the terminal interface name it when it is off. Every external
  disclosure receipt prepared under it records `secret_scan.credential_heuristic: disabled`
  (egress-receipt 1.1.0; omitted when enforced). Every check whose external AI-powered review ran
  under it carries the standing-limitation gap `semantic_review_credential_heuristic_disabled`. It
  is an owner disclosure choice, never agent work, and it weakens neither proof class.
- The behaviour is service-side and identical on Codex, Claude Code and Cursor.

## Egress receipt origin amendment (2026-10-08, issue #1019, tb4n2 N-5)

tb4n2 recorded recurring `blocked_by_policy` / `insufficient_approved_context` semantic-review
receipts on one `bounded_structural_metadata` item with no way to name the operation behind them.

- Every network egress receipt (egress-receipt 1.1.0, still unreleased, edited in place) may carry
  `origin_operation`, a closed token: `semantic_check` (an AI-powered review of a `check`),
  `observation_advice` (the background observation-advice supervisor, #619) or
  `credential_probe` (the credential ceremony's probe). It is derived, never asserted by a caller:
  from the purpose plus the reserved structural item id each producer puts in its case
  (`review-packet`, `observation-advice-packet`). An unrecognized shape omits the field, and a
  receipt stored before it keeps its exact bytes. `privacy receipts get/list` return it; 1.0.0
  receipts cannot carry it.
- The n2 receipts are `observation_advice`: its single advice packet is not a review-packet
  envelope, so the semantic-review assembly fails closed to insufficient approved context on every
  attempt. Suppressing those attempts, or admitting the advice packet, is a separate decision (a
  disclosure-shape change), recorded on issue #1019 and not made here.

## Automatic advice review and category-denial honesty amendment (2026-10-14, issue #1019)

Maintainer acknowledgement for this privacy/egress design gate: the owner explicitly requested
this scoped repair. The earlier #1019 observation-advice delivery defect is resolved by the
following shared service behavior; the original receipt-origin amendment above records the
historical failure, not the current delivery contract.

- The frozen minimized advice packet is offered as separately classified content inside the same
  `review-packet` envelope/catalog contract used by explicit `check`. The existing approved-item
  filter assembles `yoetz.review-packet-case/2`; no live repository, transcript or log is added.
  Producer-owned rule metadata and scoped gaps remain `bounded_structural_metadata`;
  `finding_summaries` are separate `finding_summary` content and never appear in the structural
  envelope. Only approved content is retained. A malformed packet, missing or denied envelope,
  or an assembly that loses the advice content fails closed. Packet digest and gaps must match
  the frozen attempt. Old pending rows with an unknown packet format remain fail closed.
- Advice uses a custom observation-only context with no cooperative ledger frontier or ledger
  citations. Its question and coverage name
  only the recorded observation facts and gaps; delivery is not a closing task check. The
  `observation-advice-packet` content marker takes precedence over the shared envelope marker
  when deriving `origin_operation`, including successful and blocked receipts.
- Predispatch receipts carry only categories actually denied by the classifier/category policy.
  Failure to assemble approved context does not deny its category: it reports
  `insufficient_approved_context`, zero included items and no category denial unless another item
  was actually denied. Scope, destination, channel and size refusals likewise preserve the actual
  request failure reason instead of declaring every candidate category denied. Approval counts
  describe classification, never provider delivery. Before classification, neither approval nor
  denial is asserted. `secret_scan.stage` still distinguishes an unrun scan from prepared scanning.
- The existing egress-receipt 1.1.0 fields carry these facts; no new reason or
  required field is introduced. Stored 1.0.0/1.1.0 receipts keep their exact bytes and remain readable;
  older overbroad category sets are historical assertions, not retroactively corrected facts.
- Codex, Claude Code and Cursor share this service path, on all supported platforms. Hooks only
  enqueue; background dispatch applies the same authority and category checks as CLI/MCP checks.
  CLI and terminal-interface privacy receipt inspection receive the same corrected network receipt.
  No host adapter, receipt agent-sink projection, or JSON/markdown/text task-receipt projection
  changes here; those overlap the privacy lane but are outside this repair. Verification uses an
  isolated service composition and fake provider, not live host sessions or model calls.

## Declared outputs outside the workspace amendment (2026-10-08, issue #1016, tb4n2 R7)

Owner decision (maintainer acknowledgement on #1016): a deliverable the task places outside the
repository (cargo-flight-dispatch's `/output/flight_plan.json`) must reach the AI-powered reviewer,
because the check-time change (ADR-031) only reads the repository and the reviewer otherwise cannot
see the work it is asked to judge. This widens what reaches a packet in practice, so it is recorded
here.

- Scope: evidence already in the case that records an obligation's requested `role: output` file or
  directory whose absolute path lies outside the session's workspace root: evidence whose own
  reference names the output, evidence of a result whose action lists the output among its
  attempted items, and per output the newest two content-bearing captures an effective claim on
  the declaring obligation cites; at most three rows per output (newest first) and eight per case,
  taken round-robin across outputs so one deliverable's repeats never crowd out another's. These
  rows rank with the current
  diff instead of competing with general tool output for excerpt room, and the content resolver
  reads their captures first.
- No new read path: FinishUP never opens the outside file itself. Only content a hook already captured
  under the session's content-capture consent, or text the agent published, can be carried. A
  declared input, a role-less item, a relative path and a task with no known workspace root select
  nothing.
- Same controls as every excerpt: only a recipe that includes targeted excerpts carries them; each
  part passes capture authentication, the partial-withholding redaction, the credential heuristic
  (unless the owner turned it off) and the non-overridable never-send scan. Opting out is the
  existing path: a Structural profile or a custom recipe without targeted excerpts, or content
  capture off for the host.
- Disclosure: carried rows are listed in the review input manifest and the egress receipt like any
  other excerpt; nothing new is hidden from the owner, and the behaviour is service-side and the
  same on Codex, Claude Code and Cursor.

### Background advice under preview-required policies (2026-10-14, issue #1019 round 2)

Maintainer acknowledgement: the owner requested this scoped follow-up to the amendment above.

- Background advice now actually sends the approved, minimized advice packet when external review
  is configured and the effective repository policy permits unattended disclosure. The background
  switch was already on by default; before #1019 an invalid envelope meant nothing was sent. This
  is a behaviour change, recorded in the changelog and release notes.
- Background advice has nobody to preview a packet and no continuation to resume. When the
  effective repository policy needs a human preview (profile `confirm_every_request`, which the
  metadata-only recipe selects, or an LLM channel with `preview_required`), admission skips advice
  with the typed reason `preview_required` (gap `advice_semantic_preview_required`). Nothing is
  queued, no disclosure proposal waits for the owner, no provider identity is recorded and no
  backoff accrues. A row queued before the policy changed closes as `authorization_missing` with no
  provider identity. As defence in depth, the egress pipeline refuses an `observation_advice`
  candidate under such a policy before classification, so its receipt asserts no category
  approval. Explicit checks keep their preview and resume ceremony unchanged.
- Per recipe: `private` sends nothing; `metadata_only` skips background advice; `assisted_review`,
  `expanded_review` and a custom policy without preview send only within the repository grant,
  allowed categories and review-context selection. The advice envelope names the effective
  review-context profile, and finding-summary prose is offered only when that profile's selection
  includes finding prose (never under `structural`).
- A refused request can still carry classification approvals in `approved_categories` and
  `counts.approved_items`. The released receipt shape is closed, so the CLI's human rendering of
  privacy receipts adds a `not sent:` line for network receipts that never reached a provider;
  `--json` and the wire are unchanged.
- Shared service behaviour for Codex, Claude Code and Cursor on macOS, Linux and Windows through
  WSL 2. No migration: the skip writes no row, and a race closes with an existing reason.

Round 3 (same day, same issue): a preview switch that lands after the service's own read (while
the coordinator prepares the packet, or at its final repository-authority check) is refused by the
egress pipeline as `scope_mismatch` or `policy_denied`. The advice row is now mapped from that typed
pre-dispatch refusal, not from the configured binding: `unavailable` / `authorization_missing`, no
provider identity, the privacy record linked, no session provider-rate charge and only the base
retry. Only `outcome_unknown` keeps the provider identity. The coordinator also refuses an advice
candidate built for a review-context profile that is no longer in force (`scope_mismatch`); the
next admission rebuilds it from the current profile. The gateway's own consume fence for a switch
after authorization is unchanged and not re-tested here (the provider gateway is faked).

### Observed command output in a verification follow-up (2026-10-15, issue #1079)

Maintainer acknowledgement: auto-supply of captured verification output is approved for this
design-gated privacy change, and only on the terms below.

When an AI-powered review returns `missing_for_assessment` for `verification_output`, a follow-up
packet may include hook-captured output of a command the named targets ran. The bytes are the
newest readable run of that command. A readable command action that no readable result cites
occupies the command, so a tombstoned newest result does not fall back to an older capture. A
tombstoned action has no command text left and cannot occupy a key. A command with no run key
(`omitted:structural`) is not auto-supplied. Native keyed `omitted:` actions qualify only
when the service authenticates complete, unredacted post-tool input and output from the same
capture phase, binds the envelope's keyed command identity to the action, and runs all gates
below on that input. Native hooks retain this input locally under the existing capture consent
and aggregate byte budget; it is eligibility context and never a provider excerpt. Missing,
truncated, redacted, pre-tool, or differently bound input fails closed. Older captures without
this context remain withheld; no agent assertion can substitute for it.
Plaintext action commands also remain ineligible for auto-supply: their text is
agent-writable and cannot authenticate the command that produced a captured output.
The task ledger stores only the keyed command identity, closed outcome metadata,
object/evidence references, content digests and byte/part counts. The new post-tool
input is encrypted local capture material, not raw command text in the ledger;
it uses the same capture consent, redaction and retention limits as other native input.
Capture-redacted output is withheld as a whole. The disclosure scan also examines decoded
string values inside native JSON results (including exec envelopes with numeric timing fields),
so JSON escaping cannot hide a secret hit. Unsupported encoding depth or scan capacity fails
closed; this changes no provider byte budget.

The item is sent only when every gate below passes. It is one repository excerpt, inside the
existing per-excerpt and total excerpt limits. This does not widen consent or add authority.
Private, and any selection that would not already send a repository excerpt, sends nothing. A
channel that withholds `repository_excerpt` drops the item. Output of a command the targets do
not name is never included. The packet labels the excerpt as observed capture, not an
agent-published result. Hook capture still does not count as the agent having supplied the
missing item. A refused capture is not sent as a raw evidence excerpt either.

- The command must already class as test, build, lint, or typecheck (`command_is_verification`,
  the same classes `command_runner_class` uses). A compound is included only when that
  classifier's strongest class is one of those four. Anything else, including a `cat` or a file
  read, is withheld whole.
- An environment dump is withheld whole, including when it is composed with a verifier
  (`pytest -q; printenv`). The dump shapes are `printenv`, `export -p`, `declare -p`,
  `typeset -p`, `set` with no arguments or only `-o` / `+o` / `-p`, a bare `env` (assignments
  and options, and no command after them), and any `/proc/<self-or-pid>/environ` operand.
  `env pytest` runs pytest and is not a dump. `set -e` is not a dump.
- A path operand is withheld whole when a repository excerpt would withhold it: a credential
  file name (the same names as the check-time change), an absolute path outside the workspace
  (or any absolute path when the workspace root is unknown), a `..` or `.git` component, or a
  path the frozen check-time change marked `not shown` or as a nested repository whose own
  change was not read (including a parent of that nested prefix). The program path
  (`/usr/bin/pytest`) is the tool, not a repository file. Wrapper directory options (`-C`,
  `--chdir`, `--directory`) and redirection targets count as paths. This gate does not call
  Git. Gitignored paths are absent from the frozen change, so a verifier that names an unlisted
  ignored path, and whose output the scan below does not hit, can still be sent.
- The output then takes the check-time change scan (`redact_sensitive_content`, heuristics
  included) plus a private-key END line or OpenSSH key-body check. The capture store only
  replaces a BEGIN banner, so those two are checked here. Any hit drops the whole item. A
  partly redacted capture is not sent. A value the scan does not recognise (for example
  `DB_PASS=`) is not a hit by itself.

A class, dump, or path withhold is omission reason `withheld_by_policy` and gap
`content_unselected`. A high-confidence secret, a private-key body or END line, or a scanner
failure is `redacted_never_send` and gap `content_redacted`. A heuristic-only hit is
`never_send_heuristic` and the same gap. An item that does not fit the excerpt budget is
`not_selected` and gap `content_unselected`. Older output held back because a newer run is a
redacted occupancy is `withheld_by_policy` and gap `content_unselected`.

### Resolved criterion, shown as one question (2026-10-15, issue #1079)

A resolved obligation's packet item gains `resolved_basis`: the result refs its resolution
already cites, the newest hook-captured verification refs of those results, and closed
`missing_input` tokens when either is not readable. The criterion remains the obligation text
in that same item. The basis copies no summary, command, or path, and it does not add a
category or raise a ceiling. A channel that withholds obligation text withholds the basis with
it. Private sends nothing.

### Published answers in the next packet (2026-10-15, issue #1079)

When the agent publishes material that answers a still-pending `missing_for_assessment` item, the
next review packet carries that material inside the existing excerpt budgets. A result summary is
added only when the effective selection already allows an evidence or test excerpt, only for a
result `supplied_since` already counts (agent-published, tied to the named target), and only up to
the existing per-excerpt and total limits. It is an evidence excerpt, the category a failure
summary already uses. It does not widen consent, add a category, or raise a ceiling. A summary
that does not fit is omitted and the omission is reported. Private sends nothing. Output the
request does not name is not added.

## Reviewer packets carry the specification, the oracle and admitted outside inputs (2026-10-16, issue #1082)

Maintainer approved 2026-10-16: rewrite reviewer instructions (pstack style) and make reviewer
packets sufficient, including outside-workspace inputs within existing privacy policy. The N6
D-lane audit found 99 of 196 reviews ended `insufficient_packet`, and reviewers kept asking for
the same three things: the controlling specification, each obligation's deliverables, and the
latest real verification with its assertions.

Every change below stays inside the owner's existing ceilings. No category is added, no
selection or channel ceiling is raised, the round cap is unchanged, and Private sends nothing.

- **Specification first.** Read-only task inputs (ADR-031) rank ahead of the check-time change,
  within a quarter of the packet's excerpt budget. The first offer is bounded in slots too: it
  leaves the change the slots its reservation would use and two slots per decisive verification
  run (the latest run, or each run a follow-up asked for), so small inputs never take the room of
  the change and the run that decides it. An input that does not fit is skipped rather than
  stopping smaller ones; it still backfills after every other excerpt. *Amended 2026-10-18 (n7
  RC6e, issue #1108; ADR-031 amendment of that date): the change now takes its reserved share of
  the packet's own budget first, and the inputs then take at most an eighth of it, never the bytes
  held back for the decisive verification output beyond the first input's own need; an input
  larger than the room left arrives as its head and tail, disclosed as truncated, while at least
  2 KiB of that room remains, and otherwise waits for the backfill. Shares and order change inside the same budget; no
  category, selection or ceiling changes.*
- **The oracle.** A file a recorded verification command names (a test, a fixture, a harness
  script) is a candidate task input. The same repository rule decides whether it is read: inside
  the repository, unchanged since the task started, not ignored, not credential-named. A test the
  agent wrote or changed is therefore never read this way; it is in the change. The command text is
  the agent's record, so it only selects candidates and never authenticates output.
- **Deliverables named in prose.** A requested `change` item that names files in its text orders
  those files after every literal declaration. This orders the check-time change only.
- **Summaries, never bytes, of binary inputs in the packet.** A binary, image or data input that was skipped
  before becomes FinishUP's own bounded summary (format, size, digest, dimensions, page estimate,
  workbook sheet names and first rows, archive member names, array dtype and shape), at most
  16 KiB, labelled as FinishUP's description and never as the file. A file whose leading bytes
  carry a signature the summarizer recognizes is summarized whether or not it holds a NUL byte (an
  all-ASCII PDF holds none); a `%PDF-` header after other bytes counts only beside PDF object
  structure. An untracked text input too large to read whole keeps its head and its last 8 KiB.
  Summaries and ends take the same redaction as any task input.
- **No cut before the scan.** A cut can leave a fragment of a credential too short for any later
  scan to recognize, so nothing is cut before the shared scanner has seen it whole. Each value a
  summary quotes (a cell, a shared string, a sheet or member name, a paragraph) is scanned whole,
  as read and as normalized, before it is capped; a flagged value is quoted only as `[REDACTED]`
  or `[withheld-by-yoetz:possible-credential]`, whatever the owner's possible-credential opt-out
  says, and the input is marked redacted so the review discloses it. The summary's byte caps drop
  whole lines, never part of one. The head and tail cuts of a long text move clear of any
  recognized credential before the text is cut, and the tail is read with 4 KiB more before it
  for that purpose. The final redaction pass and the egress scan still run on everything.
- **Admitted outside-workspace inputs.** The never-send set excludes files outside the selected
  scope. A repository's grant can now widen that scope by naming directories:
  `PrivacyPolicy.admitted_input_roots`, at most eight absolute, normalized paths with no hidden
  component, never `/` and never beneath `/boot`, `/dev`, `/etc`, `/proc`, `/run`, `/sys`,
  `/var/run` or their `/private` forms. The field is written only when set, so every earlier
  policy keeps its bytes and digest (privacy-policy 1.2.0 gains the optional property).
  - The way in is `finishup privacy input-roots add <dir>`. The directory must exist and be named
    by its real path. Adding a root is a widening: it needs an existing grant, an interactive
    terminal and the separately reauthenticated trusted decision, whose screen lists the
    directories under "Information disclosed". No agent can admit a root.
  - The way out is `finishup privacy input-roots remove <dir>`, a tightening that applies at once.
    `finishup privacy input-roots status`, `finishup privacy show` and the terminal interface show
    the admitted roots.
  - Composition: the repository grant decides between the installation row and a repository row;
    the installation row cannot admit a root for every repository. Any other composition keeps
    only the roots both sides admit.
  - The read happens only when the recipe already carries task inputs (the change, the statement
    and the `repository` excerpt kind). Only an absolute path the task statement or a `role: input`
    item names, lexically beneath an admitted root and outside the workspace, is read. A path only
    an agent-recorded verification command names is never read outside the workspace: an admitted
    directory is not consent to read every file an agent mentions. A named directory offers its
    visible files, two levels deep, in name order.
  - The root must still be its own real path, and it is opened one component at a time from `/`,
    each from the previous descriptor without following a link, so no ancestor can be swapped for
    a link between a check and the open; the path must still name the directory opened. Every
    directory on the way, the root's ancestors included, and every directory beneath it that is
    entered must be owned by the service user or by root and writable by no other account, unless
    it is sticky (`/tmp`). Group write counts as another account's unless the group is the
    owner's user-private group (`writable_by_others`, the rule used everywhere else).
  - The workspace and the service's own bundle and state directories are never read this way,
    even beneath an admitted root that contains them: they are refused by case-folded path and by
    device and inode at every level of every walk, so neither an enumeration of a containing
    directory nor a differently spelled path (a case alias on a case-insensitive file system, a
    bind mount) re-enters them, and every file the reader returns is checked again. Only the
    repository read can prove a workspace file unchanged since the task started and not ignored.
  - Hidden and credential-named files are refused; only singly linked regular files owned by the
    service user or by root that no other account may write are read; at most four inputs in all,
    sixteen candidates and five seconds per check.
  - The bytes take the same redaction as every task input, leave as `repository_excerpt` items
    labelled "outside the workspace beneath a root the owner admitted", and pass the gateway and
    never-send scan. A channel that withholds `repository_excerpt` drops them.
  - Every outside read ends by checking that the file's identity, size, mtime, ctime, mode, owner
    and link count did not change and that its name still leads to it; otherwise nothing is
    returned (issue #1118 review R6). A task-input snapshot (ADR-031 #1118 amendment) uses the
    same roots, walk and checks. It reads nothing when the owner's conversation setting is
    `local_only`, when neither the inference channel nor a separately enabled local model admits
    ordinary `repository_excerpt` content, or when the recipe carries no task inputs: no file is
    read to prepare a review that could not send it.
  - Removal wins over bytes already read (issue #1118 unit 1, E2E-2). Each outside item keeps the
    root it was read beneath, from the capture (or the ADR-031 snapshot) through the case to the
    privacy candidate (`CandidateContextItem.input_root`). The coordinator refuses an item whose
    root the deciding policy no longer admits, so a root removed after capture but before
    admission blocks that item in a fresh, recovered or cached case. The approved case carries
    the included items' roots (`input_roots`), and the gateway checks them against its current
    registry while holding the lock policy mutation holds, immediately before the consume, on the
    external route and on the local-model route, whose consume now runs under that same lock.
    A removal that commits first stops the dispatch; one that commits after the consume is
    ordered after an admitted attempt that FinishUP cannot recall. Later reviewer reads and
    continuation history must carry the same bindings through the same check.
- **Captured bytes behind a digest-only row.** When an agent records a run's output as a
  digest-only evidence row, a hook already captured bytes with that exact SHA-256, and both rows
  record the same verification run (the same result of the same command identity), the capture's
  excerpt also answers to the agent's row. A digest proves byte equality, never who ran which
  command: a row bound to no run, to another command or to another run of the same command is not
  aliased, so a caller's assertion never makes a capture answer for a run it did not record, nor
  lends it that run's freshness or a request's completion. Nothing new is read or sent; a withheld
  row never matches.
- **Redundant captured edits yield.** A captured edit of only files the admitted check-time
  change parts show whole is ranked as an older edit superseded by `check-time-change`, so the
  latest verification output takes that room first. The edit is still offered after it.
- **Supplied summaries.** The reviewer is told that an `excerpt-supplied-` item is the agent's
  account of a run, not FinishUP's capture of it: it judges the summary as that account against
  the code and any captured output, never as support alone, but does not list its
  verification-output request again only because the answer is a summary. FinishUP's own remedy
  for that request asks for a `result_recorded` summary, so an agent that follows it is not sent
  back for a second `insufficient_packet` only because it followed that remedy (the reviewer is
  advisory and may still list the item again for a real reason, such as a summary that contradicts
  the code; issue #1094 round-3 note). The #1079 published-answers behaviour is otherwise
  unchanged. Since the n7 amendment (issue #1108) the rule applies wherever a supplied answer
  arrives, not only in an in-check follow-up, and observed output, the check-time change or a file
  answering the same request outranks the summary as the witness.
- **Extra room, bounded.** Decisive material gets room by rank and by reclaiming duplicate edit
  bytes, never by exceeding the recipe's excerpt total (at most 128 KiB), the channel's prepared
  ceiling (at most 256 KiB) or the follow-up share (half the excerpt total across all rounds). A
  complementary second packet is not added: one would repeat roughly the 109k-token native review
  footprint and about 26 s of provider time per review (N6 medians), and it needs its own design.
- **Not done here: a local copy of each outbound packet.** Every dispatch already binds its exact
  request body: the privacy receipt's `request_commitment` is a keyed MAC over it and the attempt
  binding carries its SHA-256. A consent-gated encrypted copy, or a service-side rebuild verified
  against those values, needs an audit-store record and a read operation; it is tracked in #1085
  rather than written to logs, which this ADR forbids.

The behaviour is service-side and identical for Codex, Claude Code and Cursor on macOS, Linux and
Windows through WSL 2.

### 2026-10-23 amendment — explicit image disclosure (#1203)

The existing text/binary-summary permission grants no pixels. A current owner-approved LLM policy
must additionally allow `semantic-review-images` for the same bound destination and scope before a
small PNG/JPEG can accompany an existing admitted reviewer read. Original bytes and exact encoded
content pass admission/scanning; image history retains that purpose and root fence on subsequent
turns. Defaults remain off. Scanning covers raw bytes and metadata, not OCR of visible image text;
the owner must choose whether those pixels may be sent. Detected never-send content stays blocked.
No runtime grant is implied by developing or installing this capability. Bounds, format translation
and refusals are specified in [INTERFACES](../INTERFACES.md#reviewer-completion-exchanges-issue-1118-unit-3-adr-006).

## Task-named directories, quoted paths, `other` follow-ups and unadmitted outside inputs (2026-10-18, issue #1102)

The owner confirmed the n7 decisions for RC6d, f and g in session on 2026-10-18, including the
`other` answers and the coverage-note-only handling of outside inputs; #1102 records them. They
change what reaches the reviewer without adding an egress class, raising a ceiling, or adding a way to
admit a root. ADR-031's amendment of the same date holds the read; ADR-006's holds `other`.

- **A directory the task names inside the repository** contributes FinishUP's own listing of its
  unchanged files and, in the room the four-input bound leaves, the members sharing the most
  identifiers with the change. Every member passes the issue #1045 proof (unchanged since the task
  started, not ignored, not hidden or credential-named, not in a nested repository, singly linked,
  reached without a link) and leaves as a `repository_excerpt` labelled as chosen by FinishUP. A
  channel that withholds `repository_excerpt`, and every recipe that does not carry task inputs,
  sends none of it.
- **A quoted or escaped path with spaces** is one candidate; the same rules then decide it. When
  only the disk can tell a spaced folder from prose (`"/app/test data"`, `"/app/config is
  read-only"`), the whole value comes first and its words follow; the read looks at the whole
  value's metadata where it may read at all (inside the repository, or beneath an admitted root)
  and drops those words when it names something, so a folder one of its words names is never read
  under the task's name. Only words that came solely from splitting the quoted value are dropped:
  a path the task also names on its own, a `role: input` item or a verification operand is kept.
- **An outside directory named without its trailing `/`** is listed like one named with it, still
  only beneath an admitted root and only when the task itself names it. Known limit: a file read
  from such a listing keeps the `outside_workspace` label ("named by the task, outside the
  workspace beneath a root the owner admitted") although only its folder was named, as a file
  listed beneath a folder named with its `/` already did under issue #1082; the label still names
  the admitted root that bounds it.
- **An unadmitted outside input is named, never admitted.** FinishUP adds no unattended or
  non-interactive way to admit a root, and no pre-admission for a harness: admission stays the
  owner's `finishup privacy input-roots add <dir>` ceremony on a trusted terminal. When the task
  names an existing file or folder outside the workspace that no admitted root covers, the check
  records the closed code `task_input_outside_not_admitted`. To tell an input from a route or an
  output, the check-time read `lstat`s each such path the task names (metadata only, never a final
  link, never content) and counts it only when a regular file or directory is there that predates
  the task (ADR-031 #1102 item 5); that local look reads nothing beneath the path, and the one bit
  it yields is the only thing that leaves. The code's fixed sentence names the owner's step with a
  `<folder>` placeholder; the code carries no path, the agent (which holds the statement) names the
  folder to the owner, and copying the file into the workspace does not make it a task input. It
  is a disclosure only: never agent work, never a Stop-gate item or closure blocker. A
  non-interactive harness can admit roots only through an owner-attended ceremony while it is
  provisioned.
- **`other` follow-ups** carry only rows FinishUP recorded, hook-observed output of a named
  verification run and current change sections of a named edit, under every gate of the
  2026-10-15 amendment above.

The behaviour is service-side and identical for Codex, Claude Code and Cursor on macOS, Linux and
Windows through WSL 2.

## The reviewer may read the agent's declared test files (2026-10-25, issue #1220)

Maintainer approved on 2026-10-25 (#1220, option "Declared file only, scanned"): a scanned excerpt
of a test file the agent itself declared may reach the reviewer, even outside the workspace. This
narrows the 2026-10-16 rule that an agent-mentioned path is never read outside the workspace for
exactly one kind of path: the `test_file` of the agent's own `result_recorded` manifest. It adds
no way to admit a root, no unattended consent and no policy field.

- **What may leave.** The packet lists at most three declared test paths with the SHA-256 FinishUP
  observed when the check ran and a criterion ref: structural metadata in the envelope, never file
  content. The content leaves only when the reviewer asks for it with `read_file` beneath `t1`,
  as a span of at most 4,096 bytes per read, within the existing three reads and 24 KiB.
- **Which files.** Only a listed path, refused by shape before any probe: an empty, `.`, `..` or
  hidden component, a backslash or control character, a credential-named component, a path longer
  than 256 bytes, a path the shared sensitive-content scanner flags (it would travel in the
  envelope), or anything beneath `/boot`, `/dev`, `/etc`, `/proc`, `/run`, `/sys`, `/var/run` or
  their `/private` forms. The read is the outside read's walk from `/`, every directory and the
  file passing the same trust test (owned by the service user or root, writable by no other
  account unless sticky), with FinishUP's own bundle and state directories excluded by path and by
  device and inode. The system directories and the home directory's private trees and files
  are refused by spelling (case-folded too) and by identity (PR #1221 review): each ancestor of
  the path is examined without following a link and compared by device and inode with the system
  directories and with the home directory, so `/ETC/…` or `/Users/ALICE/Library/…` on a
  case-insensitive volume, or a bind mount, is refused like the canonical spelling; a directory
  beneath home whose name folds to a private tree's is judged as that tree when both spellings
  are the same directory. An ancestor that cannot be examined refuses the path. A
  top-level link that root owns (`/tmp` and `/var` on macOS) is replaced by its target; no other
  link is followed. Only UTF-8 text without NUL, at most 1 MiB, is read; the workspace's ignore
  rules do not apply to a file the agent declared.
- **Hash pin.** Every read re-reads the file and is refused (`declared_test_changed`) unless its
  bytes still match the listed digest; nothing of a changed file is sent.
- **Scanning.** The span passes the same admission as any reviewer read: classification,
  minimization, the never-send scan and the credential heuristic per the owner's setting, then the
  exact result envelope's scan. Any hit withholds the whole read (`privacy_withheld`).
- **When.** Only when AI-powered review runs, the review offers reads (never under ask-every-time),
  the policy offers `read_file` at all (repository excerpts not withheld, a workspace, the home
  rule), and a reviewer read of repository content is admissible on every destination of the
  review (`reviewer_history_admissible` with `repository_excerpt` and ordinary user content, the
  primary and any fallback). Otherwise nothing is listed and the review is the one it was before.
  Removing `repository_excerpt` from the channel stops it, as for any file read: an already
  admitted read joins the conversation's retained categories and the next exchange is refused.
- **Category.** `declared_test_excerpt` is a receipt-only `DataCategory`. The read is admitted
  under `repository_excerpt` (the same grant and ceilings as a workspace read), and every
  exchange that carries a declared-test read lists `declared_test_excerpt` among its receipt's
  `approved_categories`, so the receipt shows the disclosure distinctly. No privacy policy names
  it: a policy category set is read without it (`tuple(DataCategory)` keeps meaning every
  grantable category), so every policy keeps its bytes, digest and schema; the privacy-policy
  schemas are unchanged. egress-receipt 1.1.0 (unreleased) gains its own receipt category set in
  place; 1.0.0 is unchanged.
- **Limit.** A listed test that is gone, unreadable or no longer text is
  `declared_test_not_visible`, with a fixed continuation telling the reviewer to judge without it
  and say it was not visible. Owners who allow repository excerpts to the reviewer cannot turn off
  declared-test reads separately; turning off AI-powered review, withholding repository excerpts
  or ask-every-time does.

The behaviour is service-side and identical for Codex, Claude Code and Cursor on macOS, Linux and
Windows through WSL 2.

## Disclosure-time capacity fit (*Amended 2026-10-27, #1230*)

**Context.** In TB4 rv16 both AI-powered reviews of one attempt failed `case_capacity_exceeded`
before any model exchange. Composition had cut a task input to exactly the 16,384-byte per-excerpt
limit, measured as written. Egress then replaced one short credential-like value in it with the
fixed 39-byte `[withheld-by-yoetz:possible-credential]` placeholder (value redaction, #982) and
measured the minimized row: 16,402 bytes. Egress refused the whole packet and nothing recovered.

**Decision.**

- **One measure.** `semantic_disclosed_bytes` (`observability/privacy.py`) is the largest size an
  item can have in any form egress minimization may send it in: as written, with its values
  replaced, or with values replaced in its JSON-string encoding. Content without a credential-like
  value measures exactly its length. Composition cuts each excerpt so this measure fits the
  per-excerpt limit (the cut uses the ordinary elision marker and is disclosed like any clip to the
  item limit). It rebuilds with a narrower excerpt budget when the measured excerpt total exceeds
  the approved total. Ceiling planning measures the payload in its largest disclosed shape,
  including each replaced row's `redacted` transformation. A composed case therefore fits every
  per-excerpt, total and exchange bound once its values are replaced.
- **Redact, then cut.** A cut can drop a label (`password =`) and keep the value it made
  detectable, where no scan of the cut text sees it. So every composition cut (a head-and-tail
  clip, a captured diff split into parts, a part cut again to its disclosed size, a clipped prose
  field) is taken from the whole text with every detected value already replaced
  (`redact_before_cut`), never from the raw text; the egress scan then checks what is sent as
  usual. Text the bounded passes cannot redact in full (more values than the scanner reports
  across them) is never cut from: the cut reads a fixed FinishUP line instead (fail closed). A cut
  of replaced text has no exact place in its source, so it places no bytes there and
  never reads as showing its source whole (`SemanticCase.unplaced_item_ids`); a captured diff
  split from replaced text is placed in that text and reads as truncated.
- **Leave out, then refuse.** If a semantic packet still exceeds an approved excerpt limit or the
  exchange's byte or token bound at disclosure (for example, the owner narrowed the limits after
  composition), egress leaves out whole excerpts instead of failing the review; it never cuts an
  excerpt at disclosure. An excerpt over the per-excerpt limit is left out, and excess excerpts or
  bytes are shed from the lowest-ranked excerpt up, in the packet's `targeted_excerpts` order. The
  service's check-time change and the change sections a follow-up served are never left out: they
  are what the shown-file record (ADR-031) counts, and no fit trades the change under review for a
  dispatch. The narrowed approval is minimized and scanned again in full. Shedding never raises an
  approved limit and never changes consent or privacy rules. When the excess cannot be shed that
  way (it is fixed material, or would need the change), nothing is shed and the packet is refused
  as before.
- **Disclosed as room, by item identity.** A left-out excerpt becomes a `not_selected` omission row
  of the sent packet naming only its own source, never a linked claim: room, not a privacy
  withholding, even when it held a replaceable value. Its input-manifest section drops it by item
  id, names its source in `omitted_refs` with `not_selected`, and reads `partial` (or
  `not_selected` when nothing of it is left), never `withheld`; the rewrite is in the sent packet,
  so its provider-bound manifest says the same. What a follow-up reads as shown (sent excerpt
  refs and parts) comes from that provider-bound manifest, so a left-out excerpt is never counted
  shown. The privacy receipt counts the items actually included. A bounded diagnostic
  `semantic_disclosure_capacity_fitted` records how many excerpts were left out, never content.
- **Opening exchange keeps its frame (#1242, 2026-10-29).** On the first exchange of a reviewer
  conversation the fit stops at `first_token_limit` when the route is sized, and at the byte
  ceiling less the 8 KiB reply frame. Later exchanges keep the full exchange budget. The send
  still refuses only an exchange over the hard byte or token budget, so a packet the fit cannot
  shed under the first-exchange limit is sent when the model can still hold it. The review then
  offers no read when under 1 KiB of room remains (a result without data cannot fit).
