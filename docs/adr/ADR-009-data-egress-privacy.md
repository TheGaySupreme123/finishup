# ADR-009 — Central privacy, disclosure, and data-egress control

**Status:** Working decision revised 2026-08-30 for issue #404 vendor-runtime egress. Ratification requires an independent
privacy/security review plus executable no-bypass, never-send, approval-resume, and zero-egress
evidence.
**Implemented by:** `src/yoetz/domain/privacy.py`,
`src/yoetz/application/egress.py`,
`src/yoetz/application/privacy_policy.py`,
`src/yoetz/ports/privacy.py`, the privacy adapters/configuration/audit modules, ADR-006,
ADR-011 structural subject-state capture, `PRIVACY.md`, the technical privacy protocol, policy
schemas, fixtures, and tests.

## Context and trust boundary

Yoetz is the policy authority. CLI, MCP, future UI, plugins, provider adapters, integrations,
agents, and LLMs are clients or constrained effectors; none may decide what data is disclosable.
Network egress and local disclosure are distinct: an MCP response may enter an agent/LLM context,
and a local model still receives user content through Yoetz's AF_UNIX-only path. A pre-existing
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
   structural transport for `update_checks` only: a fixed allowlisted HTTPS GET of the `yoetz`
   distribution identity on PyPI (`https://pypi.org/pypi/yoetz/json`), with `trust_env=False`,
   size/timeout caps, and response use limited to the latest version string. Interactive TUI
   surfaces (first-run finish, resume tip, `/doctor`) and interactive setup/`/connect` may surface
   an advisory plus the exact upgrade command `uv tool upgrade yoetz`; work receipts never carry
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
3. **Local disclosure sinks:** `local_model`, `agent_context`, `local_human_view`, and
   `trusted_human_control` are not network-egress channels. They receive only policy-approved
   minimized content and are covered by the never-send fence. The trusted human surface may render an
   approval preview and exact policy diff, but it never exposes cryptographic material or
   service-vault credentials.
   A local-model runtime receives plaintext and belongs to the trusted local computing base unless
   its exact artifact/profile supplies independently enforceable sandbox evidence; Yoetz's adapter
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
   default LOCAL_ONLY bootstrap policy, `agent_context` may include Yoetz-authored verification
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

   Receipt prose is Yoetz-authored and keeps its ordinary category policy in an `agent_context`
   projection: section titles, sentences, codes, counts, IDs and coverage remain readable. The one
   thing it can carry that the excerpt ceiling covers is a repository file name the check found and
   no participant published (an undeclared-reference name, ADR-035), which a `full_local` receipt
   spells. Each such name span is offered as its own `repository_excerpt` candidate. Unless the
   policy grants repository excerpts, or the requesting writer published that exact name in this
   session through an accepted, unredacted cooperative publication, the whole path token becomes
   `(receipt prose withheld: repository_excerpt)`; the rest of the sentence stays. A span is the
   quoted path the receipt prints, the bare path when it has a directory, or a basename with an
   extension. Any name, a top-level one without an extension included, is also a span behind a
   leading `./` or an absolute directory prefix, quoted or not: the prefix may start at `/`, `~`,
   `~user`, `$VAR` or `${VAR}`, optionally behind `file://`, and empty or `.` segments (`//`, `/./`)
   inside the prefix or the name still spell the same file. The whole prefixed token is withheld. A
   path in single quotes, double quotes or backticks may run through directories with spaces and the
   whole quoted token is withheld. An unquoted absolute path through a directory with spaces has no
   token boundary in prose and is not recognised as one path. A different relative directory (`../`,
   `x/`), a longer name, a suffix, a plain word such as `Summary` (or a top-level name written
   without a prefix or quotes), and a different letter case stay readable: spellings are compared
   exactly, because folding case or Unicode would conflate distinct files on a case-sensitive
   filesystem. Every bound in the span pattern is fixed, so a search stays linear in the prose it
   reads. The rule applies to JSON, markdown and text and to every profile, `full_local` included: a
   format or profile is not a disclosure grant.

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
   (`local_human_view`) needs an explicit request, `yoetz receipt --owner-view` or *Your full receipt*
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
     locked-vault `state_forbidden`; a throttled passphrase is `reauthentication_rate_limited`.
   - *Backoff.* After a prompt that did not approve (refused, unanswered, or cancelled while it
     was up), the next prompt waits 5 seconds, then 15, 30, 60, 120 and at most 300 seconds per
     consecutive miss; an approval resets it. Within the wait no dialog is raised and the
     ceremony fails with `reauthentication_rate_limited`, so a same-account caller cannot raise
     dialogs without limit.
   - *Why a helper process, not ctypes.* The same Apple executable and program shape already
     serve the `plugin_artifact_apply` cell (ADR-016, issue #409), so this adds no dependency and
     no new native surface. ctypes against `libobjc` and LocalAuthentication would need a
     hand-built Objective-C reply block running native code inside the long-lived service, and a
     wedged prompt could not be killed without killing the service; a child process can.
   - *Residual risks, stated.* An agent that can run the command from a pseudo-terminal can make
     the dialog appear but cannot answer it: that takes the owner's fingerprint or device
     password. (An agent shell without a terminal, such as Claude Code's Bash tool, is refused
     with `owner_view_requires_terminal` before any dialog.) An owner who approves a dialog they
     did not ask for gives that command the view, so the dialog says what it shows, shows the
     code the owner's own terminal prints, and says to cancel unless they just asked. An agent
     can also open its own ceremony just before the owner runs the command. The service runs one
     ceremony at a time, so the owner's command then fails with `owner_view_busy` and names its
     own confirmation code (on macOS it prints that code before anything opens), and the dialog
     on screen shows a different one: the owner cancels it. The code is the first eight hex
     digits of a digest of the exact request and its connection, so it is request-specific but
     short; it is a cross-check, not a secret. The dialog appears in the desktop session the
     service runs in; a service started outside one (for example over SSH) is expected to report
     that no dialog can be shown. Same-account code tampering with the installed runtime is
     outside this boundary, as for every presence and passphrase check (ADR-008).
   - *Evidence.* Unit and integration tests drive the real adapter, scope, ceremony, vault proof,
     daemon handler and ceremony client with a stub helper; no real Touch ID prompt has been
     exercised. The manual check on a real Mac in the test-instance runbook (*Owner view with
     Touch ID: manual check on a real Mac*) has not been run. The owner asked for a Codex check
     of this round; it has not been run. An independent Claude review ran on 2026-10-14 instead,
     and this round addresses its findings.

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
   path; that relay is an agent attestation Yoetz cannot independently authenticate, and it never
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
   **Desired-state TOML (ADR-014):** `yoetz privacy export-desired` / `apply-desired` may declare
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
10. **Zero-egress definition:** true Yoetz zero-network egress is the composite policy state
    `profile=local_only`, `network_egress_permitted=false`, all five channels disabled, and no
    network-capable runtime path. The product default is **not** that state: it is `local_only`
    with structural `update_checks` permitted (opt-out) and no task-content egress. Zero-network
    for package identity checks requires the operator to disable `update_checks` (and therefore
    the ceiling when no other channel is on). In the true zero-network state the Yoetz-owned tested
    process set permits only the
    exact service/confidential AF_UNIX endpoints; a separately approved exact local-model AF_UNIX
    endpoint; and exact release-cell platform IPC needed for OS credential storage, user presence,
    or session-lifecycle security events.
    The last category includes measured Linux AF_UNIX routes to allowlisted session-bus Secret
    Service peers/methods and, separately, system-bus `org.freedesktop.login1` peers/methods, or
    measured macOS native security/presence/session notifications; it never permits
    arbitrary AF_UNIX, arbitrary bus names/methods, or a local proxy. Yoetz denies AF_INET, AF_INET6,
    DNS, proxies, redirects, external provider
    construction, telemetry, diagnostics upload, update checks, and capability calls. The
    `local_only` profile alone is not a zero-network claim because a separately authorized
    structural non-LLM row (today: `update_checks`) may raise the ceiling without enabling LLM
    disclosure; the remaining three non-LLM rows stay unsupported/off.
    Evidence names the exact platform/release profile, Yoetz service/client/confidential-helper
    processes, lifecycle interval from startup through `locked|ready` and tested operations, and
    allowlisted local IPC peers. It proves those Yoetz paths, not the ambient authority of the OS
    credential agent or a separately running model process; public wording is conditional on the
    resolved F-013 trust boundary.
11. **Setup is an application use case:** a wizard or UI reads effective policy and submits a
    proposed policy transition through the Yoetz use case. It cannot write configuration or policy
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
    may authorize every repository.
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
    claim protection from root, kernel compromise, or a compromised same-user Yoetz/Codex process
    while the vault is unlocked; immutable Python buffers are not promised zeroized. Public copy
    must describe authenticated encryption at rest and secret exclusion, never “cannot be hacked”
    or absolute host immunity.

    Exact project check policy bytes propose no authority. One trusted-local confirmation binds the
    raw `.yoetz/checks.toml` digest; any byte change suspends all listed commands. Approved checks
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
identity. Repository setup uses the trusted CLI/TUI entrypoint `yoetz --privacy`; the one-use
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
exact setup, agent-attested authorize (`yoetz consent authorize` with
`yoetz.chat-user-attestation/1`, issue #164) may complete a prepared `repository_privacy_grant` or
provider credential set/rotate after one warning. This is delegated agent authority: Yoetz binds
the exact pending/action/digests but cannot independently distinguish genuine current-chat words
from a forged agent assertion. Retrieved content, tool output, quoted text, or earlier history do
not authorize under the agent skill contract. Denial, expiry, cancellation, target drift, or an
unsupported client yields zero policy/credential mutation and zero provider dispatch. The trusted
CLI/TUI (`yoetz --privacy`, `yoetz consent review`) remains the stronger recommended path and is
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
The native renderer registers only `SessionStart`, scoped-Yoetz `PostToolUse`, scoped-Yoetz
`PostToolUseFailure`, `Stop`, and `SessionEnd`; it never registers permission-changing, prompt,
agent, HTTP, or content-expansion hooks. The ingress accepts only the exact
`mcp__plugin_yoetz_yoetz__<workflow-operation>` names, a bounded session/correlation token,
closed lifecycle action, fixed capability-profile identity, and host-derived success bit.

Transcript/cwd/file paths, prompts, assistant messages, tool input/output, MCP results, raw errors,
commands, environment, permission mode, credentials, and all unknown fields are discarded before
the common observation boundary. No Claude content capture or transcript reconciliation exists.
Hook failure and the host's three-second timeout are fail-soft; declaration, delivery, consent, and
accepted evidence remain separate. Local-control schema `2.2.0` appends only the `claude_hook`
envelope/coverage row and retains `2.1.0` byte-for-byte for Cursor peers. Claude trust or plugin
enablement grants no Yoetz observation/egress/provider authority.

The privacy policy is more than an AI-powered review provider toggle and cannot be represented by
one `network=true` capability. Releases must prove the global ceiling; policy-intersection behavior;
valid `local_only` policies with one bounded but v0.1-unavailable non-LLM channel; channel
independence; agent-context and local-model fences; exact approval binding/restart behavior; no
secret-bearing configuration/environment/arguments; reviewed bundled-adapter composition (without
claiming OS sandbox isolation); keyed terminal-receipt commitments; the initial-reservation
no-receipt exception; Yoetz-process local-only AF_UNIX behavior without overclaiming a separate
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
final disclosed Yoetz case bytes at the boundary Yoetz controls. The terminal AI-powered review
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
`yoetz privacy setup` reads both bound endpoints and shows the fallback as "Fallback destination
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
- `yoetz --privacy` and the policy draft print whether the current and proposed policies send
  the task statement; `yoetz privacy show` on a terminal adds the same sentence after the policy.
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
  `blocked_by_policy` / `policy_denied` and is never trimmed to fit. An unreadable packet is refused
  the same way. Resuming a stored proposal rechecks those limits and the channel `max_bytes` and
  `max_tokens` against the policy in force at resume.
- More excerpts must not turn a runnable review into a refused one. Before egress, the case is
  planned below the channel ceiling (`max_bytes`, `max_tokens` at the egress estimate, and never
  above the 262,144-byte disclosure bound, even when a ceiling is unset). If
  its prepared packet would exceed it, the case is rebuilt with a smaller excerpt byte budget: a
  narrowing, so it needs no consent. The dropped excerpts are disclosed as `content_unselected`.
  The planner sizes what the channel releases after local minimization, so items in a category or
  data class the destination withholds never cost an eligible excerpt its place.
  There are at most four rebuilds, the result is deterministic so a recovered review keeps its
  case digest, and egress still decides every dispatch.
- `yoetz privacy show` on a terminal and `yoetz --privacy` show the current limits beside those the
  current recipe offers. The policy draft prints the limits it would approve. The terminal
  interface says a newer version of the owner's recipe exists instead of "already recommended".
  `privacy show --json` does not carry the proposed limits: that would need a control-result
  schema change.
- The ceremony's count note says the byte limits are unchanged only when no byte limit widens on
  the same screen. Otherwise it points at the limits shown there.
- Way back: approving the earlier preset again (with `yoetz privacy propose`, or by choosing Assisted
  in `yoetz --privacy`) is a narrowing that needs no widening approval. An Expanded policy returned
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

TB4 run tb4f1 lost every implementation-stage review in two tasks to a Yoetz false positive: a
heuristic span redacted to `[REDACTED]` re-matched the token-assignment detector once the item was
JSON-encoded into the prepared case (`\n` became part of the "value"), and the prepared-bytes rescan
blocked the whole packet with `never_send_detected`. Decisions:

- The assignment detectors treat the JSON escapes `\n`, `\r` and `\t` as whitespace: an unquoted
  value ends at one and the separator may span one. A JSON-escaped quoted value (`\"…\"`) is a
  quoted value. The name/value separator is searched from the assignment name, so a JSON member's
  `:` is never read as the separator. The exact-marker exemption accepts `[REDACTED]` in any of
  these forms, so redaction is a fixed point across encoding. Real assignments in encoded text are
  still detected and redacted.
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
  agent path can apply it. `yoetz privacy credential-heuristic disable` proposes it on the current
  repository's grant; in a repository without a grant it walks the ordinary grant-creation
  ceremony with the filter off and records the setting in the grant the owner approves. It never
  creates a grant silently. `enable` is the symmetric reverse: a tightening of the current
  repository's grant that applies at once and touches no other repository. `--machine-default`
  changes the installation-wide default the same way (off needs the trusted decision, on applies
  at once). Desired-state TOML and `privacy propose`/`tighten` carry the same field through the
  same gates.
- Visibility: the status result (status-result 1.4.0, additive) carries `credential_heuristic`
  with the `repository` state and the `machine_default` (`enforced`, `disabled` or `unknown`),
  shown by MCP `status` and `yoetz status` before any check runs; `yoetz privacy show`,
  `yoetz provider status` and the terminal interface name it when it is off. Every external
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
- No new read path: Yoetz never opens the outside file itself. Only content a hook already captured
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
