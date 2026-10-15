# Data egress and privacy protocol

This is the enforceable, provider-independent protocol that decides whether any data may cross the
trusted local service boundary. It is the authority for classification, policy resolution, human
authorization, minimization, dispatch, and structural audit evidence. See
[`../../PRIVACY.md`](../../PRIVACY.md) for the user-facing summary and
[`docs/adr/ADR-009-data-egress-privacy.md`](../adr/ADR-009-data-egress-privacy.md) for the full
architecture decision this page implements.

## Trust boundary and actors

The trusted persistent local service owns decrypted local state, policy evaluation, authorizations,
the egress gateway, key access, and structural receipts. CLI, MCP, a future UI, plugins, importers,
and provider adapters are callers with bounded capabilities. An MCP caller or agent is never a
local-human authorization principal, even when its request asserts that the user consented.

## Content classes

Every candidate item is classified before policy evaluation as exactly one of:

- **`public_structural`** — bounded IDs, declared file/media types, counts, digests, and other
  non-content protocol facts.
- **`ordinary_user_content`** — selected task text, code/evidence excerpts, and declared work
  product.
- **`sensitive_confidential`** — confidential, personal, regulated, proprietary, or explicitly
  user-marked material requiring stricter authorization.
- **`secret_or_cryptographic`** — the class that can never enter a disclosure case at all.

Ambiguous classification always takes the stricter class. A scanner miss never authorizes an item —
category classification, scope validation, and never-send scanning are independent gates, and
content outside the selected scope (unrelated files, environment, transcripts, logs, stderr,
database rows) is rejected regardless of category. The never-send registry is versioned and its
complete public list is in [`../../PRIVACY.md`](../../PRIVACY.md); policy may add prohibitions but
can never remove one.

## Policy resolution

The machine policy is an installation ceiling. The effective policy is the **intersection** of that
ceiling with repository, task, and request policy — never a union. Standing external LLM admission
also requires an exact current repository row; a permissive machine ceiling alone grants no
repository. A more specific scope may narrow automatically, but widening always requires a fresh
local-human authorization bound to the exact broader categories, channel, provider/endpoint,
purpose, and scope. Every scope carries its full ancestor chain — installation ID, and then
workspace, task, and request identifiers as applicable; a shortcut single reference is never
accepted as authorization identity. Privacy repository identity comes from the service's trusted
session locator, never from the operation's public `workspace_ref`.

The four **`PrivacyProfile`** values govern LLM inference and its content-disclosure rules only —
they are not a bundled consent switch for telemetry, diagnostics, updates, or capability testing:

- **`local_only`** — constructs no external LLM-provider transport and disables the `llm_inference`
  network channel. It may coexist with a separately authorized bounded non-LLM policy row, but no
  such channel may carry task/user content.
- **`confirm_every_request`** — requires an exact durable preview of the already
  minimized/redacted/scanned outbound case and a local-human decision for every external request.
- **`minimal_external`** — automatically permits only the smallest context its policy allows.
- **`trusted_provider`** — permits explicitly listed categories only for one bound provider plus,
  when declared, exactly one fallback provider (each an exact binding approved in the same
  ceremony), endpoint profile, workspace/task scope, and purpose; it never means unrestricted
  access.

External profiles bind an exact five-field `ProviderBinding`: `provider_id`, `model_id`,
`endpoint_profile_id`, `endpoint_profile_version`, and `transport`. An unknown profile, unbound
endpoint, scope mismatch, expired authorization, or policy version mismatch denies before the
provider adapter is even constructed. A missing or mismatched exact repository grant additionally
denies before credential-handle minting, authorization, or dispatch.

The external binding also selects one credential authority. HTTP profiles use
`finishup_vault_api_credential`. `codex-chatgpt-subscription@1` uses
`external_runtime_oauth`: an exact Codex app-server owns ChatGPT OAuth and receives a secret-free
attempt authority. It has no API-key, OAuth-token, generic-endpoint, proxy, or ambient-home
fallback. Its content-free account/model readiness checks do not grant privacy authority.
The two authorities may be paired as one primary plus exactly one fallback (issue #582): the
`llm_inference` row then carries `fallback_provider_binding`, a second exact external
`ProviderBinding` that must differ from the primary, approved in the same ceremony as a
widening of exactly that destination. Egress admits a candidate only when its binding is exactly
the primary or that fallback, and each fallback attempt is its own authorization, dispatch, and
receipt.

`credential-probe` is a distinct `llm_inference` purpose, not an implication of enabling AI-powered
review. During provider-credential setup, the local human separately decides whether one fixed,
content-free request may verify the just-stored credential. The policy preview and its widening
decision display the resulting allowed-purpose set, and a policy that omits `credential-probe`
blocks it before adapter construction. An admitted probe uses the exact configured provider
binding, carries only bounded structural metadata, and follows the ordinary authorization and
egress-receipt path. A classified authentication or authorization refusal withdraws the stored
credential; uncertain transport, outage, timeout, unsupported-profile, and invalid-response
outcomes retain it as unverified.

`ReviewContextProfile` is a **separate** closed value — `structural`, `goal_aware`, `assisted`,
`expanded`, or `custom` — that determines which recorded case material a local selector considers,
never whether that material may leave. `structural` is typed timeline/state/coverage facts only;
`goal_aware` adds allowed intent and claim prose; `assisted` adds mechanically linked problem-local
recorded evidence, test/failure, diff, and repository excerpts; `expanded`/`custom` can select a
broader explicitly approved recorded set. Every selected item still needs category/class/scope
authority and passes the same minimization/never-send path. No profile creates a live
repository/filesystem handle — a missing excerpt is reported as `not_recorded`, `not_selected`, or
`withheld_by_policy`, never presented as observed-unchanged content.

The fail-safe LLM seed for every new installation is `local_only + structural`, with no external LLM
channel authority; the product may separately enable its bounded structural update-check channel.
The CLI's *configured, opt-in* recommendation is an inspectable standing exact-repository
`trusted_provider + assisted` recipe, eligible only for an exact
current provider data-use record stating training `prohibited`, retention `none|bounded`, and
provider human access `prohibited|restricted`. Unknown or stale posture removes the recommendation.
The recipe ships with an editable `require_current_provider_data_use_evidence=true` runtime guard.
Once a standing policy is human-confirmed, ordinary checks, automatic retries, reviewer challenges,
agent responses, and rechecks proceed without further human prompts; human involvement remains
required only for widening, credential mutation, `confirm_every_request` decisions, and finding
waivers. Never-send content has no approval path under any profile.

Repository binding is a trusted-control effect. CLI/UI supply their actual working directory and MCP
supplies its configured/session working directory. The service resolves symlinks, selects the Git
common root (or resolved non-Git directory), creates an installation-keyed commitment, and discards
the raw path. Branches and linked worktrees share one grant; independent clones and unrelated
repositories require their own.

`network_egress_permitted` is the global network ceiling. When `false`, all five channels must be
disabled. When `true`, it authorizes nothing by itself — every channel still needs its own consent.
The five independent `EgressChannel` values are `llm_inference`, `product_telemetry`,
`crash_diagnostics`, `update_checks`, and `capability_testing`. Enabling one never enables another.
The four non-LLM channels accept only their reviewed bounded structural/synthetic schemas and can
never carry task/user content. **v0.1 ships a production transport for `update_checks` only**
(allowlisted PyPI JSON GET of the `finishup` distribution version, or of `yoetz` for an installation
from the transitional `yoetz` distribution, ADR-048; interactive advisory surfaces
only). The other three non-LLM channels still have no production transport: an attempted use
terminates before dispatch with outcome `channel_unavailable`, writes a no-dispatch structural
decision receipt, and makes no DNS or socket attempt.

The product durable default is `local_only` with structural `update_checks` on (opt-out) and the
global ceiling true only because that channel is on. FinishUP's true zero-network state is the
composite `profile=local_only`, `network_egress_permitted=false`,
and all five channel policies disabled. That state permits only exact release-cell local IPC:
FinishUP's own service/confidential endpoints, an optional approved local-model AF_UNIX profile, and
measured OS credential/user-presence/session-lifecycle IPC (for example allowlisted Linux
session-bus Secret Service routes, system-bus `org.freedesktop.login1`, or macOS native
security/presence notifications). Arbitrary AF_UNIX destinations, bus methods, or proxies are
forbidden. Neither the `local_only` profile token alone nor a true global ceiling alone supports a
zero-network claim by itself — both, plus all five channels disabled, are required together.

The four `LocalDisclosureSink` values — `local_model`, `agent_context`, `local_human_view`, and
`trusted_human_control` — are not network channels; they are covered by the same never-send fence.
`local_human_view` is the owner's own view of a vault they already unlocked — it is not a
third-party disclosure. Every ordinary client result resolves to `agent_context`, whatever its
rendering, terminal or client kind; only a receipt call matched to a reauthenticated one-use
`owner_receipt_view` grant resolves to `local_human_view` (see "Receipt prose delivered to agents"
below). A client never selects its own sink. `agent_context` is further conditioned on a computed
`DisclosureProvenance` (`self_authored`, `engine_derived_from_self_authored`, `other_writer`,
`imported`): material the requesting writer authored at the frozen frontier, and prose derived
solely from it, project without an extra grant, because withholding a writer's own words discloses
nothing new. Everything else — other-writer material, imports, and every provider-derived AI-powered
finding — requires the explicit `agent_context_categories` grant. The shipped resolver attributes
status evidence rows from ledger authorship: an agent reads back the evidence it published in its
current session, while host-observed rows, other writers' rows, and imports stay omitted without a
grant. The names of undeclared files a delivered file may read (tb4n5, ADR-009 and ADR-035)
follow the same rule, keyed on each name's own status leaf: a name returns only to the writer that
published that exact name itself in this session, and no outbound channel ever carries those
names. No sink or provenance combination ever admits `sensitive_confidential` content or anything
in the never-send set. Serving the static
`guidance/` documents over MCP resources is not a disclosure sink at all — those bytes carry no
ledger, task, or user content and are identical for every installation.

## Live harness observation retention

First-party Codex live observation (ADR-010) is local control, not a network egress channel and not
a seventh MCP tool. Observation consent is independent of egress consent: one workspace-level
confirmation records a private workspace commitment (never a raw path). Revocation stops new
ingestion and retains already-kept evidence. Never retain hidden reasoning or complete transcript
prose. Sensitive bounded observation evidence lives only in encrypted objects; plaintext state is
allowlisted structural fields plus commitments. Never create an unencrypted transcript spool on
vault/service outage. AI-powered review receives only minimized approved packets. Secret-like
command output never appears in status, logs, hook advice, or AI-powered review packets. Ordinary
hook-captured output of a command the agent ran may appear in a follow-up review packet only when
the reviewer asked for verification output, only as a repository excerpt the owner's policy already
allows, and only within the existing excerpt limits (ADR-009). Private sends nothing. Output of a
command the agent did not run is never included.

## Outbound pipeline and state machine

One candidate request moves through exact states: `candidate` → `classified` →
`policy_denied`/`policy_eligible` → `minimized` → `redacted` → (`awaiting_human` when required) →
`approved` → `validated` → `authorized` → `receipt_pending` → `recorded`. Only a validated case with
a still-valid, unconsumed authorization can reach `receipt_pending`. A provider adapter receives
only an immutable `ApprovedOutboundCase` — never raw candidate context, policy objects, repository
handles, ledger handles, file paths, environment, or decryption services — and cannot enrich the
case or change its destination. The gateway computes the keyed request commitment over the exact
final application body bytes immediately before I/O; credential-bearing auth metadata and HTTP/TLS
framing are excluded from that commitment.

For `confirm_every_request`, the preview occurs after local minimization/redaction/secret scanning
and shows destination, purpose, scope, category names, the exact bounded excerpts as they would be
sent, and redaction counts. Approval is request-specific and expires if the prepared bytes, policy,
destination, scope, or purpose changes. Every physical retry — even of identical bytes — requires a
fresh exact foreground preview and decision; only crash/resume *before* authorization consumption
continues the same dispatch rather than minting a retry.

## Egress receipts

Every successfully reserved terminal outbound decision and every physical outbound attempt produces
a durable, structural `EgressReceipt` (or `LocalDisclosureReceipt` for a local sink) through the
privacy audit path. `awaiting_human`, `approved`, and `receipt_pending` are nonterminal audit
states — never finished receipt outcomes. The sole no-receipt exception is an **initial audit
reservation failure**, which returns bounded `audit_failed` before any preview, authorization, or
dispatch and fabricates no receipt identity. Receipts record provider/model/endpoint profile,
policy version/digest, authorization scope, approved/blocked categories, byte/token counts,
redaction counts, consent source, outcome/reason, and a keyed commitment to the exact final request
body bytes — never plaintext content or the provider's response.

For `external_runtime_oauth`, “request body” at this boundary means the exact disclosed FinishUP case
bytes passed through app-server stdin. Codex constructs the upstream OpenAI body beyond FinishUP's
observable boundary. Runtime provenance therefore commits separately to the disclosed case,
instruction, output schema, executable/protocol/capability/launcher/config, model/reasoning
selection, safe correlation, output digest, and process cleanup, and requires
`upstream_body_observability=unavailable`. It never substitutes the case digest for an upstream
body digest. A pre-disclosure structural failure records zero disclosed items/bytes; a post-turn-
acknowledgement ambiguity records `transport_failed/outcome_unknown` and consumes the one-use
authorization without retry.

Content-bearing v0.1 disclosure proposals are encrypted as `ObjectKind.privacy_audit` objects in
their owning task bundle; taskless channel-unavailable decisions and machine policy diffs are
closed nonsecret structural rows with no content object. Backup pins the privacy-root
generation/digest and carries the structural audit sidecar plus every rooted encrypted object;
restore preserves terminal evidence but never revives a pending or expired authorization.

| Situation | `PrivacyOutcome` | `PrivacyReason` |
|---|---|---|
| Policy/category/purpose/destination/scope block | `blocked_by_policy` | exact applicable token |
| Never-send match | `blocked_forbidden_data` | `never_send_detected` |
| Unresolved classification | `classification_uncertain` | `classification_uncertain` |
| Local-human denial | `human_denied` | `human_denied` |
| Authorization expired, stale, or reused | `approval_expired` | `authorization_expired` / `authorization_stale` / `authorization_reused` |
| Success | `completed` | absent |
| Provider refusal | `provider_refused` | `provider_refused` |
| Timeout | `timeout` | `provider_timeout` / `deadline_expired` |
| Invalid provider response | `invalid_response` | `provider_invalid_response` |
| Transport/provider unavailable | `transport_failed` | `provider_unavailable` / `transport_failed` |
| v0.1 non-LLM channel has no owned transport | `channel_unavailable` | `channel_unavailable` |
| Ambiguous I/O outcome | `transport_failed` | `outcome_unknown` |
| Late / stale result | `late` / `stale` | `late` / `stale` |
| Reserved decision, later transition fails | `audit_failed` | `audit_failed` |

`safe_failure_reason` is required for every outcome except `completed`, for which it is forbidden.

## Policy mutation

A trusted local control surface may propose a policy change. The service classifies the diff as
tightening, neutral, or loosening. Server-proven tightening commits immediately. Loosening always
returns `decision_required` with a pending proposal ID and exact digest — it can never commit
through the ordinary control channel. A separate foreground human-control surface confidentially
renders, reauthenticates, and commits it. Ordinary MCP/agent schemas expose no method that can reach
that surface. Revocation of an existing authorization is immediate.

The separate local `finishup consent` lane may let an allowlisted first-party agent relay one explicit
current-chat decision for an exact prepared repository recipe, including `expanded_review`. Its v6
agent projection carries the complete bounded substantive before/after diff and binds both frozen
policy byte sets, repository commitment, authority generation, provider/model/endpoint, recipe,
target, and expiry. Authorization rechecks the live repository, authority snapshot, and configured
route before proposing only the frozen candidate. It adds no MCP policy-mutation method, reusable
grant, ambient approval, or authority to bypass a machine ceiling or never-send rule.

For a new repository, one proposal may contain both a necessary machine-ceiling widening and the
first repository row. The service returns one authority digest covering the complete ancestor and
migration state; the trusted preview shows both changes, and one CAS commits every member or none.
Policy-digest-only older proposal shapes cannot perform this transition and fail closed under
repository-grant mode.

Package upgrades preserve accepted machine-policy bytes. An append-only catalog migration snapshots
only the bounded pre-upgrade legacy-route frontier and entitlements. When an eligible route next
arrives with a trusted locator, its accepted policy is cloned beneath the unchanged machine ceiling
and the entitlement is atomically consumed. If no legacy route existed, one bounded first-repository
carry-forward is available. This is no-reapproval narrowing, not new authority; later repositories
remain Private. Replay is idempotent, and stale CAS, crash, expiry, denial, missing locator, or old
decoder leaves external LLM admission blocked.

## Failure, cancellation, retry, and crash behavior

Classification, minimization, redaction, schema, secret-scan, or receipt-persistence uncertainty
fails closed before dispatch. Service lock, policy unavailability, unknown scope, stale
authorization, or an unbound provider denies egress but never erases local-check work.
Dispatch ambiguity (for example a connection drop mid-request) records `transport_failed` /
`outcome_unknown` — never "unsent," and never a blind retry. Cancellation before any I/O leaves a
proposal pending until an explicit denial or expiry; cancellation after possible I/O records
`transport_failed`/`outcome_unknown` with the exact final-request-body commitment. That receipt is
built before the provider call and parked beside the nonterminal row, so a cancelled attempt
records it through a shielded write and a dispatcher that died first is closed by one bounded,
idempotent startup reconciliation — before any new physical attempt is admitted, and only over
attempts consumed before the current service start. Neither path re-enters the provider. Provider
refusal, timeout, or invalid output completes AI-powered review as `incomplete_check` while
local-check results remain fully available — AI-powered review failure never discards a
local-check result.

## Extension and versioning

New content categories, disclosure sinks, egress channels, or repository-authority shapes require a
coordinated schema, ADR, and fixture update — none is added as a silent policy-vocabulary change.
`audit_store_version=1` and the
`hmac-sha256/yoetz-privacy-egress-request-v1` commitment format are frozen for v0.1.

Installed-wheel two-repository AI-powered review and receipt proof remains outstanding for issue
#139. Router downstream/fallback authority and issue #141's foreground disclosure continuation are
not part of this protocol change.

## See also

- [`../../PRIVACY.md`](../../PRIVACY.md) — the public promise this protocol enforces.
- [`docs/adr/ADR-009-data-egress-privacy.md`](../adr/ADR-009-data-egress-privacy.md) — the
  architecture decision.
- [`privacy-setup-wizard.md`](privacy-setup-wizard.md) — the setup/policy-change contract.
- [`local-service-security.md`](local-service-security.md) — the trust boundary that hosts this
  protocol.

### Cancelled background review

A foreground session attachment may cancel optional background review. Once disclosure authority
is consumed, cancellation cannot prove that nothing was sent. The gateway records the owed
`transport_failed` / `outcome_unknown` receipt through a shielded write. It also parks the bounded
receipt before dispatch so a later service startup can reconcile an interrupted attempt, before
admitting new attempts. Reconciliation never sends again or restores spent authority. The
background result remains cancelled and retains available attempt and provider provenance.

## Receipt prose delivered to agents

Receipt prose is FinishUP-authored and keeps its ordinary category policy in an `agent_context`
projection: section titles, sentences, codes, counts, IDs and coverage remain readable. The one
thing it can carry that the excerpt ceiling covers is a repository file name the check found and no
participant published (an undeclared-reference name, ADR-035), which a `full_local` receipt spells.
Each such name span is offered as its own `repository_excerpt` candidate. Unless the policy grants
repository excerpts, or the requesting writer published that exact name in this session through an
accepted, unredacted cooperative publication, the whole path token becomes
`(receipt prose withheld: repository_excerpt)`; the rest of the sentence stays. A span is the quoted
path the receipt prints, the bare path when it has a directory, or a basename with an extension. Any
name, a top-level one without an extension included, is also a span behind a leading `./` (also
`.//` or `././`), quoted or not, and empty or `.` segments inside the name still spell the same
file. Behind an absolute prefix (`/`, `~`, `~user`, `$VAR` or `${VAR}`, optionally behind `file://`)
any directories may come before the name's last component: an absolute path that ends in a withheld
file's base name counts as that file, which can only withhold more. Unquoted, the prefix's
directories stop at whitespace, at quotes and backticks, at `<` `>` `|` `,` `;` and brackets, and at
a `:` that starts another path (`:/`, `:~`, `:$`, `:./` or `:../`), so the next path in a list
starts afresh; a `:` inside a directory or a port (`host:8080/`) is kept. The whole prefixed token
is withheld. A path in single quotes, double quotes or backticks may run through directories with
spaces or the other quote characters (`"/r/Bob's/a.npz"`), and the whole quoted token is withheld
when the name ends the quoted text; a name earlier in the quotes (`"/r/x/b.npz /r/y/a.npz"`) is
found too, and its own path is withheld. An absolute path through a directory with spaces is not
recognised as one path when it is unquoted, since prose gives it no token boundary, or when anything
follows the name inside the quotes (`"/My Docs/a.npz:12"`); nor is an unquoted one through a
directory holding a stop character (`/r/Bob's/a.npz`), or a quoted one through a directory holding
its own closing quote. A name glued to other characters and then a `/` (`/r/a.npz~/x`), or followed
by a `:` and a bare relative path (`/r/a.npz:rel/x`, or grep's `/r/a.npz:12:rel/x`), reads as a
directory of a longer path and stays readable: the prefix never gives a directory back, which keeps
each search linear. A different relative directory (`../`, `x/`), a longer name, a suffix, a plain
word such as `Summary` (or a top-level name written without a prefix or quotes), and a different
letter case stay readable: spellings are compared exactly, because folding case or Unicode would
conflate distinct files on a case-sensitive filesystem. Every bound in the span pattern is fixed, so
a search stays linear in the prose it reads. The rule applies to JSON, markdown and text and to
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
request. The grant belongs to the command's own control connection as the service admitted it: the
service mints an opaque identity for every admitted connection and never takes one from the client,
refuses any connection whose hello nonce is already live or was used before, mints the grant only
for the one live connection the ceremony target names, consumes it only on a receipt call on that
connection, and revokes it when the connection closes. The grant is one-use and expires after 60
seconds. There is no standing grant, and the agent-attested consent lane cannot stand in for it.
Anyone holding the terminal can type into the prompt, a pseudo-terminal included; the boundary is a
passphrase or presence check the agent cannot pass. On macOS the packaged service composes one
operating-system presence provider, Apple LocalAuthentication: the service itself raises a system
dialog (Touch ID or the device password) whose text is fixed apart from a confirmation code the
owner's own command also prints, and only its exact approval for that exact challenge becomes a
one-use attestation the vault consumes. A client can name that source but can assert nothing. The
provider serves only this ceremony, on either vault mode. A passphrase stays offered beside it: when
the service cannot show a dialog, the command asks for the passphrase once instead, but it never
asks for a passphrase kept in the platform credential store (setup's system-keychain choice
generates one its owner never saw) unless the owner passes `--use-passphrase`, which also skips the
dialog, for example over SSH. A cancelled or failed dialog is `presence_refused` and an unanswered
one is `presence_timeout` after 60 seconds; neither grants anything, and the next dialog then waits
(`reauthentication_rate_limited`, 5 seconds rising to 5 minutes). That wait lives in the service
process and a restart clears it, so it slows repeated dialogs rather than capping them, and an agent
that causes misses can delay the owner's own dialog by up to 5 minutes. Dialogs start at least 5
seconds apart even when each is cancelled at once. A throttled passphrase (30 seconds after the
third wrong one, doubling to 5 minutes, kept across a restart) is reported as such, without the
restart hint. Another open confirmation is `ceremony_busy` (`owner_view_busy`, naming this command's
code), never a locked vault; a silent one holds the slot until its five-minute binding expires or
the service restarts. Linux and WSL 2 compose no provider: there only a vault passphrase the owner
types completes the ceremony, and a vault without one, or with one kept in the credential store,
fails closed with `owner_view_unavailable`. A command with no foreground terminal to prompt on (for
example a headless session) fails with `owner_view_requires_terminal`. Either way it shows nothing
and points to the next step. Linux and WSL 2 use the same code but were not exercised for this
change, and no real Touch ID prompt was exercised by automation (ADR-009 round 5). An agent that
runs the command can make the dialog appear but cannot answer it, so approve it only when you asked
for the full receipt yourself. A process running as the owner's account that can already read the
vault passphrase (for example from an auto-unlock keyring entry) is outside this boundary, as for
every passphrase reauthentication (ADR-008).
