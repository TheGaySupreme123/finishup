# FinishUP privacy

> **Specification-stage notice:** this repository does not contain the FinishUP product
> implementation yet. The rules below are design commitments being frozen before implementation,
> not claims about working software. Artifact-bound tests must pass before any release advertises
> them as implemented guarantees.

FinishUP is designed around one trusted persistent local service. The service—not the CLI, MCP,
an agent, an LLM, or a future ordinary UI—owns encryption keys, decrypted local state, privacy
policy, provider credentials, and outbound dispatch. Normal clients exchange only bounded control
requests and results.

## Planned default and disclosure path

External LLM disclosure is denied by default. Every proposed external request must traverse one
central path:

`candidate context → classification → effective policy → minimization/redaction/secret scan →`
`optional exact local-human preview → one-use authorization → bound gateway/provider → local receipt`

This is the fail-safe installation seed, not a hidden choice on behalf of the user. If a technical
user deliberately configures external semantic review, the CLI recommends an inspectable
`assisted-review` recipe. It is committed once as a standing exact-repository policy beneath the
machine installation ceiling and then runs ordinary
checks/retries without per-request human prompts. The user may choose a stricter, broader, custom,
or forked configuration instead.

Repository identity comes from the trusted client's actual/configured working directory, not from an
agent-supplied task reference. FinishUP resolves Git's common root and creates an installation-keyed
commitment. The raw path is never stored, logged or returned; it stays in service memory for that
client connection only, so a check can read the check-time change described below. Branches and
linked worktrees share one grant; independent clones and unrelated repositories need their own.
Without the exact grant, FinishUP blocks before provider construction, credential-handle minting,
authorization, or dispatch.

Package upgrades preserve accepted machine-policy bytes. A bounded migration may automatically
clone previously accepted authority onto an eligible pre-upgrade repository, or one first repository
when no prior route existed. That is narrowing, not new consent; later repositories inherit nothing.

Provider adapters receive an already approved bounded case through reviewed interfaces. The v0.1
working design permits only bundled adapters and passes them no repository, storage, environment,
or transcript handles. This is not an OS sandbox: a malicious adapter already executing inside the
trusted service process is part of the unresolved trust boundary.

The four LLM privacy profiles are `local_only`, `confirm_every_request`, `minimal_external`, and
`trusted_provider`. Trusted-provider permission always binds named categories, purpose, scope,
provider, model, and endpoint profile; it never means “send everything available.” Telemetry,
crash diagnostics, update checks, and capability testing have separate policies. Enabling one
channel never enables another. A separate global network ceiling authorizes nothing by itself.
`local_only` governs LLM disclosure and may coexist with a separately consented bounded structural
non-LLM channel. **Package update checks** may contact the allowlisted PyPI JSON endpoint for the
`finishup` distribution (or, for an installation from the transitional `yoetz` distribution, the
`yoetz` one) when the durable `update_checks` channel is enabled (product default: on;
opt-out in first-run setup or privacy custom section 5). That path carries only package name/version
identity — never task or user content — and never auto-upgrades. On a fresh, unconfigured
installation, pre-policy advisory paths are local/cache-only and network-disabled, so nothing
egresses before first-run setup confirms the resulting exact policy. Rerunning setup does not
suspend or revoke an existing standing policy: ordinary service activity remains governed by that
policy until a replacement is committed. True FinishUP zero-network mode is the
composite of `local_only`, the global ceiling off, and all five network channels disabled (including
turning update checks off). That mode still permits only exact release-profiled local IPC required
for the FinishUP service, confidential helper, approved local model, OS credential/user-presence
service, and session-lifecycle monitor; it does not permit arbitrary AF_UNIX destinations.

An independent review-context profile controls which potentially useful material is selected before
those disclosure rules run: `structural`, `goal_aware`, `assisted`, `expanded`, or `custom`. The
recommended `assisted` packet includes goal, obligations, claims, decisions, material timeline,
deterministic finding bases, coverage and change-observation facts, plus bounded problem-local
recorded evidence/test/failure/diff/source excerpts. It excludes sensitive/confidential content by
default and carries an explicit omission reason when content was not recorded, selected, or allowed.
Missing source never means “no code changed.” FinishUP does not browse the filesystem to fill a
semantic-review packet. The one repository read is the **check-time change** (ADR-031): when the
review recipe selects diff excerpts, the service reads the task's own repository once per check,
with Git's hooks, helpers, filters and network transports disabled, and renders the change from the
commit the task started on (for a task started before this version, the commit at its first check)
to the working tree, including untracked files Git does not ignore. Because that base is a commit,
uncommitted work that already existed when the task started is included too; untracked files that
already existed then and are unchanged since are left out, because the task-start base also records,
encrypted, the names of the untracked files and a digest of their file metadata (never their
content), and the commit each nested repository held with the same names and digests for its own
untracked files. A nested Git repository inside the task's repository has its own change read from
that commit, under every fence below, at most eight per check, and its untracked files are left
out or shown exactly like the outer ones. When no commit was recorded for a nested repository the
outer one tracks (for example, a task started before FinishUP recorded one), its change starts from
the commit the outer repository records for it, and the header says that commits made in it before
the task may then be included. When a nested repository's untracked files were not recorded whole
(for example: the task started before FinishUP recorded them; the repository was created during the
task, had no commit when it started, came after the eighth nested repository or was refused by a
safety check; or its untracked names did not fit the record, could not be stored in it, could not
be examined or could not be listed in time), they are named but their content is never read,
because any of them may predate the task; they count as not shown.
The same read also carries up to four read-only task input files the task statement names (or that
the task declares as inputs), each at most 16 KiB, only when the file is inside the repository, is
unchanged since the task started, is not ignored by Git and is not credential-named. A tracked file
counts as unchanged only when the task's own starting commit was recorded, Git compares the file
normally (a file marked skip-worktree or assume-unchanged is never read) and its bytes match that
commit exactly. The statement is read only to find those names; nothing about a skipped file is
kept. Files
named like credentials (`.env`, `.env.*`, `.netrc`, `*.pem`, `*.key` and similar) are listed by name
only; that list is a name heuristic, not a detector. Links and files with a second name, tracked or
untracked, are listed without their content or line counts: Git may open a link target while it
works, but that output is discarded and never enters the change. Every Git object a shown diff reads
must hash to its own name through an object store that is neither reached through a link nor
borrowed from another repository, every Git call is pinned to the validated repository directory and
its own `.git`, and the read fails closed if that directory is replaced between Git calls or the
working tree keeps moving. A directory replaced and put back within a single Git call is not
detected. A later review clears an AI-powered finding despite these limits only when it saw each
file the raising review saw, whole or through an identical view; for a file shown in part each check
records a keyed commitment to where its redactions and hunks lay, never its content, so a moved
redaction or hunk keeps the finding open. The change is redacted before it is stored: a concrete
credential shape reads `[REDACTED]`, and a value that only looks like a credential reads
`[withheld-by-yoetz:possible-credential]`, so the reviewer is told the value was withheld rather
than shown a marker it could take for code. It is stored
encrypted, and offered to the privacy gateway as bounded `repository_excerpt` items under the same
policy and never-send scan: a policy whose inference channel does not allow repository excerpts
never sends it, and the check says the review's context was withheld. Everything else must already
be captured or agent-published in the frozen case. The separate ADR-011 `finishup state capture`
support command may read one explicitly named local Git worktree and return only bounded structural
state digests. It returns no source or path content. Neither it nor the check-time change gives MCP
clients or review providers a repository handle.

The upstream recommendation appears only for an exact installed endpoint whose current versioned
data-use record states customer-content training `prohibited`, retention `none|bounded`, and
provider human access `prohibited|restricted`. This is inspectable provider-profile evidence, not a
technical guarantee that FinishUP can prove downstream provider behavior. Known-broad, unknown, or
stale posture removes the recommendation. The recommended recipe visibly enables a current-evidence runtime guard; a
technical user can turn that guard off through a custom policy, but that choice no longer carries
the upstream no-training recommendation.

The v0.1 working manifest ships a transport only for structural package update checks. Product
telemetry, crash diagnostics upload, and capability testing remain unavailable/off; policy cannot
create dormant consent for them, and a future installed capability requires a fresh local-human
transition before it can send anything.

## Non-overridable never-send content

Candidate or user content containing the following must never become model input or another
approved disclosure:

- encryption keys and recovery or unlock secrets;
- passwords and candidate/user-discovered API keys, authentication tokens, cookies, or private
  certificates;
- keyring contents, credential files, hidden authentication configuration, or unrelated
  environment variables;
- opportunistically accessible raw databases, unrestricted logs, stderr, or complete transcripts;
- unrelated files or content outside the authorized workspace/task/request scope.

No privacy profile, plugin, provider label, MCP request, agent message, authorship, or human click
can waive this set. Classification and scanning are defense in depth; uncertain content fails closed.

## Your own terminal is not a disclosure

Two local audiences are deliberately kept apart.

Ordinary human-readable output on your own terminal is its own sink. Reading a finding you asked
for, on a vault you unlocked, on your own machine, is not a disclosure to anyone, and no privacy
answer gates it. An unconfigured install still shows you your own findings in full.

Releasing content into an *agent-capable host* is a different sink, and that one is gated — because
that host may forward its context to its own provider, and FinishUP can neither see nor promise
anything about what happens there. That gate is conditioned on authorship. An agent always receives
back the material it published and the deterministic findings computed solely from it: that content
is already sitting in its context, so withholding it would protect nothing while breaking the very
check-and-respond loop the tool exists for. Material the agent did not author — another agent's
work, imported records, and a semantic reviewer's prose — stays gated until you widen it.

Authorship never unlocks a data class. Sensitive/confidential content and the never-send set above
remain absolute at every sink, no matter who wrote what.

The same boundary applies to structural subject-state capture. `finishup state capture` is a local CLI
operation: it hashes the explicitly selected worktree without networking and emits only closed
metadata and digests to the invoking terminal. It does not persist file contents or names, inspect
an arbitrary MCP-supplied path, populate a semantic-review packet, or prove who made a change. If
the worktree cannot be bounded and hashed safely, the command fails without returning a state
digest.

Resolved decision F-012 permits a separately provisioned provider credential to leave the vault
only through a fresh one-attempt handle as
authentication metadata to the exact profile-bound HTTPS endpoint selected by the reviewed
provider registry, with platform CA trust and hostname validation. v0.1 does not claim certificate
or SPKI pinning. The credential never enters the model body, context,
preview, receipt, log, environment, configuration, or reusable SDK state. Encryption, unlock, and
recovery secrets have no such exception. Choosing literal zero credential egress would disable
credentialed external providers.

The separate `external_runtime_oauth` authority never takes a credential from the FinishUP vault. For
the exact Codex subscription profile, Codex owns ChatGPT login, refresh, credential storage, and
the upstream OpenAI body. FinishUP supplies only a secret-free one-attempt authority and the already
approved case through app-server stdin. A dedicated Codex home may be named in nonsecret config;
FinishUP never reads, hashes, copies, logs, exports, or stores its credential bytes or account email.
There is no API-key, proxy, generic OAuth, or undocumented-endpoint fallback.

## Local models and human authority

A local model receives plaintext only after the same classification, minimization, scope, and
never-send checks. FinishUP itself uses an exact AF_UNIX-only path and performs no model launch,
download, DNS, or IP networking. A separately running model process is nevertheless a trusted
local disclosure sink unless its exact support cell proves enforceable no-network sandboxing.

Durable policy widening and provider-credential changes require action-bound OS user presence or
the purpose-specific YZH1/YZS1 confidential reauthentication path of an established passphrase
vault. Ordinary MCP/agent schemas cannot grant that authority. Exact foreground approval may authorize one
`confirm_every_request` case already inside durable policy; it cannot widen policy or create a
reusable grant, and it is not cryptographic proof against arbitrary malicious same-UID code.

Under the recommended standing policy, the model's challenge is delivered to the main agent through
the ordinary finding surface. The agent can acknowledge and act, provide evidence, revise its
claim, dispute with evidence, or state an unresolved limitation, then runs a fresh check. None of
those routine agent-to-agent steps requires a human. Humans remain required for policy widening,
credential set/rotation, explicit `confirm_every_request`, and finding waiver. Never-send or
out-of-scope material cannot be approved by anyone.

A usable OS keyring does not itself prove action-bound human presence. Under the current safe
default, pristine automatic keyring initialization requires both verified keyring create/load and
an exact artifact-bound user-presence adapter. Without both, the service writes no vault/keyring
artifact, remains `uninitialized/locked`, and lets a local human explicitly choose passphrase
setup—never as a silent fallback. That explicit choice requires proven-pristine local state,
allocates a fresh installation identity, and may proceed when keyring is locked/unavailable without
claiming it proved entry absence; committed passphrase mode never later probes or uses keyring. An existing keyring vault may remain ready for local work when
user-presence authority is measured unavailable at ready/recomposition, or when a human-control
operation explicitly observes its failure; external activation and durable authority changes then
stay fenced until fresh validation. v0.1 does not claim an asynchronous presence watcher and ships
neither a separate admin-authorization secret nor an unverified platform-presence fallback. Adding
either later requires an explicit ADR amendment.

## Local evidence and configuration

Each successfully reserved terminal outbound decision and every physical attempt produces a local
structural receipt with destination, policy/scope/category decisions, sizes, transformations,
consent source, bounded outcome, and—only for a physical attempt—a keyed commitment to the final
application bytes at the FinishUP-controlled boundary. For HTTP profiles those are the provider body
before authentication metadata. For `external_runtime_oauth` they are the disclosed FinishUP case;
Codex's upstream body is explicitly unavailable, and separate runtime evidence binds the exact
launcher/config/protocol/model/output boundary. Waiting for a human, approval, and
consumed-but-unreceipted work
remain resumable internal states, not finished receipts. If the initial audit reservation itself
fails, FinishUP fails closed before preview/authorization/dispatch and returns bounded `audit_failed`
without fabricating a receipt; this is the sole no-receipt decision exception. Receipts contain no
request body, credential, header, path, raw response, or unbounded provider error. Content-bearing
v0.1 privacy proposals are encrypted in their owning task bundle; taskless unavailable-channel
decisions contain structural data only. A future taskless content-bearing channel requires a new
reviewed encrypted-audit storage contract. The installation privacy catalog—not a fabricated task-
ledger row—keeps each proposal object live for the supported installation-data lifetime. v0.1 has no
individual privacy-audit-content deletion operation: ordinary task redaction and orphan cleanup do
not remove these objects. Verified backups include their encrypted bytes plus a structural audit
sidecar; restore never revives pending approval or dispatch authority. LLM inference consent is
independent of telemetry, crash diagnostics, update checks, and capability testing.

## Live harness observation (first-party Codex)

Observation consent is separate from egress consent. Enabling first-party Codex observation requires
one project-level confirmation recorded as a private workspace commitment (never a raw path in
logs, status, or receipts). Revocation stops new ingestion and retains already-kept evidence.

Observation never retains hidden reasoning or complete transcript prose. Sensitive bounded evidence
lives only in encrypted objects; plaintext observation state is allowlisted structural fields plus
commitments. On vault or service outage FinishUP never creates an unencrypted transcript spool.
Semantic review receives only minimized approved packets. Secret-like command output never appears
in status, logs, hook advice, or semantic packets. Live observation uses local control methods, not
a seventh MCP tool; advice surfaces through nonblocking hooks and ordinary `status`.

To tell a rerun of the same command from a different one, the hook computes an installation-keyed
commitment (`hmac-sha256:`) to the lightly normalized command of a shell tool call and discards the
command text in the hook process. Only that keyed value is stored, shown in `status`, or sent to
the local service; the command text itself is never persisted, displayed, or sent for this
purpose, with or without content consent. A plain hash is never used, because a short command
would be guessable from it, and the same command yields a different value on another installation.

The enforceable technical contract, setup behavior, schemas, fixtures, and remaining empirical or
independent-review release gates are specified in:

- [`docs/adr/ADR-009-data-egress-privacy.md`](docs/adr/ADR-009-data-egress-privacy.md)
- [`docs/protocol/data-egress-and-privacy.md`](docs/protocol/data-egress-and-privacy.md)
- [`docs/protocol/privacy-setup-wizard.md`](docs/protocol/privacy-setup-wizard.md)
- [`schemas/privacy/privacy-policy-1.0.0.schema.json`](schemas/privacy/privacy-policy-1.0.0.schema.json)
- [`docs/OPEN_QUESTIONS.md`](docs/OPEN_QUESTIONS.md)

A claim with concrete checked-in test or fixture coverage is flagged `evidenced` in
[`docs/public-claims.json`](docs/public-claims.json), with its non-live suites exercised in per-PR
CI. A claim whose own wording names still-missing capability or drill evidence remains explicitly
“not yet evidenced” and is not asserted as release evidence.

## How to inspect or report a privacy problem

Everything FinishUP decides about your data is designed to be inspectable locally. Privacy policy
answers are plain reviewed configuration you can read and edit; every terminal outbound decision
and physical attempt leaves a local structural egress receipt; and the installation privacy
catalog keeps encrypted proposal objects and their structural sidecars enumerable for the
supported installation-data lifetime. No control surface is required to trust a summary: the
receipts, catalog, and policy file are the evidence, and they live on your machine.

If you believe FinishUP has disclosed, retained, or logged something these commitments forbid,
treat it as a security report: use GitHub private vulnerability reporting or email
`support@finishup.dev`. Never open a public issue for a report that may itself contain sensitive
content. Ordinary non-sensitive questions about privacy behavior belong in repository issues.
The repository security policy ([`SECURITY.md`](SECURITY.md)) defines the private routes; they are
verified before any release that advertises them.

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
