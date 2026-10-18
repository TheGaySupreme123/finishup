# Privacy and AI-powered review

The full user-facing promise is [`PRIVACY.md`](../../PRIVACY.md). The enforceable technical contract
is [`docs/protocol/data-egress-and-privacy.md`](../protocol/data-egress-and-privacy.md) and
[ADR-009](../adr/ADR-009-data-egress-privacy.md). This page is the operator's view: what the
defaults are, and what changes when you turn something on.

## Two defaults, deliberately separate

An unconfigured installation is **external-LLM-egress-free and local-only**. No task content
leaves for a provider. The independent structural package update channel may be on unless disabled;
local checks, findings, and receipts all work in this state.

Turning on external AI-powered review is a separate, explicit decision. It is not implied by
installing, by binding a provider, or by having a credential.

An MCP host can impose a stronger process-local ceiling with `finishup mcp serve --semantic off`. That
strict route cannot request external AI-powered review even if durable policy is widened later. It
is separate from the policy profiles below; see [Auto-approving an MCP
route](auto-approving-agents.md).

## Which tasks use AI-powered review

Every task starts with FinishUP's local checks unless you chose AI-powered review on every task.
Within the privacy policy you approved, your setting decides who may turn AI-powered review on for
one task:

| Setting | What happens | Change it with |
| --- | --- | --- |
| Agent opt-in (recommended) | Tasks start local; your agent turns on AI-powered review for a task when it helps, without asking you again. | `finishup privacy conversations agent-opt-in` |
| Owner approval | Tasks start local; each review an agent turns on waits for your approval, like **Ask every time**. | `finishup privacy conversations owner-approval` |
| Local only | Agents may not turn on AI-powered review; every task runs local checks only. | `finishup privacy conversations local-only` |
| Every task | Every task runs with AI-powered review; an agent cannot switch a task out of it. | `finishup privacy conversations ai-powered` |

`finishup privacy conversations status` shows the setting for the current repository; `/privacy`
in the terminal interface shows it too. Moving toward local checks or your approval applies at
once. Anything that needs less of you is a widening: it applies only after the trusted local
approval, like any other widening. Where this repository cannot send anything for review yet, the
command walks you through the one-time privacy policy that turns AI-powered review on, with your
setting included. A repository's first privacy policy asks this question too, starting on agent
opt-in (or the narrower setting an earlier repository's grant chose); choosing a setting for one
repository never widens what another repository starts with. A repository without a privacy
policy of its own sends nothing for AI-powered review: `status` and `finishup privacy
conversations status` say AI-powered review is not set up there, and where tasks start local an
agent that turns it on for a task there is told to continue locally.

The agent turns AI-powered review on for its task by recording one decision. That decision is a
request, never a grant: what may be sent is still exactly what this policy allows, the never-send
set is always withheld, and every disclosure gets a receipt. The task's checks and `status` say
which mode the task is in and name the decision; the task's receipt lists each switch, the
identity that recorded it, and the mode its check ran in, and a task that stayed local says so.
Other tasks are not affected, and a new task starts local again. A task that used AI-powered
review still gets its closing review before its receipt, even after going back to local checks.
If the agent turns it on where it cannot run, the task stays local and the check says why and
what to run: you chose local only, AI-powered review is not set up for the repository yet
(`finishup --set`, then `finishup --privacy`; `finishup provider status` shows what is missing),
AI-powered review is turned off in your verification settings, or the agent's connection was
registered local-only (`finishup setup run --route-profile policy`). When you choose local only,
no work is sent for AI-powered review from then on, even for a check that was already running.

A policy approved before this setting existed keeps its behaviour: with AI-powered review on, every
task is reviewed (an agent cannot switch a task out of it); without it, tasks run local checks only,
and status says AI-powered review is not set up rather than that agents may not use it.
Background project advice runs only when every task is reviewed.

## Native work evidence is a separate choice

The default host integration records structural observation. When you explicitly select a host's
versioned ordinary-work artifact, it can also prepare bounded native content for that host. Selecting
the artifact does not enable content capture. Content capture is a second, reversible choice for the
same repository:

```text
finishup observe content-enable --workspace /exact/project \
  --profile claude-code-ordinary-observation-v1
finishup observe content-status --workspace /exact/project --json
finishup observe content-disable --workspace /exact/project \
  --profile claude-code-ordinary-observation-v1
```

Status keeps configured profiles separate from locally effective capture. A configured profile is the
profile you selected; local status lists it as effective only while observation consent is active and
the local runtime gate is enabled. Retaining plaintext additionally requires that exact profile in
the mapped task's consent grant. Local status does not establish that task-level permission; without
it, ingress drops content chunks. Pausing observation or disabling the runtime gate preserves the
configured choice but empties locally effective capture. Disabling a profile removes that choice.
Connecting another host to the same repository, or confirming observation consent again, keeps the
content capture you enabled. Only disabling the profile or revoking observation consent turns it
off; after a revoke, enable it again if you still want it.

Native content capture and AI-powered review have separate authority. Enabling a host profile does
not authorize external review, choose a provider, or permit any content to leave the computer.
AI-powered review still requires its own provider readiness and repository privacy decision
described below.

## The four LLM privacy profiles

`local_only`, `confirm_every_request`, `minimal_external`, `trusted_provider`.

The terminal interface names these in ordinary words — **Local only**, **Ask every time**,
**Minimal external review**, **Trusted provider** — under `/privacy`. The words are a label for
the same durable profile; nothing about the policy changes because the wording is friendlier.

Trusted-provider permission always binds named categories, a purpose, a scope, a provider, a model,
and an endpoint profile. It never means "send everything available."

Enabling one channel authorizes no other. Telemetry, crash diagnostics, update checks, and
capability testing have their own separate policies. `local_only` governs LLM disclosure and can
coexist with a separately consented bounded structural non-LLM channel.

**True zero-network mode** is the composite of `local_only`, the global ceiling off, and all five
network channels disabled. Even then, exact release-profiled local IPC is permitted for the FinishUP
service, the confidential helper, an approved local model, the OS credential service, and session
paths.

## The never-send set is absolute

Some content classes can never become model input or reach another sink — see the enumerated list in
[`PRIVACY.md`](../../PRIVACY.md). No profile overrides it. No approval unlocks it. Authorship does
not unlock it: sensitive and confidential content stays sensitive no matter who wrote it.

Effective policy loosens only through a reauthenticated decision you make: the trusted local
ceremony, or your explicit current-chat approval of one exact prepared, previewed, expiring consent
target that a capable agent relays for you. That relay is the agent's assertion, which FinishUP cannot
independently authenticate, so the local ceremony remains the stronger path. Loosening is never
silent: every path shows the complete change before you decide. The machine row is an installation
ceiling; external LLM work also needs an exact granted row for the current repository beneath it.

Secret-shaped text that only looks like a credential (an assignment to a name such as `token`) is
redacted in place when it would leave your machine: only the value is replaced, by
`[withheld-by-yoetz:possible-credential]`, and the rest of the line and file is still reviewed. The
check reports `semantic_review_value_redacted`. If a value cannot be replaced safely, FinishUP withholds
only the item that carries it and reviews the rest; the check lists the withheld items and reports
`semantic_review_item_withheld`. Checks, receipts and `status view=operation` name each affected
item and the line numbers involved, counted within the captured excerpt rather than the whole file
(`semantic_redacted_values`), never the value. Both limit only
the AI-powered review; local checks still see your
work in full, and you never need to change consent or your code to clear them. Only a concrete credential, a private key, or a scanner that cannot finish
blocks the whole review. You never need to hide or git-ignore a requested output to keep it out of
review.

What FinishUP records on your machine follows the same split. A concrete credential shape (a known
API-key or access-token format, a private-key header, or a password inside a URL) is replaced before
anything is stored. Text that only looks like a credential is kept as captured in the encrypted
local store, so local checks see your work as it is; it is replaced only when content would leave
your machine. The one exception is the change FinishUP reads from your repository at check time for
review (described below): it is redacted as it is read, so a concrete credential reads
`[REDACTED]` and a value that only looks like one reads `[withheld-by-yoetz:possible-credential]`.
The reviewer is told that both markers are values FinishUP withheld, never your code, so a line such
as `password=[withheld-by-yoetz:possible-credential]` is not reported as a broken expression.

### Turning the possible-credential filter off

The replacement of text that only *looks* like a credential is a filter you can turn off for the
external AI reviewer, for example when it keeps hiding values your review needs and you know they
are not secrets. The setting belongs to the current repository:

```text
finishup privacy credential-heuristic disable   # this repository: stop replacing look-alike values
finishup privacy credential-heuristic enable    # this repository: turn the filter back on (default)
finishup privacy credential-heuristic disable --machine-default   # default for new repository grants
finishup privacy credential-heuristic enable --machine-default    # restore that default
```

Turning it off means values assigned to names such as `password`, `secret`, `api_key` or
`*_token` are sent to the external AI reviewer as written, instead of as
`[withheld-by-yoetz:possible-credential]`. Everything that stays on your machine keeps the
filter: what FinishUP shows your agent and what a local model reviews are filtered exactly as before.
It never affects the never-send set: a known credential shape, a private key, a password inside a
URL, or a scanner that cannot finish still blocks or redacts exactly as before.

Because more may leave your machine, turning it off is a loosening of this repository's privacy
grant: it applies only after you approve it in the trusted approval on this terminal, which shows
it as **Possible-credential filter: On → Off**. If the repository has no grant yet, the command
walks you through the ordinary grant approval with the filter off, so the setting becomes part of
the grant you approve; nothing is granted without you. No agent can turn it off for you. Turning
it back on is a tightening of the same grant and applies at once, to this repository only. The
installation-wide default (`--machine-default`) is what a new repository grant starts from;
changing it does not change a repository that already has a grant.

`finishup status` and the agent's status show, before any check runs, whether the filter is on for
this repository and what the installation default is; `finishup provider status` and `/privacy`
show the same pair, and `finishup privacy show` names the installation default when it is off. A
repository without a grant has nothing to turn back on; `enable` then tells you to use
`--machine-default`. While it is off, every privacy receipt for an external review
made under it records it, and every check whose external AI-powered review ran under it reports
`semantic_review_credential_heuristic_disabled`. That code describes your choice, not a problem
with the agent's work. The setting is part of your privacy policy, so
`finishup privacy export-desired` and `apply-desired` carry it too, through the same approval.

### Letting review read files outside the workspace

Some tasks keep their specification, data or the code being ported outside the repository, in a
shared folder such as `/shared/legacy_app`. FinishUP never reads outside your repository unless
you admit the folder for this repository:

```text
finishup privacy input-roots add /shared/legacy_app   # admit a folder (asks for your approval)
finishup privacy input-roots remove /shared/legacy_app  # stop admitting it (applies at once)
finishup privacy input-roots status                   # list the admitted folders
```

Name an existing folder by its full path, with no link on the way. The filesystem root, hidden
folders and system folders such as `/etc`, `/proc` and `/dev` are refused, and up to eight folders
can be admitted. Admitting a folder lets more leave your machine, so it applies only after you
approve it in the trusted approval on this terminal, which lists the folders under "Information
disclosed". It needs this repository's privacy grant; no agent can admit a folder for you.

After that, when the task statement names a file inside an admitted folder, or names the folder
itself, the reviewer can receive up to four such files, each read the way task inputs are: never a
hidden or credential-named file, never through a link, never a file or folder another user can
write, and always through the same redaction and never-send checks. A file inside your repository
is never read this way, even when the folder you admitted contains your repository, and neither
is a file only a test command your agent ran mentions. Nothing is read unless your review policy already sends repository excerpts, so
Private and Metadata only send nothing from these folders. `finishup privacy show`, `/privacy`
and the status command above show what is admitted.

## Commands

```text
finishup --privacy                 # the AI-powered review options or the recommended policy (below)
finishup privacy setup             # equivalent guided policy review
finishup privacy show              # current effective policy
finishup privacy tighten           # tighten (proceeds through gates)
finishup privacy propose           # propose a change for decision
finishup privacy decide-policy     # approve or deny one exact pending policy proposal on the terminal
finishup privacy export-desired    # effective nonsecret policy as desired-state TOML (never secrets)
finishup privacy apply-desired     # apply desired-state TOML; tighten may proceed, widen never silent
finishup privacy credential-heuristic disable|enable  # external reviewer's possible-credential filter, per repository
finishup privacy input-roots add|remove|status        # folders outside the workspace review may read, per repository
finishup privacy pending           # list disclosure decisions waiting for you
finishup privacy decide-disclosure # decide one exact pending disclosure by id (see below)
finishup privacy receipts          # inspect bounded structural egress receipts
```

`finishup privacy receipts list` pages through every receipt of what FinishUP showed locally and sent
off the machine, newest first; pass `--cursor` with the `next_cursor` it prints to read the next
page. If a stored receipt cannot be read back, the listing does not fail: it prints every receipt
it could read, reports `undecodable_count` and the skipped receipt ids, explains the partial page
on stderr, and exits `40` so a script cannot mistake it for a complete listing. Run
`finishup privacy receipts get <receipt id>` for each skipped id; a receipt that cannot be read is
reported as `privacy_audit_unreadable` with a correlation id for `finishup service diagnostics`.
`invalid_request` means only that the command itself was wrong, such as a cursor from a different
listing.

You can also ask a capable FinishUP agent to install, configure, or change FinishUP in ordinary
conversation. The agent should explain each consequential choice, recommend an option and its
trade-off, perform the mechanical steps, and leave the decision with you. If you explicitly ask
for AI-powered review, it recommends **Expanded review** first for the deepest useful in-scope
review and explains that it permits broader problem-relevant context; **Assisted review** is the
lower-disclosure AI-powered alternative. Metadata only and Private remain available. Choosing a
recipe is not yet approval: the agent prepares one exact combined change and shows it before asking
you to approve or deny it.

On an authority-capable Codex route, that prepared view includes every substantive `before ->
after` policy row, the provider/model/endpoint binding, repository commitment, current and
candidate policy digests, diff and authority digests, expiry, and one-use target. Your explicit
current-chat decision can complete exactly that action. Any repository, policy-generation, route,
recipe, target, expiry, or replay drift stops with no policy or provider mutation. A host without
the required chat-authority capability gives the shortest trusted-local continuation instead of
silently choosing a different policy.

`privacy pending` exists for one situation: `privacy decide-disclosure` needs an exact pending id,
which normally arrives in the check result that is waiting on it, and that id can be lost — a
closed terminal, an agent that did not relay it. The listing names the decisions you can still
make and their expiry, and nothing about what any of them would disclose. Destination, categories,
and prepared bytes belong to the decision preview, which is bound to the exact prepared case and
is the only surface that renders them.

`export-desired` / `apply-desired` are the reviewable path for version-controlling policy. The
asymmetry is the point: tightening can flow through gates, widening always requires a human.

Privacy commands bind to the repository derived from their actual working directory. The service
resolves symlinks and Git's common root and commits it under the installation key. It never stores
the raw path; it keeps it in memory for that connection only, so a check can read the change
described in [What AI-powered review actually sends](#what-ai-powered-review-actually-sends).
Branches and linked worktrees share authority; independent clones and unrelated repositories do not.
A task's public `workspace_ref` is not consulted.

With a reviewer bound, on a repository's first privacy policy or where tasks start local under
agent opt-in or owner approval, `finishup --privacy` lists the AI-powered review options: Private,
Metadata only, Assisted review, Expanded review and Custom, with **Assisted review** as the default
choice. It is marked recommended only when the exact configured provider route has a current
reviewed data-use record stating no default training and retention no longer than 30 days; on any
other route (a ChatGPT subscription among them) nothing is marked recommended and the Assisted
draft records no data-use evidence requirement, which the review screen states. **Private**
stays selectable and says that every task stays on local checks under it.

Otherwise (no reviewer bound, or an existing policy that is not set to agent opt-in or owner
approval), the CLI recommends
**Assisted review** when the exact configured provider route has a current reviewed data-use
record stating no default training and retention no longer than 30 days, and **Private**
otherwise. Assisted review is exact-repository-scoped and problem-local, and does not prompt
before each request once its policy is committed; its tradeoff is that selected ordinary user
content may be sent. **Metadata only** remains available as the minimal-disclosure option —
public structural metadata and declared file types, task scope, and a foreground approval before
every provider request — and is the profile that makes `privacy pending` matter. Accepting the
displayed exact policy asks nothing further. Declining it opens Private, Metadata only, Assisted
review, Expanded review, and Custom; a named recipe goes straight to the exact review, and only
**Custom** opens the underlying settings, grouped into five sections. The final trusted widening
decision is never skipped.

### `/privacy` in the terminal interface

`/privacy` shows the current posture and the one recommended policy — Private when no exact provider
route has current reviewed no-training evidence with retention no longer than 30 days, Assisted review
when one does — with both what accepting it buys and what it
costs. It then offers exactly three choices: `Keep current`, `Review recommended change`, and
`Other privacy options`. `Other privacy options` lists the same five recipe names the CLI uses.

The interface takes **no approval of its own.** Choosing anything but `Keep current` suspends the
interface and hands the controlling terminal to the same `finishup privacy setup` flow, ordinary
proposal, and separately reauthenticated trusted decision used by the CLI — and that trusted screen
is where the exact `before → after` policy diff is rendered and where the widening is authorized.
If terminal handoff is unavailable it prints `finishup privacy setup` and changes nothing. Tightening
likewise stays on the existing policy gate. `local_only` remains the default and the interface
never moves off it on its own
([ADR-017](../adr/ADR-017-full-screen-terminal-interface.md) decision 5).

### What the trusted approval screen shows

Before a widening is authorized, the trusted terminal prints every security-relevant field the
proposal moves as a plain-English `before -> after` line, grouped by destination, information
disclosed, authorization, limits, and local visibility, with the ones that make privacy less
restrictive marked `(!)`. Simultaneous tightenings appear too, unmarked, so you see the whole
change rather than half of it. The service sends structured field/value records and never
explanatory prose, and the wording is fixed locally by FinishUP. The diff digest is printed underneath
and labelled for what it is: integrity evidence binding the decision to exact bytes, not a
description of the change.

The agent-chat decision surface renders the same structured substantive diff. It is not allowed to
show only a digest and call that informed approval; the digest binds the bytes while the readable
rows explain what changes.

When a fallback endpoint is paired (see [Providers](providers.md#pairing-a-fallback-endpoint)),
the destination group carries a second row, `Fallback provider and model`, directly under
`Provider and model`. Adding or changing it is a widening and is marked `(!)`; removing it is a
tightening and appears unmarked. The approval covers exactly the two named destinations —
nothing is sent to the fallback before that decision, and nothing else ever becomes a fallback.
`finishup privacy setup` shows the same pair before asking, as `Destination` and
`Fallback destination (after the primary cannot serve)`.

Custom privacy setup asks separately whether to authorize the configured fallback, naming its
provider and model. Declining keeps the policy bound to the primary alone. Named review recipes
include the configured pair in the review screen before approval.

## What AI-powered review actually sends

When you choose **Assisted review** (the default choice, marked recommended only for a provider
route with reviewed data-use terms), the CLI shows and confirms a standing
exact-repository policy that sends the reviewer a structured packet: the goal, obligations, claims, the
material timeline, local findings and their exact bases, coverage gaps, and bounded
problem-local excerpts of evidence, tests, diffs, or source **already recorded in the case**, plus
the **check-time change**. It also carries the earlier AI-powered findings still open, what the
reviewer asked for, and your recorded responses to them, so the next review can rule on each one.
These are the same finding and response records the case already held; no new kind of data is
sent for them.

The check-time change is the one thing FinishUP reads from your repository for review. When the recipe
includes diff excerpts, each check reads the change from the commit the task started on (for a task
started before this version, the commit at its first check) — committed and uncommitted edits to
tracked files, plus untracked files Git does not ignore — from the repository the check's own
connection named (only when that directory is the repository's own working tree: a repository whose
Git settings point its working tree elsewhere is not read), and shows it to the reviewer first, with
a header naming every changed file. Files you declared as outputs come first, then small files,
then the rest from smallest to largest, then generated files (build output such as `dist/`,
lockfiles, minified bundles and source maps, unless you declared them as outputs), so when the
change is cut for room your deliverables and source are kept and scratch and build output go
first. A generated file is still listed in the header, marked as placed after the other files. It covers edits made by scripts and commits that no hook captured. A declared output that
lives outside the repository (for example `/output/result.json`) is never read by FinishUP itself; when
the case already holds a capture of it (output a hook recorded, or evidence the agent published
that names it), that capture is carried with the same priority as the change, under the same
redaction and never-send checks, and listed in the review input like every other excerpt. Because the starting point is a commit, uncommitted work that was already in your
working tree when the task started is included too. Untracked files that were already there when
the task started and have not changed since are left out of the change and only counted in its
header, so the reviewer never reads them as your agent's additions; one that changed is shown whole
and marked as having existed at the start. To tell them apart, FinishUP keeps, encrypted with the task,
the names of the untracked files present when the task started and a digest of their file metadata,
never their content. A Git repository nested inside yours (for example an `api` directory that is
its own repository) has its own change read from the commit it held when the task started, which
FinishUP keeps with those names, and shown under its directory, at most eight per check; one that
cannot be read safely is named in the header with the reason. FinishUP keeps the same names and
digests for the untracked files inside each such repository, so they are left out or shown exactly
like the ones in yours. When that commit was not kept for a nested repository yours tracks (for
example, a task started before this version), its change starts from the commit your repository
records for it, and the header says that commits made in it before the task may then be included.
When the untracked files inside a nested repository were not all kept (for example: the task
started before this version; the repository was created during the task, had no commit when it
started, came after the eighth nested repository or failed a safety check; or its untracked files
were too many for FinishUP to keep, had names it cannot store, could not be examined or could not be
listed in time), they are listed by name only and their content is never sent, because any of them
may have been there before the task; the header says so and counts them as not shown. When the
task statement names files the work depends on, such as a specification, a rulebook or the source
being ported (or the task declares them as inputs), up to four of them
travel too, each up to 16 KiB, but only when the file is in your repository, has not changed since
the task started, is not ignored by Git and is not named like a credential. A file Git tracks
travels only when the task's starting commit was kept, Git compares it normally (a file marked
skip-worktree or assume-unchanged never travels) and its content still matches that commit
exactly. A test or fixture file a recorded verification command ran is offered the same way, so the
reviewer can read the assertions behind a passing run; a test your agent wrote or changed is
already in the change. Task inputs travel ahead of the change, within a quarter of the room for
excerpts and never in the places the change and the latest test run need. A binary, image or data
input (a PDF included) is never sent: FinishUP sends its own short description instead (format, size, image dimensions, an estimated page count, a spreadsheet's sheet names and
first rows, an archive's file names, an array's shape), labelled as FinishUP's description; a value
in it that looks like a credential is replaced by a marker before anything is shortened. A large
untracked data file sends its first and last lines, never cutting through a credential. Task inputs are labelled as task inputs, not as
your agent's work, and pass the same redaction and never-send checks. The reviewer also gets one short
list of the deliverables you declared, whether the change touches each one, and FinishUP's own facts
about them (for example that a deliverable refers to a file you created but did not declare). Git hooks, helpers, filters and network
access are off while it is read, credential-like text is redacted, and each part still passes the
never-send check. Files named like credentials (`.env`, `.env.*`, `.netrc`, `*.pem`, `*.key` and
similar) are listed by name only and their content is never shown; this is a check on file names, so
a secret kept in an ordinarily named file relies on the redaction and never-send checks instead.
Files that are links, or that have a second name elsewhere on disk, are listed but their content and
line counts are never shown; Git may still open such a file while it works, but that output is
discarded and never enters the change. Every stored Git object a shown diff uses must match its own
name, and a repository whose object store is reached through a link or borrowed from another
repository is not read; a local `git clone` that hard-links its objects is read normally. If your
working tree or object store keeps changing while the change is read, FinishUP reads it again, up to
three times, and otherwise reports the change as unavailable rather than send a mix of two states.
Whenever the change is unavailable, the check result, `finishup status` and the receipt say why in one
plain sentence (for example, that the working tree kept changing, or that the repository failed a
safety check). A later review clears an AI-powered finding despite these limits only when it saw
each file the raising review saw, whole or through an identical view; for a file shown in part each
check records a keyed commitment to where its redactions and hunks lay, never its content, so a
moved redaction or hunk keeps the finding open. A task that still carries check records from a 0.3
development build may have a finding resolved by the older comparison of lengths and counts only;
its receipt says so under limitations and, because that resolution was not fully verified, reports
insufficient coverage rather than a clean conclusion. A change larger than the packet is cut and
says so.

The change travels as **repository excerpts**. If your policy's AI-powered review channel does not
allow repository excerpts, the change is never sent, and the check result says the review ran with
part of its context withheld.

Sensitive and confidential content is off. The never-send set remains absolute. The reviewer gets a
packet, not a handle on your repository — composition passes bundled provider adapters no
repository, storage, environment, or transcript handles.

The Codex subscription evaluator follows the same policy and receives the same approved packet.
The difference is credential and transport authority: Codex owns ChatGPT login and internally
constructs the upstream OpenAI body, while FinishUP passes the packet to one exact app-server over
stdio. The receipt commits to the packet and exact runtime cell and says
`upstream_body_observability=unavailable`. It does not claim to know Codex's upstream body. Login,
plan, or model availability never substitutes for repository privacy approval.

For the first grant, the trusted screen may show both a machine-ceiling change and insertion of the
repository row. One authority digest binds the complete preview and one atomic CAS commits both or
neither. An eligible upgrade carry-forward is labeled separately: it preserves the machine bytes,
consumes one bounded pre-upgrade entitlement, and grants no new repository, so it needs no repeated
approval. Older clients and missing repository locators fail closed.

The recipe is only recommended for an exact endpoint profile with a data-use record satisfying
`reviewed_at <= now < expires_at`, training `prohibited`, retention `none|bounded`, and a bounded
ceiling no greater than 30 days. Provider human-access facts remain prominent disclosure
information, but are not a separate recommendation threshold. Known-broad, unknown, or stale
posture removes the recommendation.

### The task statement

The reviewer judges the work against what you asked for, not only against the agent's own plan.
Agents pass your request verbatim when they start a task (`task_statement`); the reviewer receives
it as its own section, labelled as the agent's transcription, and is told it is the specification
and wins over the plan (which is labelled "agent plan (the agent's own summary)"). When no
statement was supplied, the task title stands in and is labelled as a title. After an
AI-powered review, the receipt's limitations section says which one the reviewer had: your
request as the agent transcribed it, or at most the task title.

This is new content, so it has its own consent. Goal-aware, Assisted and Expanded policies approved
from this version on include it; Structural never does; Custom only when you list the
`task_statement` section. A policy you approved before this version is not widened: the statement
stays on your machine, and checks and receipts say `task_statement_not_authorized` until you
approve a current recipe with `finishup --privacy`. The approval screen, `finishup --privacy` and
`finishup privacy show` say in plain words whether the task statement is sent. Your prompt as captured
by the host is never used for review.

### How many excerpts the reviewer sees

Each review sends selected excerpts of recorded evidence, command output and changes, within limits
you approved: at most 16 KiB per excerpt and 128 KiB of excerpts in total. The Assisted recipe also
caps the count at 16 excerpts. From this version the Expanded recipe allows up to 64, so on a long
session the byte budget, not the count, decides how much the reviewer sees. The byte limits and the
per-case ceilings (256 KiB, 65,536 estimated tokens) do not change.

An Expanded policy you approved earlier keeps its 16-excerpt limit until you approve the new
recipe. `finishup privacy show` and `finishup --privacy` show your current limits beside the ones the
current recipe offers, and the approval screen marks the higher count as a widening. When many
large excerpts would push a review over your per-case ceiling, the review carries fewer excerpts
and says so (`content_unselected`) instead of being refused. Content your review channel does not
send does not count toward that ceiling. The packet's own structure always counts, and when a
fallback destination is set, anything either destination may receive counts, so the estimate never
comes in under what is sent. A review packet with more excerpts or
bytes than your policy allows is still refused, never cut down to fit. To go
back to 16, choose Assisted in `finishup --privacy`, or propose the earlier Expanded limits with
`finishup privacy propose`. A lower limit is a narrowing, so it needs no new approval.

## How review comes back

Inside that confirmed policy, review is direct-to-agent. The reviewer returns a bounded challenge to
the main agent, which can act, supply evidence, revise its claim, dispute with evidence, or state an
unresolved limitation — then recheck. The reviewer can also ask the agent a question. The agent
answers each review finding with a reason, and the next review sees that answer (and the agent's
answers to FinishUP's own findings) and rules on it; a reply that names an earlier finding comes back as
a new finding linked to it. Routine checks and retries need no human prompt.

The reviewer works as a verifying reviewer: it checks the change against the task and the recorded
verification against the change. It judges recorded test and command output itself instead of
asking the agent to run it again, reports every distinct problem it finds (up to three per review),
and names the exact missing item when it needs more. It knows it is the review that was asked for,
so it does not report its own review, FinishUP checks, findings, or limits on what its packet could
carry as problems in the work, and it never asks the agent to install tools or change the
environment. It does flag delivery risks it can see, such as an import the recorded environment
lacks or files written outside the requested location, and it tests an "impossible" or
"infeasible" conclusion against what the task asked for. A limitation outside the agent's control
is acceptable when disclosed; one the agent could reduce is not support. Work left open while completion is claimed is still reported, and so is a real
discrepancy in the agent's own record, such as a completion claim beyond the plan or a recorded
command that differs from the one observed. Every provider — the Codex subscription, OpenAI, and
OpenAI-compatible endpoints — gets the same instructions. Track a required review by choosing
`semantic_required` for each check, not as a plan item.

When the reviewer cannot assess the packet and names recorded content FinishUP already holds — the
output of a recorded run, its exact command, or a captured edit the packet had no room for — FinishUP
answers inside the same check: it sends the packet again with that content first and asks again, up
to three times. Each follow-up packet follows the same policy, limits and never-send rules as the
first and is its own disclosure with its own privacy receipt, and the content added this way takes
at most half of the packet's excerpt room. FinishUP tracks what each packet carried part by part, so
the parts of a long capture the first packet had no room for can still be added, and a part already
sent is never sent again as if it were new. When the reviewer asks for the current diff of a file
an earlier captured edit changed, FinishUP also sends that file's current section from the change it
read for this check, never a fresh read of your repository. The check records the last answer; the
check result and the receipt say which follow-up round it answered and what FinishUP added. A
follow-up that fails ends
the check the way a failed review does. Anything else the reviewer names (the task statement, plan
or claim text, or material only the agent can record) still comes back to the agent as before.

AI-powered output is advisory, provenance-labeled, and fenced by fixed rules. It never silently
becomes local-check truth, and it never upgrades a coverage claim.

A reviewer concern is not thrown away because one of its citations or its quote cannot be checked.
A quote is kept only when it matches text the reviewer was actually sent, and the result shows that
sent text word for word; otherwise the quote is removed and the result says so. A concern that
cites only material the review did not carry becomes no finding, but its wording is added to the
review summary as an unverified concern, so the agent still sees it.

If a fallback endpoint is approved and the primary could not serve — repeated timeouts,
connection failures, or rate limits, a quota exhaustion, or a missing credential — the same
approved packet goes to the fallback as a fresh attempt with its own authorization and privacy
receipt; under Metadata only that is its own foreground approval. An answer the primary actually
gave is never re-asked elsewhere. The result and receipt then name the fallback as the provider,
model, and endpoint that served and carry `fallback_from`: the primary, how many attempts it was
given, and the exact reason it was abandoned. The markdown and text receipts say which endpoint
served and why the primary could not, so a review that came from the fallback is never mistaken
for one from the primary.

## Auditing it

Every terminal outbound decision and every physical attempt leaves a local structural egress
receipt. Policy answers are plain reviewed configuration you can read. The installation privacy
catalog keeps encrypted proposal objects and their structural sidecars enumerable.

No control surface is required to trust a summary — the receipts, catalog, and policy file are the
evidence, and they are on your machine.

Installed-wheel proof for issue #139 remains outstanding until two consecutive real AI-powered
checks in one approved repository have distinct authorizations, credential handles, dispatch
identities, AI-powered review provenance, and terminal privacy receipts, and a second repository is
shown blocked. Router downstream/fallback grants and issue #141's foreground disclosure continuation
remain separate work.

For an `external_runtime_oauth` profile, the equivalent attempt identity is the secret-free
runtime authority plus exact runtime evidence, not a vault credential handle. Post-acknowledgement
ambiguity is terminal `outcome_unknown`; it does not mint a replacement attempt.

Starting a session takes priority over the optional background review, so a review already in
flight can be cut short. Once a request has been authorized and sent, that cannot un-send it: the
receipt for that attempt is recorded as `transport_failed` with reason `outcome_unknown`, which
says the request left your machine and its answer never came back. Nothing is sent again. If the
service stops before the receipt lands, it is written once when the service next starts, before any
new request can go out. The background note for that session is marked cancelled and names the
attempt and provider it reconciled, so `finishup privacy receipts` accounts for every authorization
that was spent. A cancelled note that names neither means nothing was sent.

When you are auditing a run rather than the installation, the
[AI-powered review dogfood runbook](../runbooks/semantic-dogfood.md) gives the preflight and the provenance
gate: which route the agent actually got, and how to read `semantic_provenance`.

Read `semantic_provenance` together with `semantic_status` and `semantic_reason`, never on its own.
The outcome is three-way, not two-way: on the statuses where the protocol forbids provenance, null
means **no provider attempt was made**; where it requires provenance, an attempt happened (which is
not the same as it being useful); and `failed`/`coordinator_failure` is unconstrained, so it is
**indeterminate** — never read it as "not attempted".

If you believe FinishUP disclosed, retained, or logged something these commitments forbid, treat it as
a security report: [`SECURITY.md`](../../SECURITY.md), not a public issue.

### Reviews that take longer

Codex subscription reviews default to a 15-minute total budget. An explicitly configured shorter
budget stays in effect; `external_runtime.timeout_seconds` accepts up to one hour. A host tool can
stop waiting before the review finishes. Recover with the same check request and request ID:
`OPERATION_PENDING` means the existing check is still running. Repeated waits do not start another
review or reset its budget. A completed result still needs to qualify before it can resolve a
finding or support a completion claim.

While a review runs, `status` with `view: "operation"` and the check's request ID shows where it
is: queued, case admitted, runtime starting, account and model validation, provider sampling,
response validation, cleanup, or terminal. It also shows the attempt number, the elapsed time,
the fixed deadline, and the time remaining. After the review ends it shows the outcome and its
reason. This read answers even while the check is still running; other status views wait for
the check to finish. In the terminal interface, a running check shows the same phase and elapsed
time, and `/progress` reads the latest check again. An `overdue` condition means the deadline
passed without a recorded result; retry the same check request ID to recover it.

Progress names phases only. It never shows prompt or response text, streamed tokens, reasoning,
token counts, your account, or credentials. A phase is not evidence that the review is correct.
Checks started before this version show no progress.

### Routine checkpoints and final reviews

A Codex subscription review uses one of two budget profiles. A check made after your task
records a completion claim, or a check the agent asks to be the closing review (`final_review`), is
a **final** review. It uses the configured final reasoning effort
(`high` by default) and an output limit of 8192 tokens. Every earlier check is a **routine**
checkpoint, which uses the routine effort (`medium` for new setups) and an output limit of 4096
tokens.

- **Choosing values.** Choose the efforts during setup. The limits are the optional
  `routine_output_limit` and `final_output_limit` keys in `[external_runtime]` (1–8192).
- **Older subscriptions.** A subscription connected before routine checkpoints existed keeps its
  single effort for every check until you choose a routine effort.
- **What does not change.** The profile is fixed when the check starts, so retries and
  recovery never switch it. It does not change what may be disclosed, how long the review may
  run, or whether it retries.
- **What is recorded.** Every check result and receipt names the exact model, reasoning effort,
  and output limit used. A review whose visible answer exceeds its limit is stopped and reported
  as an invalid answer.
- **What the reviewer judges.** On every provider, a routine checkpoint reports problems in the
  work so far without judging whether it is complete; a final review judges completeness against
  the task: each stated requirement and requested output, with or without a completion claim.
- **The closing review.** The receipt is the last step, so the last review before it is a final
  review. When a task uses AI-powered review (or a check deferred a required review before your
  first edit), its closure checklist lists `closing_review_required` until a final review is current
  after the last change; the check result names the review phase. A change here is an edit, a
  verification run, a switch of review mode, or a command that changed the project's files.
  FinishUP compares the project's files before and after each command your agent runs, so a
  command that only reads (a timestamp, a search, a status check) does not ask for another closing
  review. A command whose effect FinishUP could not establish (one still running in the
  background, one that left a program it started still running in the project folder, a project
  too large to compare quickly) does, and the reminder says so. To tell whether a program is still
  running there, FinishUP looks at your own processes that started during the command: only their
  working folder and the files they have open for writing, on this computer, kept nowhere and sent
  nowhere. Inside version-control, package and cache folders it compares what matters (settings,
  hooks, and the files directly inside a package or cache folder) and skips their routine
  bookkeeping. Effects outside the project folder, such as a database or another directory, are
  not compared. `finishup observe status` shows how many commands were compared, how many could
  not be, and why (for example a command still running in the background), with the last 64 by
  call. A closing review that returned no judgment (its answer was lost, it timed out, or the
  provider was unavailable) is not asked for again. Follow that check's own advice, which allows
  at most one new check; otherwise finish. FinishUP's closing notes say AI-powered review did not
  return a judgment, and the receipt lists the review as not completed.

### Cancelled background review

A foreground session attachment may cancel optional background review. Once disclosure authority
is consumed, cancellation cannot prove that nothing was sent. The gateway records the owed
`transport_failed` / `outcome_unknown` receipt through a shielded write. It also parks the bounded
receipt before dispatch so a later service startup can reconcile an interrupted attempt, before
admitting new attempts. Reconciliation never sends again or restores spent authority. The
background result remains cancelled and retains available attempt and provider provenance.

## Receipt text your agent can read

Your agent reads its receipts in JSON, markdown and text under your privacy policy. Normal receipt
prose, section titles, counts and coverage codes stay readable. When a receipt names a repository
file that your policy keeps from agents (for example a file the check found but no participant
published), only that name becomes `(receipt prose withheld: repository_excerpt)`; the rest of the
sentence stays. The same file written as `./artifacts/model.npz`, or as a full path (starting at
`/`, `~`, `$HOME` or `file://`, in quotes when a folder name has spaces), is withheld too, and so
is a file at the top of your repository written that way, even without an extension. A plain word
that happens to match a file name stays readable. A name your agent published itself in the same session returns to it. The list of omitted
fields tells your agent where something was withheld; for a very large receipt it names the
containing sections, and a field that would grow too long ends with a visible
`[receipt text truncated after withholding: ...]` note. Asking for a full local profile or another
format does not give your agent more access. Older receipts follow the same rule when read again.

Every receipt is the agent's view unless you ask for yours, because a program can make any terminal
look like yours. To see your full receipt, run `finishup receipt --owner-view` yourself, or choose
*Your full receipt* in the terminal interface. FinishUP then asks you to confirm it is you, for that
one receipt only, and shows it once; your privacy policy and your agents' access do not change.

On a Mac, FinishUP confirms it is you with a system dialog: Touch ID, or your login password. Your
terminal prints a confirmation code first, and the dialog shows the same code; approve only a
dialog whose code matches a request you just made yourself. An agent that runs the command in a
terminal of its own can make the dialog appear, but it cannot answer it for you. Cancelling the
dialog, or leaving it unanswered for a minute, shows nothing, and FinishUP then waits a few seconds
(longer after repeated misses, up to five minutes) before it raises another one. Another program
can cause that wait too; restarting the FinishUP service (`finishup service restart`) clears it. If
another confirmation is already open, perhaps one an agent started, the command says so and
names its own code instead of opening a second dialog: cancel any dialog whose code you do not
recognise, and never approve one you did not start. If nothing is on screen, `finishup service
restart` ends the other confirmation.

This works with either secure storage choice, including the system keychain, whose vault
passphrase you were never shown. The dialog appears on the screen of the Mac session where the
FinishUP service runs, not where you typed the command. If you are connected over SSH while the
service runs in your desktop session, the dialog appears on the Mac's own screen; if you chose
your vault passphrase yourself, run `finishup receipt --owner-view --use-passphrase` to type it
instead. A FinishUP service that cannot show a dialog at all (for example one started from an SSH
session) is expected to report that, and then FinishUP asks for a passphrase you chose. It does not
ask on its own for a passphrase kept in the system keychain, since you may never have seen it:
there it says the full receipt is unavailable, and `--use-passphrase` lets you type one you chose.
These SSH cases have not yet been checked on a real Mac.

The dialog guards against agents that cannot read your keychain, not against everything running
as you: a program running as your account that can read the system keychain entry can confirm
with that passphrase instead of the dialog.

On Linux and on Windows through WSL 2 there is no system dialog yet, so FinishUP confirms it is you
only with a vault passphrase you type. A system-keychain installation there keeps a generated
passphrase you were never shown, so its full receipt stays closed for now. Where no one can answer
the prompt, or the vault has no passphrase at all, FinishUP says the full receipt is unavailable and
shows nothing. Either way `git status --short` in your repository lists what your change created.
On any system, after three wrong passphrases FinishUP waits 30 seconds before accepting another,
longer after more, up to five minutes; the command says so, and restarting the service does not
clear that wait.
