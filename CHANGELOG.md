# Changelog

FinishUP was previously called Yoetz. All notable user-visible changes to FinishUP (named Yoetz
through 0.2.5) are documented in this file. Format is a lightweight, project-native heading style
that marks the pending version as unreleased above reverse-chronological released versions.

## 0.3.0 — Unreleased

Public-alpha release candidate; publication remains gated by #785 and by the rename's release
gates on #1056. This heading takes the release date when 0.3.0 is tagged. See
[release notes](docs/releases/v0.3.0.md) for changes and validation limits.

### Yoetz is now FinishUP

- **The product is renamed FinishUP** (#1055, [ADR-048](docs/adr/ADR-048-finishup-rebrand-and-frozen-legacy-identifiers.md)).
  The PyPI and npm package and the command are `finishup`; new output, receipts, guidance and the
  files written into agent hosts use the new name. Existing installations need no migration:
  - An installation first made as Yoetz keeps its data, vault, keyring binding and settings in its
    Yoetz-era folders, used in place; nothing is moved or rewritten. `finishup service status` and
    `/doctor` say when those folders are in use. Folders under both names (a lone `config.toml` counts)
    are refused as `installation_root_ambiguous` rather than guessed; service commands, `setup
    status`, `provider status`, agent tools and the terminal interface name that refusal and its
    remedy instead of reporting the service as unavailable.
  - Every `YOETZ_*` variable is still read when its `FINISHUP_*` twin is unset; two different values
    fail as `config_env_conflict` (`isolation_root_env_conflict` for the isolated root). New host
    registrations carry both isolated-root names. `.yoetz/checks.toml` is still read when it is the
    only policy (`policy_ambiguous` when both exist).
  - Codex, Claude Code and Cursor registrations, plugins, skills and admission grants made by Yoetz
    keep working and are reported as `legacy_only`, `duplicate` or `foreign`; integrate and the
    guided connection migrate an owned one in one reviewed preview that lists every earlier-name
    item it removes, disconnect removes both spellings, and anything FinishUP cannot prove is its
    own is left untouched. Migrating one Claude Code project leaves the shared `yoetz-local`
    marketplace for other projects; Codex deletes `.agents/plugins/yoetz` only once nothing
    activated still reads it.
  - `yoetz://` guidance URIs, `mcp__yoetz__*` tool names, `yoetz-blocker:`-style decision markers,
    `yoetz` command heads in results from an older service, and receipts naming package `yoetz`
    are still recognized.
- **A transitional `yoetz` distribution** is published to PyPI and npm at the same version for one
  release. It installs `finishup` and keeps a deprecated `yoetz` command, so released `yoetz upgrade`
  lands on FinishUP in place and hosts connected through the old tool keep running. The alias
  prints a one-line notice in interactive terminals only. Until you move, any `finishup` command
  shown works as `yoetz` with the same subcommand, and update tips, the upgrade plan and consent
  requests started through `yoetz` name `yoetz`. Move with
  `uv tool install --compile-bytecode --managed-python --python 3.14.6 finishup` (plus any
  extras; `finishup upgrade` prints the command), reconnect each host in each project you
  connected, and for Codex take the steps `finishup setup status --host codex` lists until it no
  longer says the registration under the earlier name `yoetz` stays beside `finishup` (that kept
  entry still starts the `yoetz` command from the old tool); then `uv tool uninstall yoetz`. See
  [Upgrading from Yoetz](docs/usage/upgrading.md#upgrading-from-yoetz).
- **Some identifiers stay spelled `yoetz` permanently** under protocol 0.1, because they live inside
  stored or released bytes: ledger protocol tags, object and vault formats, crypto domain
  separators, keyring service names, the SQL schema, wire enum values such as `yoetz_owned`, the
  `yoetz.<name>/<n>` tag namespace, actor ids, marker file names, and the released schemas with
  their `$id`s under `https://schemas.yoetz.dev/0.1/`. They are not leftovers.
- A consent prepared before the upgrade stays reviewable after it, with the warning it was prepared
  with, and expires within 15 minutes as usual.

### Added

- Codex stream parsing defers ledger mapping imports until needed, reducing cold hook startup
  work while preserving public import names, parser profiles and wire bytes.

- Provider packet supply markers now have a packaged row schema and golden vectors. A follow-up
  round whose requested excerpts are entirely withheld reports them unavailable with empty
  supply refs; room cuts still report pending. The dispatch remains counted.

- Codex admission commands accept `--codex-path` and `--codex-home`. Multiple installed versions
  can read an agreeing registration without manual selection; disagreement has an explicit
  continuation and cannot grant admission; the refusal is `host_admission_codex_binary_inconsistent`.

- **Every task starts local, and your agent turns on AI-powered review when it helps.** A task
  runs FinishUP's local checks until the agent records one `decision_recorded` 1.1.0 switch with
  `review_mode: "ai_powered"` (and `"local"` to turn it back off); later checks that omit `mode`
  then run AI-powered review within your privacy policy, and other tasks are unaffected. Your
  setting decides who may switch: agent opt-in (the new recommended first-run answer), owner
  approval (each review waits for you), local only (agents may not opt in), or every task.
  `finishup privacy conversations agent-opt-in|owner-approval|local-only|ai-powered|status` changes
  and shows it per repository; widening it needs the trusted local approval, narrowing applies at
  once. `check` and `status` carry `review_mode` (the mode, why, and the switch), the CLI, terminal
  interface and MCP text say "Review mode: local (FinishUP)" or "Review mode: AI-powered review"
  with the reason, and a task that asked and still runs local gets the exact command to run (one-time
  reviewer setup, the owner's local-only choice, or re-registering a local-only host connection).
  A receipt names each switch by sequence, event id, the actor the ledger recorded (with its
  assurance) and the declared authority, and says how its check ran ("ran local checks only
  (FinishUP); AI-powered review was not requested for this task" for a local task). A local
  task's checks complete at local coverage, and its closure readiness and the Stop gate ask for no
  AI-powered review it will never run; a task that already used AI-powered review still gets its
  closing review from the Stop gate's `check` with `final_review: true`, even after it runs local
  again. Under "every task" (and on installations set up earlier that review every task) an
  agent's switch to local changes nothing, so it can never drop a required review. The owner's
  local only is enforced at the privacy gateway as well, including for a check already in flight,
  and a failed read of the setting runs the check local. A switch is a request, never a grant. Guidance `review.md` says when to turn it on and
  when to stay local, with the exact draft; the startup card points at it. Same MCP path on Codex,
  Claude Code and Cursor (#1068, #1073, ADR-049).
- `check` accepts `"mode": "inspect"`: a read that records nothing, mints no finding and runs no
  review. One call returns what is left to close and whose move each gap is (the agent's, or a gap
  in FinishUP's own observation), what the host's hooks observed since the last check, and whether each
  obligation's resolution evidence links to its declared deliverables or requested commands
  (`evidence_off_declared_items` when it does not); obligations whose evidence has no such link are
  listed first, and the answer counts every obligation and every such case even when the list is
  shortened. Available through MCP `check` and `finishup check` on every host; your agent host
  approves it as it approves any `check` call (#1048, ADR-047).

- When the AI-powered reviewer answers `insufficient_packet` and names a recorded run's output, its
  exact command, or a captured edit FinishUP holds but had no room to send, the same check now sends
  the case again with that content first and asks again, up to three times, instead of handing the
  request back to the agent. Each round is its own disclosure under the same privacy policy,
  limits and never-send rules and its own durable review job; requested content uses at most half
  of a packet's excerpt room; the review input manifest's `follow_up_round` and `missing_inputs`
  show what was added on the check result, MCP and CLI text and every receipt format. Only what a
  sent packet actually carried counts as shown, so content composed but left out for room is still
  supplied, and a request naming any part of a multi-part captured edit is answered (#1047).

- A failure only on probes the agent wrote itself beyond the task's stated scope is now
  `agent_criterion_unmet`: the agent's own criterion, not a task requirement. Fix it, or narrow it
  by responding `acknowledged` with the reason, which discloses it as a limitation and does not
  block. A reviewer's `task_requirement_unmet` whose only cited work is the agent's own runs beyond
  the task's declared verification, while that verification holds, is recorded the same way
  (#1043).

- AI-powered review now sees the change inside a Git repository nested in yours (an embedded
  repository or a submodule-style checkout), counted from the commit it had when the task started;
  one that cannot be read safely is named in the change header with the reason. Its untracked
  files are treated like yours (those already there when the task started and unchanged are left
  out); when FinishUP could not list them whole at the task's start (for example, a repository created
  during the task, one with no commit yet, one past the eighth, one a safety check refused, or one
  whose untracked files did not fit), they are named but their content is never sent, because any
  of them may predate the task. Up to four files the task statement
  names (a specification, a
  rulebook, the source being ported) travel with the review as bounded task-input excerpts when
  they are in the repository, unchanged since the task started (a tracked file only when its
  content still matches the task's starting commit and Git compares it normally), not ignored and
  not credential-named. The reviewer also gets one list of the declared
  deliverables with FinishUP's facts about them; a command's older output is never shown as its
  latest; and untracked files that predate the task and are unchanged are no longer shown as the
  agent's additions (the task's encrypted starting point keeps their names and a metadata digest,
  never content). The packet's byte budget is unchanged (#1045).

- When a host starts your agent again after a context compaction, FinishUP now adds a short recap of
  what it recorded to the context the agent is given: the held task, session and writer ids, the
  head frontier, the plan counts, the readiness state, open obligations, findings waiting for an
  answer, the latest check's verdict and frontier, the declared deliverables, and one next-step
  sentence. Every line names its source (the status view and ledger position, the check, the hook
  mapping or the local outbox), withheld text stays withheld, and it is bounded to about two and a
  half thousand characters with a line naming anything left out. It is a read of `status`: it
  records nothing and is not evidence. Codex and Claude Code show it; Cursor does not report a
  compaction, so nothing changes there (#1027, ADR-044, `docs/usage/after-compaction.md`). The
  compact `status` item also carries `latest_check` (the latest check's event, examined frontier and
  verdict) when a check is recorded, and each `obligations` item says whether it is
  `in_current_plan` (a waived or superseded obligation is listed but not current).

- When the external reviewer's copy of your work had a possible credential replaced or an item
  withheld, checks, receipts and `status view=operation` now name the item and its line numbers
  (`semantic_redacted_values`; never the value) and tell the agent, once, that local checks saw the
  values and it should verify the repair itself and respond `self_verified` rather than reshape its
  work (#982).

- You can turn off the possible-credential filter for the external AI reviewer in one repository
  with `finishup privacy credential-heuristic disable`, and back on with `enable` (#982). Off, values
  that only look like passwords or tokens are sent to the external reviewer as written instead of
  as `[withheld-by-yoetz:possible-credential]`; local outputs (agent context, local model) keep the
  filter, and known credential shapes, private keys, URL passwords and an unfinished scan still
  block or redact. The setting is part of the repository's privacy grant: turning it off applies
  only after the trusted approval on your terminal (in a repository without a grant, it walks the
  normal grant approval), and no agent can apply it; turning it back on applies at once to that
  repository. `--machine-default` changes the installation-wide default new grants start from.
  `finishup status` and MCP `status` show the repository state and the default before any check;
  `privacy show`, `provider status`, `/privacy`, every external privacy receipt
  (`secret_scan.credential_heuristic`) and every check whose AI-powered review ran under it
  (`semantic_review_credential_heuristic_disabled`) say so. Existing policies keep their exact
  bytes and digests.

- Local checks now report facts about the task's own work, not only about the ledger (#977,
  ADR-033). Closure readiness, check results and receipts name a planned verification (an
  obligation's requested command) that hooks never saw run, that failed on its latest run, or that
  last ran before your latest edit; an edit after the last test, lint, typecheck or build run; a
  requested output file that is missing (a receipt-blocking finding, even if an action named it),
  git-ignored or excluded, unchanged, or outside the repository; and package installs that went
  into FinishUP's own runtime or a private environment, writes outside the workspace, and
  verification that only ran as root. Matching uses the hooks' keyed command identity; no command
  text or path is stored. The work-integrity pack is now `0.3.0`.

- The Stop hook continues an agent once per ledger state when closure still names its work (open
  obligations, an unrepaired receipt-blocking finding, a missing or stale planned verification, a
  git-ignored requested output), on Codex (`decision: block`), Claude Code (`additionalContext`)
  and Cursor (`followup_message`). Host loop guards are honoured, and every decision is visible in
  `finishup observe status` hook diagnostics (#977).

- A blocker outside the agent's control is now explicit: a `decision_recorded` naming the
  obligations with the statement line `finishup-blocker:<authority|consent|credential|
  dependency_unavailable>`. Those obligations read as a disclosed standing limitation (#977).
  FinishUP cannot verify the claim, so the first Stop after it is recorded asks the agent once to
  confirm each blocked obligation and its kind (status `closure_readiness.blocked_obligations`
  names them). That Stop says that data the task calls recoverable, a failing test or an
  infeasible-looking result is not a blocker. Stopping again honours the blocker without asking
  again. The closing review checks each recorded blocker once against the task and challenges one
  the task contradicts, as an ordinary finding the agent answers with `respond` (#976).

- Hooks classify three closed runtime facts per tool call (`install_target`, `write_scope`,
  `effective_user`; no path or command text) on the unreleased control-request 2.9.0, and
  observation advice 0.1.8 tells the agent once when a package install went into FinishUP's own
  runtime or a private environment, or a write landed outside the workspace. A publish rejected for
  its result `outcome` now names the closed outcome set and the blocker line (#977).

- `finishup closure-prepare --output <file>` saves the complete inventory or prepared request to an
  owner-only file, replaced whole, and prints a short summary, so agents query the file instead of
  preparing again (#916).

- `status view=evidence` accepts `filter.author=mine`, which lists exactly the evidence the
  requesting writer published in its current session (decided by the service from ledger
  authorship, never a caller flag), and every evidence row now names the ledger-recorded
  `publication_channel` of its source event (a cooperative writer can record only `cooperative_mcp`
  or `local_cli`; import and observation channels are service-only). Both are optional additions made in place to the unreleased 0.3 status
  request 1.2.0 and status result 1.4.0. The CLI human status and the MCP text summary show the
  channel. An evidence page now builds only the rows it returns (plus one to find the next
  cursor), filtering before it builds them, instead of every row in the task. Dogfood evidence per
  host remains tracked in #914.

- `status` now tells an agent whether anything is left to do. `closure_readiness` carries a
  `state` and splits what bounds a completion conclusion into `agent_actionable` work,
  `standing_limitations` that the host, capture profile or privacy policy always has, and
  `acknowledged_not_done` items. When only standing limitations remain, `state` is
  `ready_with_limitations` and MCP text, the CLI and the terminal interface say: "Nothing further
  to do. N standing limitation(s) and M acknowledged item(s) will be disclosed on the receipt.
  Request the receipt." A closed, versioned table classifies every gap code, and a build-time test
  fails on any unclassified code. Verdicts, receipt conclusions and coverage are unchanged: a
  local-only check with limitations is still `insufficient_coverage`, and every gap is still
  disclosed (#913). A missing AI-powered review is agent work only where the connection can run
  one: on a strict MCP connection, which never dispatches AI-powered review, it is a standing
  limitation even when the repository policy requires review.
- Every `status` view now reports the same task coverage and gaps as the compact view at that
  frontier. A results, history or evidence view no longer shows the newest record's own
  `current / 0 gaps` beside a partial task (#913).

- AI-powered review now fills its approved excerpt slots with the most valuable content: the newest
  captured edit of each changed file, then the latest recorded output of each verification command,
  then repair evidence, then everything else by recency. Items reach the reviewer in recorded order
  with older hunks and runs marked as superseded; long output keeps its final summary line; an
  oversized plan or claim is clipped instead of replaced by a digest. An `insufficient_packet`
  review must now name what it needed. The check result lists each item and whether you can supply
  it, as a coverage limitation, never a finding. A repeated request stops being listed only after
  you publish new material directly tied to the ref it names: output of the named run or a rerun of
  the same command, a diff covering every file the named edit changed (paths inside your workspace),
  evidence whose reference is the named ref, or a claim correction citing such material. Material
  related only to another file, run or claim does not count. The excerpt count and the privacy
  policy are unchanged (#907).

- AI-powered review now receives the task statement: what the user asked for, apart from the
  agent's plan. Agents pass the request verbatim as `start.task_statement` (or `finishup start
  --task-statement-file`) and may revise it by calling `start` again on the same session (or in a
  `plan_revised` 1.1.0 payload through the CLI); history is kept. The
  packet carries a source-labelled `task_statement` section (`agent_transcribed`, or
  `task_title_only`), bounded to 16 KiB with head and tail kept, and labels the plan item
  "agent plan (the agent's own summary)". The reviewer is told the statement wins over the plan and
  never to ask for behaviour it excludes. Sending it needs the new `task_statement` review section
  in privacy policy 1.2.0 (Goal-aware, Assisted and Expanded presets; never Structural). Existing
  approvals are not widened: checks and receipts say `task_statement_unavailable` /
  `task_statement_not_authorized` until you approve a current recipe with `finishup --privacy`, and
  the approval screen, `finishup --privacy` and `finishup privacy show` say whether it is sent.
  Host-captured prompts are not used (#908).

- The Expanded review recipe no longer stops at 16 excerpts. From privacy policy 1.2.0 it allows up
  to 64, a new protocol maximum, within its unchanged byte budget (16 KiB per excerpt, 128 KiB in
  total), so on long sessions the bytes rather than the count decide what the reviewer sees.
  Assisted keeps 16. An Expanded policy approved earlier keeps 16 until you re-approve through
  `finishup --privacy`, whose approval screen marks the higher count as a widening. `finishup privacy
  show` and `finishup --privacy` show your current limits beside the proposed ones. A review packet
  with more excerpts or bytes than the policy allows is refused as `policy_denied` and is never
  trimmed. A case that would exceed the per-case ceiling is planned with fewer excerpts, and says
  so, instead of being refused. Resuming a stored review rechecks the current limits. Choosing
  Assisted, or proposing the earlier limits, takes you back to 16 without a new approval.
  Content your channel does not allow out no longer costs allowed excerpts their room, and a case
  too large to build is cut to fit with the dropped excerpts named. AI-powered review case
  diagnostics now record the approved excerpt limits and the effective limits the case was built with beside what
  was selected (#907).

- Codex, Claude Code and Cursor session-start context can show a fresh repository-grant snapshot
  and name the owner's missing admission command. The notice leaves route and host approval
  unconfirmed, preserves existing context and spends only spare hook time. No cross-session
  route cache or new retry path is introduced. Native acceptance remains tracked in #857.

- Claude Code's scoped `PermissionDenied` hook now shows the user a notice based on a fresh
  repository grant read and may emit the host's one-retry cue. The same request must be preserved;
  a later hold goes to human approval. No-verdict denials and an unreadable, full or unsafe retry
  ledger offer no retry. Both structural and ordinary capture profiles carry the notice. Claude
  does not deliver `additionalContext` on this event, so the model receives only the host's retry
  cue, not the grant explanation. Shipped guidance keeps grant claims conditional and host approval
  separate. Live acceptance and the remaining cross-host work stay tracked in #857.

- `finishup observe status` now reports what the observation ingress hooks cost on every pass they
  run, not only over-budget ones: `hook_diagnostics.pass_timings` in `--json` and a `hook_pass_timing` line in text give,
  per host, raw hook event and path (Codex `observe` or legacy spool, Claude Code and Cursor
  `structural` or `ordinary` profile), the pass count, mean, p50 and p95 as histogram bucket
  bounds, the maximum, an outcome tally and the last one to two clock hours. The aggregate is
  fixed-size and kept apart from the 64 KiB failure-reason history, which routine passes, including
  every legacy synchronous spool pass, no longer evict. Samples exclude interpreter start and exit.
  Codex `hooks session-start`, `hooks user-prompt-submit` and the `start`-scoped
  `hooks post-tool-use`, and the Claude Code and Cursor `hooks startup-gate` and
  `hooks startup-context` commands are not measured, so the aggregate is not a complete hook cost
  profile for any host. Reading it never creates state, and a read racing an update sees the last
  complete aggregate. Codex `PostToolUse` registration is unchanged until these numbers confirm its
  cost (#915).

- One guided installation and connection lifecycle for Codex, Claude Code, Cursor IDE and
  Cursor Agent CLI, including preview, status, disconnect and reconnect, carried from 0.2.4
  (#767).
- Multiple agents can work in independent tasks within one repository. Parents can delegate
  work, children can register for explicit acceptance, and lineage views and receipts retain
  each child's findings, unfinished work, and observation gaps. Requesting a receipt does not
  close a task or erase a child dependency (issues #494–#504, #509).
- Projects group concurrent tasks and surface declared overlaps under each source workspace's
  existing consent. The CLI supports project creation, membership changes, grouping opt-out and
  opt-in, and generation-bound coordination grants. Retrying a project mutation recovers its
  recorded operation without creating a second project or repeating a membership change
  (issues #505–#508).
- Opt-in required startup for native Claude Code and Cursor plugins, with scope-bound plan
  checks, owner controls, and same-task pending-operation recovery (#692, #797). Native acceptance
  remains bounded as documented in the required-startup runbook.
- `finishup setup status --json` reports each Claude installation's MCP mode (plugin-managed or
  bare) and whether a session-start cue is installed; a bare registration has none (#789).
- Observation capacity can be set to a custom queue count from 64 to 8,192 rows with
  `--capacity custom --queue-count N`, in addition to standard (512), larger (2,048) and largest
  (8,192). Every capacity preview discloses the scope, current and requested limits, possible
  disk, memory and CPU cost, the limits that still apply, and how to lower, pause and resume, in
  the CLI, the terminal interface's `/observe`, and agent guidance. Sessions in a workspace share
  one queue sized by the largest active selection, so an increase says it raises that queue for
  every session; a smaller session count limits only that session. Status reports the effective
  budget and its limiting dimension (#828).
- Requesting No FinishUP cap (`--capacity none`) returns `capacity_no_cap_unsupported` and changes
  nothing: the local observation state has a 16 MiB safety ceiling, so the largest supported
  capacity is 8,192 rows. With `--json` the facts are under `error.capacity` beside the standard
  `error.recovery` (#828).

### Changed

- **Behaviour change:** background AI-powered advice now actually sends the approved, minimized
  advice packet to your configured reviewer where every task uses AI-powered review and your
  privacy policy allows unattended requests (#1019). That is the "AI-powered review on every task"
  answer, or a privacy policy approved before 0.3 that enables AI-powered review; where tasks start
  local (the recommended "FinishUP (recommended)" answer, owner approval or local only), nothing is
  sent in the background (ADR-049 decision 11). The background switch was already on by default,
  but an invalid review envelope meant nothing was sent before. Set
  `observation.semantic_advice_enabled = false` to stop background sends on every host.
- Background advice is skipped under policies that require you to preview each request (the
  Metadata only recipe, or `preview_required` on the AI-powered review channel). It shows
  `advice_semantic_preview_required`; nothing is queued or sent, no approval waits for you, and no
  provider attempt or retry backoff is recorded. Explicit checks keep their preview. The advice
  packet follows your review-context choice (a choice changed while a review waits is applied, never
  the stale one), a policy change that lands mid-request is recorded as not sent rather than as a
  provider failure, the MCP status advice text names the preview skip, and
  `finishup privacy receipts get|list` now marks refused receipts whose category approvals were never
  sent (#1019).

- Rereading `status` without writing now gets a direct answer. From the third first-page `status`
  read in a row by the same agent on the same task with no `publish_work`, `check`, `respond`,
  `receipt` or `start` in between, the result's text leads with one line: no status read is
  needed, and the one next write the result's own closure state names (for example resolving the
  first open obligation with `resolution_evidence_refs`, `respond`, `check`, or `receipt`). Paging
  and polling a running check do not count. The structured result is unchanged, so no schema
  changes; on Cursor the line is a separate block after the exact result copy. The start-of-session
  text and the `status` tool description now say: after resume or compaction, read status once,
  keep the returned obligations and findings, then do the work, and do not reread status between
  ordinary steps (tb4 n5).

- Agent guidance now routes reads to the one section an agent needs. The request templates,
  workflow, coverage and publication pages each open with a map from situation to section anchor,
  so a whole-page read (which returns only the first 4 KiB page of an 80 KiB document) leads
  straight to the template or rule in question; in tb4n5 agents read the whole templates page 34
  times before finding a section. The operating card names each focused topic by its trigger. The
  publication topic adds a checklist to run before sending a batch, the review topic a table for
  answering each kind of finding, and the receipt topic a numbered closing sequence with stop
  conditions. The host skills state the `self_verified` precondition: a later check that still
  cannot prove the repair. No tool, field or behavior changed, and the mandatory startup text
  stays within its 8 KiB budget.

- Reading a long guidance page by its plain address now shows, on its first page, the list of
  sections it contains with their sizes, so an agent reads the one section it needs instead of
  paging; the list comes from the same catalog the reader accepts, so it cannot go stale, and the
  hand-written maps at the top of those pages shrink to the few rows a section name does not make
  obvious. The startup text says each rule once: the Codex and Cursor startup text adds "do not
  list resources", the per-step cadence lives only in the operating card, and the host skills
  drop their repeated start, recovery and cadence lines and keep a one-line capacity consent rule
  that points at the capacity procedure. Each skill's description now also names closure ("a
  FinishUP finding, Stop message or receipt needs an answer"), so hosts that choose skills by
  description load it again when closing, and the operating card says a long page lists its
  sections on page 0. Together that leaves about 420 to 490 bytes of the 8 KiB startup budget free
  on every host. On Codex, the Stop message that asks for a final `check` now repeats the
  `yield_time_ms` setting for that cell, as does the status explanation when a code-mode cell made
  the check stale (tb4n5).

- The Codex subscription AI-powered reviewer now uses the newest Codex you have installed instead
  of one pinned build, so updating Codex is enough. Any stable release from `0.157.1` on is used
  once it passes a capability check, which runs with no sign-in and sends nothing to a model:
  - the app-server protocol still carries everything the reviewer uses;
  - Codex starts a read-only, network-off review thread;
  - nothing unreviewed is reported before a review;
  - your ChatGPT sign-in lists the chosen model.

  `setup` and `repair` try installed releases newest first and fall back to the previous release
  that passes (guided setup keeps this when you accept the Codex it offers; typing another path
  uses only that one). They report the releases they skipped and why. This lets reviews use models only
  newer Codex releases list, such as `gpt-6.1-sol`. A signed-in home whose model no installed
  Codex lists now reports `codex_model_unavailable` instead of opening a new sign-in. Bindings
  made with the pinned `0.157.1` (or `0.150.1`) build report `codex_runtime_profile_outdated`;
  `finishup provider codex-subscription repair` moves them and keeps the sign-in and settings.
  `runtime install --download` fetches the newest Codex, and `runtime remove` deletes the copies
  no binding uses. Receipts keep recording the Codex release, executable digest and capability
  record that ran. Newer Codex output (`partial_answer` messages, new plan names, the
  `flexUnavailable` error) is handled, and unreviewed events still fail closed. Each check kills
  every process the checked Codex started, including ones it left running; if FinishUP cannot confirm
  they are gone, it stops with `codex_capability_probe_cleanup_unconfirmed` instead of trying
  another release. On Linux hosts where Codex's sandbox cannot create user namespaces (gVisor,
  Docker's default seccomp, some kernels), Codex's warning about it no longer blocks setup. The
  reviewer runs no commands and writes no files, so the sandbox confines nothing there.
  `status`, `setup` and `repair` report `codex_sandbox_unavailable`. This applies only to Codex
  releases whose behaviour has been reviewed (today `0.162.1`). Another release sending that
  warning is refused as `codex_sandbox_unavailable_unreviewed_runtime`, and an older reviewed
  release is used instead if you have one. Every other warning still stops setup.
  Authenticated live evidence through a capability-admitted release is pending.
- **Output says "local".** A clean local check now reads "no issue detected
  within local coverage" on the CLI, the terminal interface and MCP; human finding lists label
  their origin "local" or "AI-powered review"; guidance, usage docs and the README follow. The
  terminal interface no longer says "Nothing leaves this computer" for the Private policy or a
  local-only check; it says no work is sent for AI-powered review. Wire values keep their
  spellings: `deterministic_only`, `deterministic_mode` and `no_unresolved_deterministic_findings`
  (#1068).
- **First-run setup asks three review answers, all on the policy route.** "FinishUP
  (recommended): local checks; your agent can turn on AI-powered review for a task when it
  helps", "FinishUP, local only (agents may not opt in)", or "AI-powered review on every task".
  Every answer registers the policy MCP route, so you can allow agent opt-in later without
  reconnecting; the privacy policy alone decides what may be sent. The prompt wizard, the
  host-connection path and the terminal interface's first run ask the same question and set up what
  it chose, and so does `/connect` for Claude Code and Cursor (Codex `/connect` still inspects or
  repairs on its configured route); non-interactive setup keeps the strict default for a fresh
  registration, so an agent driving setup passes `--route-profile policy`. The two answers that add AI-powered review list the privacy options with Assisted
  review as the default (recommended only for a provider with reviewed data-use terms, so a ChatGPT
  subscription is your explicit choice); Private stays selectable and says tasks stay local under
  it. The local-only answer applies on Enter. A repository's first privacy grant asks how its
  tasks use AI-powered review (a chat grant starts on the same default), and widening one
  repository never widens the installation-wide default: a fresh install's first grant gives it the
  hybrid (or the narrower answer), so another project or an independent clone starts local instead
  of waiting for its own grant on every check. A repository without its own privacy grant says
  "AI-powered review is not set up for this repository" in status, the terminal interface and
  `finishup privacy conversations status`, and an agent's opt-in there stays local and says why;
  status says "not set up" rather than "agents may not" for an installation that never chose.
  `finishup privacy conversations agent-opt-in` (or `owner-approval`) in such a repository now
  walks its privacy grant with the setting included instead of reporting no change. With a
  reviewer bound, `finishup --privacy` lists the AI-powered review options (Assisted review by
  default, Private with its warning) on a repository's first grant and wherever tasks start local
  under agent opt-in or owner approval, so a ChatGPT subscription owner is no longer granted
  Private on Enter (on a route without reviewed data-use terms Assisted review is the default but
  is not marked recommended, and the listing says its draft records no evidence requirement); a
  first Private grant reads as local only rather than the hybrid an earlier repository chose. Abandoning AI-powered review setup in the
  terminal interface now finishes as local only without re-registering. Installations set up
  earlier keep their behaviour, checks and receipts until their owner chooses a setting (#1068,
  #1073, ADR-049).

- **New Codex-subscription setups suggest `gpt-6.1-sol` at reasoning effort `medium`** for final
  reviews, and `medium` for routine checkpoints as before. Released 0.2.x setups suggested
  `gpt-5.6-luna` at `high` (unreleased 0.3 builds briefly `gpt-6-luna` at `high`). The suggestion is
  bound only when the Codex that FinishUP adopts lists it. Codex `0.162.1` lists it (checked
  2026-10-14), so setup binds it directly there; on the `0.157.1` floor, setup uses `gpt-6-luna`
  with the same efforts and says so before sign-in. A dedicated home that is already signed in, and
  whose account no admitted Codex lists `gpt-6.1-sol` for, falls back to `gpt-6-luna` once and keeps
  its sign-in. A model you type yourself is never substituted, and upgrading keeps every existing
  setup's model and efforts. A sign-in whose Codex does not list the chosen model or effort now
  names a next step (`codex_model_unavailable`, `codex_reasoning_effort_unavailable`).
- A delivered file that loads a file the agent created but did not declare (a model, a word list,
  a data table) now stops closure instead of being only disclosed: the Stop hook continues the agent
  and names each such file, `status` lists them (`closure_readiness.undeclared_references`), the
  check's next step names the referencing obligation as work (`review_recorded_work`), and the
  receipt stays below clean until the content is embedded, rebuilt at run time, or the file is
  declared as a delivered output. A `full_local` receipt names the files; an export or share receipt
  counts them and names none. Disclosing the dependency no longer resolves it. An untracked file the
  task started with is not counted (#1044).

- A requested output the task writes only under a condition (an incomplete-records ledger, a
  quarantine log for a malformed input) that you declared as a file and that is absent because the
  condition did not occur now has one documented exit: correct the plan. The finding, the workflow,
  publication and request-template guidance and the operating card say to model it as a `change`
  item naming the condition, plus the source files that implement it, supersede the old
  obligation, and replace the completion claim; the next check resolves the absence finding.
  Writing an empty or placeholder file, or changing when your code writes the file, to satisfy the
  declaration is named as wrong. A replacement completion claim may now name only the replacement
  obligations a plan revision recorded. A file the task asks for unconditionally stays required:
  only a `change` item of its own that spells the file's declared path and states its condition
  re-models it; a mention beside another file, a file re-declared as an input, or prose calling it
  unconditional keeps it required.

- An undeclared file now stops closure only when a delivered file may read it. A file the code
  provably only writes (`np.savez(...)`, a frame's `to_csv`, an `open(..., "w")`) no longer
  counts; an unsupported wrapper, `ZipFile.write`, an `open` with no mode, an archive opened for
  append (`ZipFile(..., 'a')` reads its members), or a read before a write still does. A path the code builds from literals (`os.path.join('checks', 'case_0',
  'walk.npz')`) names exactly that file. A bare file name that a declared file shares, or that
  the code never ties to the file's directory, is not treated as a dependency; the receipt
  discloses how many such files there were (`deliverable_references_ambiguous_name`), never which
  (#1044 follow-up).

- When a delivered file may read a file you did not declare and your privacy settings withhold
  its name, the Stop text now says so, says FinishUP shows you only a name you published yourself,
  and tells you to list the files your change created with your own shell and declare them or
  their directory. A name you published yourself in the same session is shown to you. The
  AI-powered review no longer receives these names, or a digest of a check that held them, in a
  check's history at all.

- At Stop, the acceptance re-read now asks only about resolved obligations whose acceptance
  criteria the final answer neither names nor addresses, and names them, on Codex and Claude Code
  (which pass the final answer to the Stop hook); Cursor asks as before. A plain "criteria
  confirmed" answer ends it with no new record, check or receipt; republishing an unmet obligation
  as `acknowledged_not_done` works as before (#1050).

- While work is in progress the AI-powered reviewer judges incomplete work only: something marked
  done that is not, planned verification not run, a missing or emptied output, a done or ran claim
  the record does not show, an early stop. A correctness concern it raises then comes back as an
  advisory note in the review summary, not a finding; the closing review still judges correctness
  and completeness. Challenges about FinishUP's own state (a FinishUP tool call, a hook observation
  awaiting its result), or calling work "never attempted" mid-work, are no longer findings;
  `semantic_process_state_filtered` discloses them without bounding the receipt (#1042).

- A check before the first material edit no longer calls the AI-powered reviewer, whatever its
  mode: it runs the local checks, sends nothing and records
  `semantic_review_deferred_before_first_edit`; the next check after an edit reviews as configured
  and the closing review is never deferred. Where review is optional the deferral is disclosed and
  does not lower the receipt, as a local-only check would not; where it is required it bounds the
  receipt until a review runs, and `status` and the Stop gate then ask for the closing review, so
  work that needs no edit is still reviewed. A check retried after an interruption keeps the review
  decision its first attempt made. A reviewer ruling that a finding is fixed, citing material
  recorded after it, now closes the finding even when the check records environment facts such as
  verification run only as root; those facts stay disclosed on the receipt (#1046).

- Every published action needs a result that names its `act_` id. The workflow guidance and the
  operating card now say so up front, and a `publish_work` result (dry runs included) lists each
  action it recorded that no result names yet in `action_notices`. A second action in the same
  batch no longer raises `action_without_result` for the first; unrelated work in a later batch
  still does. Once a result names the action, that finding resolves even when the check also
  records content-capture limits, which stay disclosed on the receipt.

- The AI-powered reviewer no longer adds its own copy of the local `action_without_result` or
  `result_without_action` finding: a challenge under that label that cites only the unpaired action
  (or orphan result) and its plain output is dropped and disclosed by
  `semantic_process_state_filtered`. One that also cites a claim, an obligation, a paired action or
  a failed run is kept, so failed or unrun verification and false completion are still reviewed
  whatever their label (#1042 follow-up).

- A reviewer ruling that a finding is fixed now counts when it cites the repair by the event that
  recorded it, so a repaired and acknowledged finding the reviewer supports resolves instead of
  ending as a standing disagreement. A ruling the reviewer could not assess, or a `fixed` that cites
  nothing newer, stays an open round and is never recorded as a disagreement; after two such
  rulings on one finding in a row with no edit (four at most), checks stop asking for the review
  and say so, and the finding stays unresolved. A disputed
  finding no longer tells you to repair or self-verify it. Answering a finding a recheck already
  resolved now says that nothing is owed (#1046 follow-up).

- A local-only check you asked for (`deterministic_only`) on a route that does not require
  AI-powered review no longer lists `semantic_review_not_requested` on the receipt, in `status` or
  in closure readiness. Where review is required it is still listed and still bounds the receipt
  (#1041).

- The startup guidance is a compact operating card, enough for ordinary work; the workflow,
  publication, coverage and request-template pages are read on demand. Reading `status` or
  previewing with `dry_run` before every publish is no longer part of the guidance: a publish that
  fails validation appends nothing and names what stopped it (for events, the first rejected event
  and its field), and the agent fixes that and sends it again (#1048).

- `finishup service run` refuses an unusable configuration with `invalid_request: <reason>` (exit 2),
  like other commands, instead of `internal_error` (#1040).

- `requested_item_never_attempted` is no longer raised before the agent has started acting, and
  its repair text no longer suggests revising the obligation as the default exit (#977).

- Checks run the `research-evidence/0.2.0` and `work-integrity/0.2.0` policy packs (work-integrity
  is now `0.3.0`, see #977 above), and status
  reports `gap_classification_version` `"2"`, so results produced under the new task-statement,
  observed-run corroboration and test-edit rules carry their own identifiers. Checks and findings
  recorded under `0.1.0` stay readable, and a later check can still resolve a finding recorded
  before the upgrade. A check request that names a pack must name its current version. The
  publish-work result moves to schema 1.1.0 (control 2.9.0); the released 1.0.0 keeps `0.1.0`.
- Codex and Cursor now receive a compact initialize instructions body (at most 2,048 bytes)
  instead of the 19.8 KB `agent-instructions.md` document, which Codex code mode copied into
  every FinishUP tool description. The body keeps when to call `start`, the no-false-activation,
  consent, disclosure and coverage-wording rules, and tells the agent to read the full safety
  floor with `read_guidance` before the first `start`. The Codex skill gains a code-mode section:
  declaration-only tool discovery, a UUIDv4 helper that uses `crypto.randomUUID()` or
  `crypto.getRandomValues()` when present and falls back to a labelled non-cryptographic
  `Math.random()` source only without `crypto`, and a `yield_time_ms`
  sized to each FinishUP call's deadline. On Codex only, `read_guidance` returns its document once,
  in `structuredContent.text`. Claude Code and the generic host are unchanged. Codex dogfood
  acceptance is pending (#918).

- Background AI-powered observation advice stays switched on by default wherever AI-powered review
  is configured (`[verification] semantic` is `required` or `optional`), so upgrading does not
  change it; it sends only in a repository whose tasks all use AI-powered review (see the
  background-advice entry above, ADR-049). `[observation] semantic_advice_enabled` is now an explicit owner choice: `false` turns
  background advice off and `true` keeps it on whatever the default. FinishUP writes the line only
  when you set it, so a config without it follows the default. `finishup provider status`,
  `finishup setup status --next` and the terminal interface `/status` show whether it is on and why.
  While you have it off, rows queued before you switched it off are closed at service start
  without being sent, so turning it back on never sends old work (#888).

- The served `workflow.md` and `coverage-and-receipts.md` guidance drop repeated wording that the
  combined 0.3 changes had accumulated, so each stays under the 65,536-byte `read_guidance` limit;
  every rule is still stated, and the closure-readiness text now says `acknowledged_not_done`
  findings are recorded while obligations cannot be yet.

- The generic-host initialize instructions (`agent-instructions.md`) no longer state the `client`
  shape and the JSON-string rule for canonical integers twice; each rule is kept once, in the
  canonical-values section. This keeps the combined 0.3 MCP surface inside its reviewed 253,000-byte
  budget without dropping any rule.

- `finishup service isolation --json` now emits the versioned `yoetz.isolation-report/1`. Its
  `path_identity` block replaces the untagged 0.2 `identity` block, whose `config_digest` was a
  digest of the config file's path, not of its content; a consumer detects the 0.2 output by its
  missing `schema` key. `--content-digests` adds a bounded SHA-256, size, existence and time
  observation of the selected config, never its content, and `finishup instance status` reports
  the same `path_identity` block (#567, #571, #807).

- Updating FinishUP no longer requires quitting agent apps or stopping the service. `finishup upgrade
  --accept` runs from inside an open session, which keeps working on the previous version; the
  first FinishUP call of the next session switches to the new version and retires the previous
  service. Upgrading from 0.2 still follows 0.2's stop-first procedure once (#820).
- Updating from 0.2 preserves existing tasks, settings, permissions, and host registrations.
  On ordinary service startup after unlock, supported task ledgers receive a verified backup
  and automatic schema upgrade before new work is admitted. Interrupted upgrades resume from
  recorded progress; failed verification keeps the service unavailable for writes and retains
  recovery evidence (issue #496).
- The 0.3 functionality uses additive control contracts and migrations while retaining the
  released 0.2 schemas and migration bytes. Observation selection, runtime isolation, and
  recovery improvements from 0.2 remain in effect.
- Small status reads reuse immutable projection pages instead of replaying the ledger for
  each query (#748). New Codex subscription review bindings default to a 15-minute budget
  and allow explicit budgets up to one hour; existing explicit budgets remain unchanged (#750).
- Linux sandbox readiness is documented as a fact of the client host, separately from the
  AI-powered review evaluator runtime; this adds no WSL or AppArmor acceptance claim (#765).
- The Grok provider preset names grok-4.6 (#763).
- Native startup guidance is delivered independently of observation consent and availability
  (#692). Claude Code sessions receive a compact MCP initialize block that fits the host's
  observed 2,048-character rendering cap, with the "call `start` first" trigger and the
  late-start rule as its first two sentences (#789); Codex and Cursor now get their own compact
  body (see above), and the generic host keeps the full document.
- Guidance, the Claude skill and `AGENTS.md` state what to do when material work began before
  `start`, and how to load deferred FinishUP tool schemas by name (#789).
- Local control schema 2.9.0 carries custom capacity counts, capacity labels and the effective
  budget; both client and service must run it. Defaults are unchanged (Focused, 512), and a
  saved custom count reads as the default on an older version. Agent guidance and the skills
  say that a larger or uncapped capacity needs a disclosed, owner-accepted preview and is never
  chosen for an ordinary task (#828).

### Fixed

- A non-root user can now use FinishUP in a project directory that root owns, as container images
  commonly set up (`/app` owned by root, the agent running as `nobody` or `agent`). Setup, hooks
  and MCP tools accept such a project root when no other account can write it, or when it is a
  sticky directory, for Codex, Claude Code and Cursor alike. Before, `setup run` failed with
  `internal_error` and host connections with `target_unsafe`. Files FinishUP writes inside the
  project must still belong to the user, and a root-owned Git worktree is used as a plain
  directory, because Git itself refuses another owner's worktree. Claude Code's own executable
  must still be installed as the user who runs it: a root-installed `claude` is refused
  (`target_unsafe`), whereas Codex accepts a root-owned launcher (#1071).

- In such a root-owned project, a checkout that root made (`/app` and `/app/.git` owned by root, or
  your own `git init` in a sticky root-owned `/app`) now works as a plain directory instead of
  being refused at every service connection: the service starts, hooks and MCP attach from the
  checkout's top or any folder beneath it (one identity for all of them), and work is checked as
  published. Git-based change capture does not read it, because Git refuses another owner's
  checkout; the receipt says "the repository failed a safety check (… another owner …)" rather
  than "not a Git repository". Cursor's project registration status, connect and disconnect work
  in a root-owned project, and a Codex disconnect removes the project's `marketplace.json` instead
  of failing half-way on every retry. A `.claude`, `.codex` or `.cursor` folder root committed to
  the image no longer makes revoking auto-review admission, a Codex disconnect or the privacy
  ceremony report a failure; Claude Code's plugin setup and Cursor's project registration still
  refuse such a folder (`target_unsafe`) until root makes it the user's. FinishUP also no longer
  reads or writes host settings in such a folder that another account created (possible in a
  shared, sticky project folder such as `/app` with mode 1777): admission status reports it as
  unknown, auto-review admission and Claude Code's project-scope setup refuse it, and writes go
  through the folder FinishUP checked, never a link swapped in after (#1071).

- `finishup instance create --bind-runtime` on a FinishUP runtime the current user cannot write (for
  example one root installed in a container image) now fails with `runtime_pin_unwritable` and
  removes what it created. Before, it reported `internal_error` and left a half-created instance
  behind, so the retry after fixing permissions reported `instance_exists` (#1071).

- A FinishUP installation whose private runtime directory (`.<name>-releases`, next to the
  installation) belongs to another account is now refused by name, `release_runtime_not_owned`,
  with that directory and the repair that fits: install FinishUP as the account that runs it (or have
  root prepare that directory for that one user), or, when the installation is yours and the
  directory was made by someone else (for example with sudo), remove it and FinishUP recreates it.
  Before, the service, MCP connection and hooks stopped with
  `release_runtime_unavailable: permission_denied` or "could not be verified", and setup connected
  agents to a runtime that could not start. Every way of connecting an agent (`setup run`, with or
  without `--host`, the full-screen interface's first run and `/connect`, the menu,
  `finishup integrate … install` for Codex MCP, Claude Code and Cursor, and
  `finishup recommend accept codex-plugin-activation`) now refuses that connection with
  `release_runtime_not_owned`, and a connection to a runtime another account can write with
  `release_runtime_group_writable` or `release_runtime_world_writable`; disconnect, removal and
  status still work (#1071).

- One Codex home, Claude Code configuration or Cursor configuration now serves several projects
  connected one after another (#1058, #1070). `finishup setup run --host codex` for a second project no
  longer stops with `destination_conflict` and advice to create a new Codex home: it adds only that
  project's pieces and reuses the home's shared plugin and MCP registration. Disconnecting one
  project keeps the shared pieces the other connected projects FinishUP knows of use (Codex moves its
  marketplace binding to one of them; Claude Code no longer runs the marketplace removal that
  uninstalled every project's copy; Cursor keeps the user plugin). The last project's disconnect
  removes them, also when another project's folder was deleted in the meantime or a Codex
  project that held the marketplace binding was deleted or lost its plugin files. `setup status`
  lists the connected projects. Connecting the same directory again through a symlink, a
  different letter case or its old path after a move is refused as
  `project_connected_via_other_path`, with the path already connected and the disconnect that
  clears it. When the shared pieces predate this release, or FinishUP's record of the connected
  projects was lost, FinishUP keeps those pieces on an ordinary disconnect and says so in status and
  the preview (for Codex, only while another project or a trusted checkout carrying FinishUP's
  plugin files may use them; see below). For Codex, the projects this installation of FinishUP connected stay known even if the
  record is deleted, and a trusted checkout that carries FinishUP's plugin files but never connected
  through FinishUP only counts as a project that *may* use the shared pieces: they keep those pieces
  and never take over the home's marketplace binding, and a disconnect that would leave only such
  projects stops with `membership_unverified` and offers reconnecting the project you use or
  `--remove-shared`. A project connected only through another FinishUP installation is not detected
  once the record is lost. Running a Codex disconnect again, or for a project that never
  connected, no longer removes the MCP registration the other connected projects use, also while
  another connected project's plugin files or folder are missing for now (a branch switch, `git
  clean`, an unmounted volume); the disconnect names the project they stay for and, when its
  folder is missing, the home-wide preview that removes them if it is gone for good. Connecting
  a project on another review mode (local only or AI-powered review) changes it for every project
  sharing that Codex home or Claude Code configuration; `setup run`, the terminal interface's
  first-run preview, `integrate codex mcp preview` and `integrate claude plugin preview` now name
  those projects and both modes, and an unattended `--accept` that would change them stops and
  asks for the reviewed preview (Cursor keeps the review mode per project). That also holds when
  FinishUP cannot read which projects use the home (`membership_unknown`), and a legacy registration
  that differs only in how it starts FinishUP no longer switches local-only review to AI-powered
  review. An unattended `finishup setup run|status|disconnect --host codex` without
  `--route-profile` keeps the home's current review mode (local only for a new home).
  `setup disconnect --remove-shared` previews and asks for consent naming the projects that stop
  using FinishUP; the low-level `integrate codex mcp remove` and `integrate cursor plugin remove`
  stay home-wide but now name them too. Two setups for the same agent configuration at once can no longer lose a project:
  setup holds a private lock per configuration in FinishUP's own state folder, so a first Claude Code
  or Cursor setup into a configuration folder that does not exist yet needs no manual `mkdir`
  (Codex still needs its home to exist and now says so), and a lock that cannot be taken stops
  with `connection_lock_unavailable` before anything changes. A damaged connected-projects record
  is reported as `connection_projects_record_invalid` by `setup run`, `setup status` and `setup
  disconnect`, with the file and the way out (make it owner-only again, or restore it). After
  disconnecting projects in any order, each can be connected again (Claude Code previously
  refused the first one with `destination_conflict`).
  A project still carrying its Yoetz-era activation (ADR-048) loses that activation with its own
  disconnect also when the other projects keep the shared pieces; a Yoetz-era MCP entry or Cursor
  plugin folder that other projects may still load stays with the shared pieces until the last
  disconnect, and the disconnect's approval cleanup removes exact earlier-name approval entries too.
  Yoetz kept no record of the projects it connected. For Cursor, a Yoetz-era plugin folder found
  without a record counts as shared pieces whose users FinishUP cannot confirm: an ordinary
  disconnect keeps it, also when only one project used it, and only `--remove-shared` removes it;
  a connect that migrates it keeps that uncertainty for later disconnects, and the disconnect (in
  the terminal interface too) names the `--remove-shared` command. For Codex, a project's own
  Yoetz-era activation goes with that project's own disconnect, never with another project's
  `--remove-shared`. A project still carrying it counts as connected: another project's connect
  records it, and another project's disconnect keeps the MCP registration it uses. Yoetz-era Codex
  tables or a Yoetz-era MCP entry found without a record make trusted checkouts that carry
  FinishUP's plugin files possible users, which keep the MCP registration or stop the disconnect
  as `membership_unverified`; with neither another project nor such a checkout, an ordinary
  disconnect removes the registration. A Codex connect no longer moves the MCP registration from
  the earlier name `yoetz` while a project's Codex settings still need it (such as the approval
  table Yoetz 0.2's `integrate codex admission grant` wrote): moving it made Codex refuse to load
  that project. The earlier entry stays beside `finishup`, and the plan and `setup status` say for
  each project what holds it and what releases it: the exact revoke where only an approval
  FinishUP (or Yoetz) wrote holds it, what to fix in a project file FinishUP could not read, or
  the edited tables to remove by hand. All of a home's projects are read for this; the entry also
  stays while the Codex home's own `config.toml`, its record of connected projects, or a project
  path with a control character cannot be read, and the step says what makes it readable.
  Connecting again once nothing listed holds it finishes the move. Every case also names the
  explicit way out, as your choice: remove FinishUP's MCP registration under both names with
  `integrate codex mcp preview-remove` and `remove`, then connect again; the step says that every
  project of the home loses FinishUP until one connects again, and that a project still naming the
  earlier server stops loading its Codex configuration until those tables go. A connect that would
  also change the review mode stops first, since the earlier entry serves every project on its own
  mode, and offers both the current mode and that way out. A Codex disconnect now also keeps the
  registration when one of those inputs cannot be read, and says so. The interactive `finishup
  setup` approval, `integrate codex mcp install`, the menu and the terminal interface say the
  earlier entry is kept (and whether a project uses it or only not every project could be read)
  instead of promising its removal. After a Codex disconnect that keeps the registration for other
  projects, also for their own Codex settings or because not every project could be checked,
  status reports the disconnected project `configured: false` with `shared_registration_retained:
  true`. A Codex disconnect that removes the shared plugin while the registration stays for a
  Yoetz-era project now says so, and names the projects whose plugin files are missing as losing
  it too.

- `finishup setup disconnect` now removes the selected project's FinishUP tool-approval entry (the one
  `integrate <host> admission grant` writes) as part of the same previewed plan, before the
  registration itself. Previously (Yoetz 0.2.x) a Codex disconnect left
  `[mcp_servers.yoetz.tools.check]` in the project's `.codex/config.toml`; Codex then refused to
  start in that project ("invalid transport in `mcp_servers.yoetz`"), and the disconnect ended
  `incomplete` with the project skill still installed. Claude Code and Cursor disconnects remove
  their entries the same way. After a Codex disconnect, FinishUP checks that Codex still loads its
  configuration in the project. `setup status --host codex` explains such a leftover under either
  spelling, `mcp_servers.yoetz` (left by a Yoetz 0.2.x disconnect) or `mcp_servers.finishup`, and
  prints the exact command that removes it (or, for a table you edited, names the file to fix;
  with both kinds in one file it names which is which and still gives the revoke for the exact
  one), and FinishUP's own Codex registration commands no longer fail because of it. A
  disconnect that cannot remove the entry safely (an approval file FinishUP cannot read, such as a
  symlink, or approval settings you added or edited yourself that still need the FinishUP server)
  now stops before changing anything and names the file to fix, instead of leaving the project
  unable to start. A Codex disconnect keeps the FinishUP server registered while another project's
  configuration uses it, lists those projects, and says when it could not check them all.
  `setup disconnect --remove-shared` removes the pieces shared by every connected project.

- The Codex-subscription evaluator now works on Linux without a system bubblewrap, for example
  in a container that must stay exactly as shipped. Codex 0.162.1's exact "could not find
  bubblewrap on PATH" warning is admitted the same way as its user-namespace warning: the reviewer
  runs no commands and writes no files, so the sandbox confines nothing there. The fact is
  disclosed, not hidden. `status`, `setup` and `repair` report `codex_sandbox_unavailable: true`
  with the new `codex_sandbox_unavailable_reason` (`bubblewrap_missing` or
  `user_namespaces_unavailable`), and the terminal interface says the evaluator runs without
  Codex's verified Linux sandbox. Only reviewed Codex releases are admitted; others are refused
  as `codex_sandbox_unavailable_unreviewed_runtime`. Every other warning, including Codex's WSL1
  one, still stops setup. Approved network-denied checks still need a usable `bwrap`.
  Receipts do not carry this fact yet.

- MCP input schemas now target 4,800 bytes per tool so Codex does not apply its size-triggered
  schema rewrite. Required fields, enums and event envelopes stay inline; full payload examples
  and variant rules are available through `read_guidance` in request templates. Claude Code and
  Cursor use the same compact inputs. Full server-side validation and output schemas are unchanged.
  Field descriptions are preserved when they fit; larger tools keep priority field rules first.
  If a future schema exceeds the budget even without descriptions, the bridge logs a diagnostic
  and serves the minimal form instead of failing startup. CI still rejects oversized schemas.

- Automatic AI-powered observation advice can now reach the configured reviewer through the
  approved review-packet envelope on Codex, Claude Code and Cursor. Scoped gaps and rule metadata
  are retained; finding summaries travel only when their category is approved. Malformed or denied
  advice stays blocked. Privacy receipts now distinguish actual category denials from request or
  packet-assembly failures, while older receipts remain readable (#1019, ADR-009).

- Hooks, the agent connection (MCP) and the service start as fast as an ordinary run again. They
  run from a sealed copy of the installation that held no compiled bytecode, so every start
  compiled the whole package (12 s against 6 s on WSL, 0.9 s against 0.5 s on macOS) and slow
  machines missed the service handshake. The copy now ships bytecode, reusing the installation's
  own checked-hash bytecode when its source hash matches and compiling the rest once (timestamp
  bytecode is never reused); an older copy is rebuilt on the next start. The documented install,
  `npx finishup` and `finishup upgrade --accept` add `--compile-bytecode`, and `npx finishup` and the
  upgrade set `SOURCE_DATE_EPOCH` for uv so that bytecode is checked-hash. A service that is
  still starting when a command gives up is reported as `service_handshake_timeout` (retry)
  instead of telling you to run it under a supervisor (ADR-007).

- FinishUP runs for normal accounts on Ubuntu, Debian, Fedora and RHEL. Their default umask `0002`
  makes every installed file writable by the account's own private group, and with the retained
  release runtime the service, the agent connection (MCP) and every hook refused to start on
  Codex, Claude Code and Cursor with only "The retained runtime could not be verified". The same rule refused such
  users' repositories (`unsafe_root`), Codex launchers and host settings folders
  (`target_unsafe`). Group write now counts as owner-only when the local account files prove the
  group is the owner's own private group with no other member (machines whose accounts come
  from a directory service such as LDAP or SSSD still need `umask 022`); world write, or group write through a group someone else
  is in, is still refused, now as `release_runtime_group_writable` or
  `release_runtime_world_writable` with the exact `chmod -R go-w …` repair on `finishup service run`,
  `finishup mcp serve` and `finishup upgrade`, on `finishup service status` and other commands that find
  no service, and in `finishup setup`; hooks name the token without local paths and still make no
  decision. `finishup upgrade --accept` and `npx finishup` install under umask `022` (ADR-007).

- A receipt your agent reads no longer shows the names of repository files your privacy policy
  keeps from agents, even when the agent asks for a full local profile, in JSON, markdown and text.
  Only the name is replaced with `(receipt prose withheld: repository_excerpt)`, including when it
  is written as `./path` or as a full path (starting at `/`, `~`, `$HOME` or `file://`, quoted when a
  folder name has spaces), a top-level file without an extension included; the rest of the receipt stays readable, and a name
  the agent published itself returns to it. A receipt with many withheld names still renders: past
  its bound the omitted-field list names the containing sections, and an over-long field ends with
  a visible truncation note. Older receipts follow the same rule when read again (#1069, #1073).

- Every result the CLI and the terminal interface show (receipts, status and the rest) now follows
  the agent's privacy view, as it already did over MCP: a terminal is not proof that you are the one
  reading, since an agent can run FinishUP in a pseudo-terminal of its own. To see your full receipt,
  run `finishup receipt --owner-view` or choose *Your full receipt* in the terminal interface, and
  confirm it is you; the view is for that one receipt, once, on that command's own connection. On a
  Mac, FinishUP confirms it is you with a system dialog (Touch ID or your login password) that shows
  the same confirmation code as your terminal, so a system-keychain installation, whose vault
  passphrase you were never shown, can open its full receipt too. A passphrase you chose still
  works: FinishUP asks for it when its service cannot show a dialog, or directly with
  `--use-passphrase` (for example over SSH), but never asks on its own for a passphrase it keeps in
  the system keychain. Cancelling the dialog or leaving it unanswered for a minute shows nothing,
  and the next dialog waits a few seconds, longer after repeated misses; too many wrong passphrases
  say so instead, without suggesting a service restart, which does not clear that wait. If another
  confirmation is already open, perhaps one an agent started, the command says so and names its own
  confirmation code instead of reporting a locked vault; every confidential ceremony now reports
  another open one as `ceremony_busy` and a throttled passphrase as `reauthentication_rate_limited`
  (wait up to five minutes), where both used to read `state_forbidden`. On Linux and WSL 2 only a
  vault passphrase you type works for now: a system-keychain installation there, whose generated
  passphrase you were never shown, reports that the full receipt is unavailable and shows nothing
  (#1069, #1073).

- On Cursor, the Stop-time acceptance re-read no longer asks the agent to end its final answer with
  a `finishup-acceptance:<obligation id>:met` line: Cursor's Stop hook receives no final answer, so
  that line could never answer it there. Cursor agents are told instead to confirm a met criterion
  in the final answer and stop, which ends the re-read (it is asked once per flagged set), in the
  Stop text, the `closure_prepare` notes and the MCP status and `closure_prepare` text. The CLI,
  the terminal interface and a connection that does not name its agent say which hosts read the
  line. Codex and Claude Code text is unchanged (#1050).

- FinishUP no longer records an agent's own successful `status`, `receipt` or `read_guidance` call
  that Codex wrote to its session log. Each such read was added to the task as an action, result
  and evidence, so the task the agent was reading changed under every read and a closing loop could
  keep growing it; on the tb4 n5 trial one hour of `status` polling grew the record by about twelve
  events per read. A failed or denied FinishUP call, FinishUP's own writes and every other server's tools
  are still recorded as before, and so is a held Codex log entry released later. On Cursor's
  ordinary-work hooks, which name every MCP call `MCP:<tool>` without its server, a read is kept
  out only when FinishUP's own server recorded serving that exact call; another server's tool named
  `status` is still recorded (tb4 n5).

- **`finishup setup` is smoother.** Run from your home folder, the filesystem root or a
  symlinked path, it ended in `internal_error` after every question had been answered. It now
  checks the folder before the review and privacy questions (on a machine with only Codex, before
  its first question), lets you type the project folder, and otherwise stops with a plain next
  step; registration, the privacy policy and an API key's repository binding then apply to that
  folder, not the one setup started in. A successful Codex-subscription sign-in in the guided
  connection no longer reports `Credential: unknown` and exits with an error, and a privacy step
  you decline or that fails after the provider step is no longer reported as complete, on any
  setup path: setup exits 20, names the reason and points to `finishup --privacy` (and to storing
  the API key, when none was stored). Setup no longer asks to "verify this API
  key" for Codex, which has no key, no longer prints the API-key vault report after a Codex
  sign-in, and no longer ends by telling Claude Code and Cursor users to preview a Codex
  registration. The agent list (shown in a terminal whenever Claude Code or Cursor is installed;
  on a machine with only Codex the Codex wizard runs instead) and the Codex wizard's installation
  list both offer the Codex that a plain `codex` command runs and show each path; the agent list
  says that one agent is connected per run. Claude Code and Cursor connection plans describe their
  changes in plain words, as Codex plans already did. When more than one installation of an agent
  is found, connect and disconnect list the paths to pass with `--host-path`. The privacy policy
  setup approves is the grant for the folder it connected: each other repository needs its own
  privacy grant (`finishup --privacy` there) before its tasks can use AI-powered review (#1067).
- In a repository holding another Git repository inside it (an `api` directory with its own
  `.git`), FinishUP's local, names-only read of what changed no longer fails: it reads the nested
  repository the same way the change shown to the reviewer does. So the check again tells whether
  the workspace changed at all, which outputs the change touches, and whether a delivered file
  refers to one you created there but did not declare; a nested repository that is unchanged since
  the task started does not count as a change by itself (#1045).

- A parent's receipt no longer fails when a delegated child holds an AI-powered review finding
  (`code_defect`, `task_requirement_unmet` or `agent_criterion_unmet`): the parent's
  child-dependency manifest and JSON receipt carry the child's finding under its own kind (#1043).

- `finishup service run` now starts on Linux with glibc older than 2.32 (Ubuntu 20.04, Debian 11,
  RHEL 8 and images built on them, such as `condaforge/miniforge3`), where it could not set its
  endpoint permissions and stopped with only `internal_error`. A service that cannot start now
  names the failing stage, the kind of error and where, with a correlation id that
  `finishup service diagnostics --correlation-id` resolves; an agent's `start`, or a command that
  starts the service, reports `service_start_failed` with the same stage and id at once instead of
  waiting out the start budget (#1040).

- With Codex 0.159.3, code-mode cells and direct tool calls pair with their outputs again: each
  rollout row carries its own id beside the shared `call_id`, and FinishUP paired on the wrong one.
  The agent's own FinishUP calls after a check no longer read as unclassified work that keeps the
  receipt at "current as of an earlier frontier"; a cell that only calls FinishUP is recorded by those
  calls, and a hooked direct call is recorded once (#1038).

- In Codex, a shell `apply_patch <<EOF` no longer leaves a "pending attempt expired" limitation
  once the rollout shows the file change, and it counts as an edit of the files its patch names
  although Codex reports no result for it: it makes an earlier verification stale and lets the next
  check review, where a non-git workspace gives no other sign of the change; a rollout line Codex
  is still writing is no longer reported as a truncated payload; and Codex's record of a Stop-hook
  prompt is no longer an unsupported event (#1041).

- A shell command that writes into the workspace (`cat > f`, `sed -i`), one that writes only the
  agent's own notes, and a long build or simulator command now reach FinishUP's record. The local
  control wire refused them, the hook retried until it gave up, and a check could stay current
  after the edit that should have made it stale (#1039).

- Fewer rejected calls: a `decision_recorded` payload's `decision_id` is accepted and ignored (a
  retry with or without it replays the same request); `status` accepts `limit` as a JSON integer
  from 1 to 100; `read_guidance` reads a guessed anchor that names exactly one listed section (its
  heading slug, an anchor written beside it, or words only its anchor contains) and still refuses
  an ambiguous one; resolving an obligation without `resolution_evidence_refs` is refused with what
  the list must hold, and `status view=obligations` states how to resolve one; a run linked to a
  requested command with a `command` action is disclosed as the agent's equivalence instead of
  `command_attempt_mismatch`; and the refusal for a result id in a result's `evidence_refs` names
  where a result id goes (#1049).

- After a Codex context compaction, every command's real exit status was lost: each stream completion
  was refused by the ledger and quarantined as `ledger_rejected`, so post-compaction test runs stayed
  `unknown` (183 outcomes across 7 of 7 compacted tb4n3 attempts). The completion is now bound to its
  hook call's generation before its captured content is looked up, and a delivery whose every event
  the ledger already holds is treated as the duplicate it is, with its explicit outcome still applied
  to the recorded action (#1027, ADR-022).

- Withholding a credential-like value from the external reviewer no longer taints the whole check
  (#982, a regression from per-item withholding). Only the value is replaced, in place, by
  `[withheld-by-yoetz:possible-credential]`, and the rest of the item is still reviewed
  (`semantic_review_value_redacted`). An item is withheld only when that cannot be done
  (`semantic_review_item_withheld`). Both bound only the AI-powered review; neither adds
  `content_redacted` or blocks local finding resolution any more. A capture-time `content_redacted`
  no longer vetoes local proof either.

- A closing review with one withheld item keeps a valid provider manifest and its `final` review
  phase (#979).

- Status no longer fails when every open obligation is named by a recorded blocker, and a check
  whose only remaining gap is such a blocker no longer fails internally with
  `invalid_ranked_findings`; standing task facts are disclosures, not `ledger_stale_or_incomplete`
  findings (#977).
- `finishup observe checks status` no longer reports a workspace without `.finishup/checks.toml` as
  `invalid_policy` (exit 20). Approved checks are optional: it now reports `state: not_configured`
  and exits successfully; `preview`, `trust` and `run` say `policy_not_configured`, and only a
  real read or parse fault says `invalid_policy`. Every such failure, and the guidance, now states
  that this is FinishUP configuration, never a `finishup-blocker` (#977).
- AI-powered reviewer challenges are no longer dropped when a citation or quote cannot be proved.
  The review packet now lists as citable only the records it actually sent; a challenge keeps the
  sent records it cites (disclosed as `semantic_review_refs_reduced`), and one that cites no sent
  record is shown in the review summary as an advisory, unverified concern (`ref_not_carried`)
  rather than vanishing. Quotes are matched against the sent text tolerantly (whitespace, JSON
  encoding, typographic punctuation, the redaction marker) and recorded as the exact sent span;
  each rejection reason is counted separately in diagnostics (#976).
- Requested-output facts (an output left unchanged or written outside the workspace) are now
  reported only for items named in a recorded `edit` action's attempted items; an item named only
  by a command, research, or other action no longer reports as an unchanged requested output (#977).
- A repaired AI-powered finding can now resolve in a long session. A recheck over a bounded review
  scope used to require every item the reviewer cited to be shown again, but the repair's own work
  pushed those early items out of the review's recent-history window, and correcting the criticised
  claim (as reviewers ask) replaced it, so no repaired finding resolved and agents looped on
  `work_open_findings`. The recheck must now have shown the finding itself, the repair evidence the
  response cites and a later change, and account for each cited item: shown again (an evidence
  excerpt or claim also counts for the event that recorded it), replaced by a corrected claim it
  showed, or an early event the window evicted. An omitted repair or change still blocks, and the
  receipt still discloses `semantic_reference_scope_reduced`. The rule is replay-derived and needs
  no new field, so existing ledgers re-evaluate on upgrade. A finding's resolution explanation now
  reads the latest check that could have resolved it rather than a later scoped or local-only one
  (#947).

- A cached 100-row `status` page no longer costs ~2 s. Every page was schema-validated about eleven
  times on its way from the service to the host, each time walking every row of every non-matching
  page shape. Valid results are now decided without rebuilding diagnostics, and repeated
  validations of identical content are answered once per process. Leaf classification is decided
  once per field shape. Pages, receipts and omission reasons are byte-identical; a synthetic
  1,000-event Codex ledger shows ~8x less CPU per page and `closure-prepare` in a few seconds
  (#916).

- A hook no longer spends about a second building the whole 232-schema catalog before its first
  service call. A short-lived client now parses only the schemas its frames use (92 of 232), with
  the same verdicts and errors; the service keeps the full catalog. Recorded Codex, Claude Code and
  Cursor hooks were replayed through the builds before and after the change on an idle macOS arm64
  machine. The median tool callback took 1.26 s instead of 1.90 s. Outputs and ledgers matched,
  except for when one advice message arrived, which also varies between two runs of the same
  build (#1083).

- A later run of the same command (only its latest run is judged), or a later observed edit, now
  retires an earlier hook-observed failure before a completion claim. Such a failure no longer
  raises `failed_work_omitted`, `material_limitation_omitted` or `failed_command_unresolved` advice,
  and a `claim_recorded/1.1.0` claim no longer has to list it in `limitation_refs`. The receipt's
  limitations still name each such failure once as history. A claim made while the latest observed
  run is red and undisclosed gets exactly one finding that names the run by its result and action.
  Hooks commit to the command with an installation-keyed `hmac-sha256:` value and discard the text,
  so no command text is stored, shown or sent. `status view=results` adds each observed run's tool,
  occurrence, command commitment and exit status. Older ledgers without a command identity use the
  observed-edit rule only. Cooperative results keep their disclosure duty (#909).

- Hooks no longer tell the agent "task frontier moved … run status before an exact-frontier check"
  after routine tool calls. Every such notice described motion by the FinishUP observation writer,
  which leaves a held publish frontier valid, and the text contradicted the `status` cadence in the
  workflow guidance. Motion by any other writer still surfaces as `frontier_conflict` on the next
  state-sensitive call (#915).

- Publishing a change the way the guidance recommends no longer traps agents in a finding they
  cannot clear. A digest-only (or withheld) `caller_asserted` evidence digest now raises no
  `ledger_stale_or_incomplete` finding; the receipt's limitations name once, with a count, the
  cited evidence items whose caller-asserted digests FinishUP did not verify, keeping digest-only
  items (bytes not retained) apart from withheld ones, and the coverage gap
  stays. A legacy digest's finding text now names only actions an agent can take, and the
  publication and coverage guidance no longer promise "content-bearing evidence". A resolved
  finding stays on the receipt as history but its coverage no longer lowers the receipt's.
  Binding a caller digest to matching captured bytes remains open (#912).

- An agent can read back the evidence it published: production now composes the privacy
  enforcer with its ledger-authorship provenance resolver, so under the default policy the
  requester's own evidence descriptions and references are returned instead of
  `local_disclosure_not_authorized`. Other writers', host-observed and imported rows stay omitted
  without a grant; the never-send scan, absolute data classes and per-projection receipt are
  unchanged. Guidance no longer asks agents to page every evidence item and match on descriptions
  the projection omits; it names published IDs, `filter.author=mine`,
  `filter.strength=immutable_snapshot` and structural links instead (#914).

- AI-powered review now sees the change under review even when no hook captured it. When the
  review recipe selects diff excerpts, each check reads the task's repository once and gives the
  reviewer the change from the task's starting commit (committed and uncommitted edits, plus
  untracked files Git does not ignore, including work already present when the task started) ahead
  of other excerpts, with a header naming every changed file. Script edits, commits, missed hooks
  and Cursor's ordinary profile are covered on every host. The change travels as repository
  excerpts, so a policy that does not allow them never sends it and the check says its context was
  withheld. Repositories whose Git config defines a filter or an include are not read, files named
  like credentials are listed by name only, and the whole read has 20 seconds. The task-start
  commit is recorded when `start` creates a task; limits are disclosed as
  `check_time_change_unavailable`, `check_time_change_base_unavailable`,
  `check_time_change_truncated` and `check_time_change_redacted` coverage gaps (#883, ADR-031).
  Those limits on a later review still let it clear an AI-powered finding when the later review
  saw every file the raising review saw, whole or through the identical view; each check records
  which files it showed and, for each partly shown one, how much and a keyed commitment to where
  its redactions and hunks lay, never paths or content, so a moved redaction or hunk no longer
  clears a finding (maintainer decision 2026-09-30). A resolution relying on a raising record from
  before those view commitments is disclosed on the receipt as
  `check_time_change_resolution_unverified`. A task started
  before this version takes its base from its first check, so commits between checks stay in the
  change. The read is pinned to the validated repository directory and its own `.git` (a
  `core.worktree` redirection is refused), never shows a tracked or untracked file that is a link
  or has a second name, refuses an object store reached through a link or borrowed from another
  repository, verifies every Git object it shows against its name (so a local `git clone` that
  hard-links its objects is read normally), and retakes the change (up to three times, then
  `changed_during_capture`) when the working tree or object store moves while it is read. When the
  change is unavailable, a closed reason code beside `check_time_change_unavailable` makes the
  check result, status, receipts (JSON, markdown and text) and the MCP check summary say why in
  one fixed sentence. A custom recipe whose half-share is smaller than one part still carries the
  first part, and the files a review is recorded as having seen are counted from the packet the
  reviewer actually received.

- Codex shell, exec, `apply_patch` and MCP results now record the outcome Codex states instead of
  `unknown`: the exit code nested in the hook's tool result, the `Exit code: N` or
  `Process exited with code N` header, or MCP's `isError`. A completed command, MCP or patch item
  in the session rollout is recorded as a result with its status and exit code, and carries the
  same command commitment as its hook copy, so a passing rerun on either path retires the failure.
  Output text is never read as an outcome, and a result with no stated outcome stays `unknown`
  with `host_outcome_unavailable` on that record only. Unresolved-command advice now also reads
  Codex `exec_command` and `local_shell` calls. While the session's tool hooks fire, the rollout's
  copy of a hooked call stays local when the hook already stated the outcome, so one command is one
  result; when the hook stated none (a still-running process) or no tool hooks fire, the rollout
  item is delivered with its outcome. This holds when the rollout item is read before its hook
  result arrives: the item waits locally until the hook results of that command settle it. With
  parallel runs of one command it waits until no other run of that command is still open, or
  until the turn ends, so runs whose hook rows are still held locally do not trade outcomes. An
  item that the turn's end cannot prove to be a stated hook result's copy is delivered with
  `unpaired_event` instead of being dropped. So is an item whose pairing is lost to local
  retention, to the pending bound, or to a session that stopped storing rows (#910).

- Codex observation records each tool call once. A tool call's pre-event and its result now share
  one ledger action instead of two, and a code-mode `exec` cell no longer adds its own action next
  to the nested calls its hooks already recorded (a cell whose tools fire no hook is still
  recorded), so a shell command costs at most four
  observation records instead of about eight. Earlier sessions keep their recorded history. A lost
  pre/post pairing (`unpaired_event`) stays disclosed on status, check coverage and the receipt,
  but it no longer raises the "Observation coverage is incomplete or stale" advisory that no wait
  could clear; the agent gets one no-response notice per new orphan scope. The advisory now names
  its live cause and clears when source lag, drain, service or vault conditions recover;
  unsupported-record gaps still keep it and do not clear in session. `status view=findings` items
  carry the `finding_frontier` that `respond` accepts as-is (#917).
- With the Codex subscription evaluator bound, the service no longer re-hashes the retained Codex
  runtime (about 359 MB on Linux) on the event loop for every observation advice cycle. Structural
  readiness is memoized by binding and file fingerprints and re-checked off the event loop only
  when they change. Every evaluator launch still verifies both files (#881).
- Codex subscription AI-powered review no longer stops at a `runtime_warning` on Codex `0.157.1`.
  FinishUP's retained evaluator runtime now keeps Codex's `codex-code-mode-host` helper, pinned by
  digest, beside the native executable. Setup, repair, launch, `runtime status` and
  `runtime remove` now cover both files. `finishup provider codex-subscription repair` moves an
  older binding and keeps its sign-in and choices. Retaining Codex's bundled `bwrap` remains open
  (#874).
- Codex `0.157.1` is now the oldest release Codex subscription AI-powered review admits on macOS
  arm64 and Linux x86_64, in place of `0.150.1`. Existing bindings report
  `codex_runtime_profile_outdated`, and `finishup provider codex-subscription repair` moves them,
  keeping the sign-in, model and settings. Rate-limit bookkeeping accepts the new `normalModelSlug` field, and the native
  `rateLimitExceeded` error is reported as rate-limited. Other new app-server events still fail
  closed. Authenticated live evidence for `0.157.1` is pending (#871).
- Codex subscription AI-powered review no longer breaks when your everyday Codex updates. Setup
  binds FinishUP's own verified private copy of the Codex release it admits. It offers only an
  eligible runtime as the default, and it can download a release with your npm after asking.
  The new `finishup provider codex-subscription repair` rebinds a binding stranded by a replaced
  executable or an older capability identity. It reuses the existing ChatGPT sign-in and never
  signs in, logs out, or switches accounts. Re-running setup or repair keeps the model, reasoning
  effort, timeout, retries, and fallback role. `runtime status`, `provider status`, the prompt
  menu and `/provider` now name the exact structural cause, such as
  `codex_runtime_executable_changed`, and its fix, and the upgrade guide ends with that check.
  Native acceptance remains pending (#855).
- Delegation guidance now tells parents to give each child its selector, distinct actor and
  complete publication/check/receipt/closure duties. Helpers assigned no child selector are
  explicitly kept off the child ledger; Claude's compact startup text states that exception
  within its existing budget. Named conformance rows and per-host qualification limits are
  recorded for the multi-agent workflow (#509).

- Concurrent Codex, Claude Code and Cursor sessions, including their delegates, no longer queue
  behind one another on the local observation store until hooks time out and inputs are lost.
  Reads such as `finishup observe status`, consent checks and the service's delivery selection no
  longer wait for the store lock; each write holds it only for what changed rather than for the
  whole observation state; and every lock wait in a hook stays inside that host's hook timeout.
  When the store is still contended, the hook reports `store_lock_timeout` with the role and step
  that held the lock (instead of a generic failure or a false "unconsented workspace"), the
  service's delivery pass stops and retries without failing, a check refused for store contention
  can be retried with the same request instead of failing internally, and a cancelled delivery
  pass can no longer run beside the next one. Native three-host acceptance on macOS remains open
  (#689).

- A Codex multi-agent v2 child that attaches with its delegation handle now binds its host
  identity to exactly one accepted child. v2 gives every thread of a delegation tree the parent's
  session, so a child callback that names its own rollout takes its child identity from that
  rollout's header: the attach publishes the child lane, the provisional annotation is bound, and
  the child's command, file, and advice evidence stays on the child lane. The child's own rollout
  is reconciled into that lane automatically, and `finishup observe reconcile` of a child rollout
  resolves the same lane idempotently instead of failing `mapping_missing`; an unprovable child
  rollout is refused with a bounded `child_*` reason. Native v2 acceptance remains open (#841).

- A coordination finding declared before a project opt-out, opt-in, consent or approval
  revocation, unlink, or dissolve no longer stays open with no way to close it. The next check
  records the superseded context as history and can resolve the finding, and the receipt says the
  generation was superseded. Declaring or disposing against the old generation now returns
  `coordination_generation_superseded` with a recovery step you can take (#842).

- Connecting Codex, rerunning setup, or repeating `finishup observe grant` no longer turns off
  native content capture you enabled for Claude Code or Cursor. Repeating consent that is
  already in effect changes nothing, so content capture already in progress keeps its
  authorization. Your observation detail and capacity settings are also kept. Only
  `observe content-disable` or `observe revoke` removes a host's content capture, and granting
  again after a revoke starts with none (#835).
- `status view=project` answers again after any project member records a receipt; previously every
  member's project view failed as `INVALID_REQUEST`. Status faults in stored state or in FinishUP's
  own projection now return `STORAGE_CORRUPT` or `INTERNAL_ERROR` with a correlation id that
  resolves to the failing stage and source location, and one unreadable member is reported as a
  `project_member_unavailable` gap instead of failing the whole view (#840).

- Active native work is no longer abandoned while it keeps working, and abandoned work has a
  supported way forward (#837):
  - Host activity counts as contact from when the host reported it, even when FinishUP delivers or
    retries it later. That includes a turn ending or a subagent finishing.
  - A native subagent the host reported starting keeps its parent in contact until the host
    reports it finished, for up to an hour.
  - Queued host events are delivered before FinishUP decides whether contact was lost.
  - Resuming finished or abandoned work is refused without disturbing the session still in use.
  - A task whose work is finished or abandoned cannot start child work. It gets its own reason
    and directs you to a successor task for new work, while its history and receipts stay as
    recorded.

  The session lease and the default recovery window are unchanged. A single long quiet operation
  can still lose contact, as described in the multi-agent usage page.
- Busy starts recover their recorded route, and review-case construction resolves authenticated
  captured evidence instead of substituting its description (#745).
- Long AI-powered reviews retain execution leases and durable responses through client
  disconnects and recovery, avoiding duplicate dispatch after a client timeout (#750).
- Child lifecycle and native host correlation preserve parent dependencies and session-health
  distinctions. Codex 0.153.4 multi-agent v2 child identity comes from the child's own rollout
  metadata; token-usage and fractional-number handling no longer break stream reconciliation
  (#752, #762). Native installed multi-agent acceptance remains open (#499, #507).
- Consumed egress is reconciled after advice cancellation (#761); an invalid routine summary
  no longer stops observation admission flushes (#764).
- Every local CLI error has a recovery directive (#780). Failed transport sends receive the
  retryable transport classification, and pending request futures are consumed on failure (#781).
- Paired edits produce one advice finding, and verification baselines use a typed contract
  (#782). Oversized hook payloads produce an explicit scoped coverage gap (#784).
- Privacy receipt commands serialize datetimes and admit the local purpose on the control
  wire, fixing #731 and #732 (#783).
- The npm release verifier checks both the persistent install and subsequent delegation
  (#777). The parent/worker capture test observes outbox drain between writes to avoid
  counting runner-load overflow as a product regression (#775).
- Project overlap advice no longer disappears when a sibling task was idle, evicted, or last used
  before a service restart or vault relock. Coordination reads each consented sibling's recorded
  scopes with payload access, exactly as it does for an active task. A consented sibling whose
  scopes cannot be read is reported as a coverage limit while the other pairs are still detected,
  and a sibling that is not admitted no longer stops detection for the others. A failed
  post-publish sweep now leaves a bounded diagnostic instead of failing silently (#839).
- The release carries every 0.2.2 install fix, including the review follow-ups ported in #774,
  and every 0.2.3 and 0.2.4 repair: Codex home-aware setup, Cursor exact-path and Agent CLI
  project binding, fractional Codex metadata, selected observations and routine summaries across
  local control, contended session attachment with shielded lease release, and the foreground
  desktop approval and runtime-retaining host handoffs (#786, #787, #788). It also carries the
  0.2 repairs prepared for 0.2.5: cold session attachment within host hook budgets (#790),
  complete capture recovery and loss reporting (#792), claim and plan scope differences in status
  and receipts (#793), unrelated command gaps partitioned from repair proof (#794), Linux Cursor
  IDE identification without launching it (#795), and approval-preserving setup that inspects the
  selected installation (#796), plus the remaining 0.2.5 repairs: exact-session recovery and
  automatic reattachment beside independent tasks in the same workspace, with delegated children
  still behind their authenticated attachment path (#811, #815, #816).
- Lowering, revoking, expiring or ending a larger observation capacity while the local state is
  above 1 MiB no longer blocks later writes. Accepted records still drain. Refused input is
  recorded as loss, and delivery attempts and session ends are still saved, within finite room
  that follows only the accepted records. A session end that still cannot be saved is reported as
  `session_end_unrecorded` (#843).
- One stranded native capture handoff no longer closes observation admission and content for a
  whole workspace. A handoff whose structural record can no longer deliver it is retired by that
  record's delivery, by background service maintenance without waiting for new input, or by a new
  check's preflight; a handoff whose record is still waiting keeps the unchanged pending-age limit.
  A Claude Code or Cursor hook no longer quarantines a queued Codex row in the same workspace as a
  content-profile mismatch, and a late capture for an already delivered record stages nothing.
  `observe status --json` names each retirement under `capture_handoff_retirements` (#836).
- A check refused before admission no longer strands its caller behind an `OPERATION_PENDING`
  whose operation reads `absent`. A pending check whose lease has lapsed no longer defers the
  observation delivery that later checks wait on; a capture handoff no structural row can consume
  is retired; a refused check wakes the delivery sweep; and SQLite admission survives unrelated
  lifecycle writes. Every remaining pre-admission refusal names its stage with a same-identity
  replay directive and `retry_after_ms`, and `status view=operation` reports that stage on the
  `absent` page (issue #838).

Entries for 0.2.5 and earlier describe the product under its former name, Yoetz.

## 0.2.5 — 2026-09-23

- Recover exact sessions and automatically reattach known tasks when independent tasks share a
  workspace, while retaining task identity and admission boundaries (#811, #815).
- Recover cold hook attachment within host budgets and report capture recovery, delivery loss,
  and quarantine state explicitly (#790, #792).
- Compare completion claims with the effective plan and keep unrelated command gaps from
  invalidating repaired findings (#793, #794).
- Preserve setup approvals, inspect the selected installation, and identify Linux Cursor IDE
  installations without launching them (#795, #796).

- Add opt-in required startup for native Claude Code and Cursor plugins, with scope-bound plan
  checks, owner controls, and same-task pending-operation recovery (#692). Native acceptance remains
  bounded as documented in the required-startup runbook.
- Deliver native startup guidance independently of observation consent and availability (#692).
- Claude Code sessions receive a compact MCP initialize block that fits the host's observed
  2,048-character rendering cap, with the "call `start` first" trigger and the late-start rule as
  its first two sentences; other hosts keep the full document (#789).
- Guidance, the Claude skill and `AGENTS.md` state what to do when material work began before
  `start`, and how to load deferred Yoetz tool schemas by name.
- `yoetz setup status --json` reports each Claude installation's MCP mode (plugin-managed or
  bare) and whether a session-start cue is installed; a bare registration has none (#789).

See [release notes](docs/releases/v0.2.5.md) for verification scope and known limits.

## 0.2.4 — 2026-09-20

- One guided installation and connection lifecycle for Codex, Claude Code, Cursor IDE and
  Cursor Agent CLI, including preview, status, disconnect and reconnect (#767).
- Preserve exact host profiles and runtime paths in setup continuations; keep required Linux/WSL
  password approval on the foreground thread.
- Inspect the selected host's readiness and retain partial-installation and fresh-session limits.

See [release notes](docs/releases/v0.2.4.md) for installation verification and coverage limits.

## 0.2.3 — 2026-09-19

Repairs to existing 0.2 behavior; no 0.3 feature merge. The verified scope and known limits are
recorded in [release notes](docs/releases/v0.2.3.md) and issue #786.

- Privacy receipt list/get render stored timestamps and local disclosure purposes correctly
  (#731, #732).
- Codex setup registers MCP in the selected home and reconfirms a refreshed preview when plugin
  activation changes the effective entry (#759, #786).
- Newer Codex fractional metadata no longer discards the surrounding transcript record (#754).
- Cursor project registration uses the exact project path so Agent CLI can initialize the same
  bridge as the IDE; existing placeholder registrations remain upgradeable (#786).
- Explicit Cursor CLI project binding uses the project selected in the accepted registration,
  revalidating its identities on each call; desktop still requires native roots (#786).
- Local transport preserves retryable send failures and consumes pending request errors (#678).
- Local control accepts the existing selected-observation envelopes and bounded routine summaries,
  preserving route validation and rejecting unknown structural fields (#786).
- Routine-read outcomes survive structural mapping; legacy unqualifiable summary buffers drain
  as original records instead of blocking later hook observations (#786).

- Contended session attachment drains existing runtime users and preserves same-request recovery.
  Optional review cancellation retains accounting, and observation feedback failures cannot skip
  ingestion lease cleanup (#744, #755, #786).

## 0.2.2 — 2026-09-18

Patch release in the **0.2** public-alpha line, focused on making the documented install paths
work on any machine regardless of which Pythons it already has. See
[release notes](docs/releases/v0.2.2.md).

### Fixed

- The website's PyPI button copied a version PyPI never had (`yoetz==0.2.0`), so every install
  from it failed. The command is now unpinned, and both install popups say that `uv` is required
  and that it fetches Python 3.14 itself (#766, #770).
- `npx yoetz` now makes the exact version a persistent `uv tool install` before delegating, so
  Codex, Claude Code, and Cursor connections made from `npx yoetz` no longer bind to `uv`'s
  prunable cache and survive `uv cache clean` (#766, #768).
- Bare `yoetz` on the prompt-loop fallback (`YOETZ_TUI=0`, or an install without the terminal
  UI dependency) opens the setup wizard instead of exiting `internal_error` (#766, #768).
- Setup offers the Codex home from `CODEX_HOME` or `~/.codex` for confirmation instead of asking
  for a blank absolute path, and `yoetz setup run --codex-path` no longer refuses without
  `--codex-home`; non-interactive runs bind and report the same default (#766, #768).
- A `yoetz` console script that cannot prove itself (a group-writable prefix such as Homebrew's
  `/opt/homebrew`, a symlink, or a modified install record) reports `launcher_unproven` on Codex
  MCP registration instead of a bare `harness_unavailable` (#766, #768).
- The first-run detection screen no longer prints each Codex version twice, and the header names
  the foreign Codex MCP entry when the `yoetz` server name is already taken (#766, #768).
- Public errors on the MCP and CLI surfaces carry a typed `continuation` token that each surface
  renders as a concrete next step, guidance pointer, and nudge, so an agent that hits an error such
  as `vault_initialization_required` is told what to do rather than only that something failed
  (ADR-030; #739, #740, #669, #743).

### Changed

- The install documentation states the Python 3.14 requirement, that `uv` downloads it on demand
  whatever other Pythons are installed, that `pip` and `pipx` on an older Python cannot install
  Yoetz, and which two `uv` settings block the download (#766, #768).
- Product wording says "local checks" and "AI-powered review" everywhere people read it: rendered
  receipts, the terminal interface, CLI and MCP descriptions, guidance, skills, and docs. Wire
  identifiers, schema bytes, and storage are unchanged; `docs/INTERFACES.md` maps the product words
  to their wire names (#769, #773).
- The website's hero shows the Product Hunt featured badge.

## 0.2.1 — 2026-09-14

Patch release in the **0.2** public-alpha line, focused on significant Linux and WSL
compatibility fixes. See [release notes](docs/releases/v0.2.1.md) for validation boundaries
and known privacy-receipt CLI issues.

### Changed

- The agent install guide (`docs/usage/agent-start.md`) now opens with a platform check — macOS
  and Linux, Windows only inside WSL 2, with the exact WSL and `uv` installation steps and which
  side of Windows each command runs on — tells an agent whose host has no structured question
  tool (Cursor's agent, for one) to put each decision in plain chat and wait for the answer
  instead of choosing, and hands the terminal over as if the user has never opened one.
  [Install and first run](docs/usage/install-and-first-run.md) gains the Windows section the CLI
  and README link to. Host notes checked against the September 2026 documentation of Codex,
  Claude Code, and Cursor record what each does differently: where its question tool
  is unavailable or non-blocking, what blocks the guide fetch or the `uv` installer, and what
  native Windows means for it. The copied setup prompt now tells the agent to ask for approval
  or a pasted guide when its sandbox blocks the fetch (issue #709).

### Fixed

- `yoetz privacy receipts list` and `yoetz privacy receipts get <receipt-id>` answer again. The
  service never registered either read method, so every call, including one for a receipt a
  completed semantic review had just recorded, exited 2 with `invalid_request`; and the catalog
  could only decode local-disclosure receipts, so a network egress receipt would still have been
  refused. Both methods are now served with their contract-shaped bodies, `get` reports
  `not_found` for an unknown ID, malformed filters, cursors, and IDs are rejected as
  `invalid_request`, and stored network receipts read back with their channel, destination,
  dispatch, and commitment fields (issue #730).
- Codex subscription setup accepts Linux x86_64 (WSL 2's Linux userspace included) through its own
  exact evaluator cell instead of refusing with `codex_runtime_platform_unsupported`. macOS arm64
  bindings keep their identity, and a binding whose cell does not match the host fails before
  launch (issue #716).
- Native Cursor and Claude Code plugin install, replace, update, enable, disable, and remove no
  longer refuse every non-macOS host. Linux, including a distribution inside WSL 2, now proves
  the one-time `plugin_artifact_apply` approval by asking for the invoking account's Linux
  password at your own terminal and verifying it through the operating system (PAM), with the
  same action-bound banner, single-shot pending, and fail-closed cancellation, timeout, wrong
  password, and missing-console paths the macOS Touch ID cell has; macOS is unchanged, any other
  platform still fails closed with `human_authority_unavailable`, and `preview` now names the
  mechanism and platform under `authorization.human_presence`. A refused or cancelled prompt on
  the Claude Code path is now reported as `human_authority_unavailable` instead of escaping the
  CLI as a traceback (issue #719).
- On native Windows, `yoetz` refuses with a bounded `unsupported_platform` line naming the WSL
  path (exit 20) instead of `internal_error` from every stateful command; `version`,
  `--version`, and `--help` still answer (issue #709).

## 0.2.0 — 2026-09-11

Prepared 0.2 public-alpha baseline; superseded by 0.2.1 before tag or registry publication.
See [complete baseline notes](docs/releases/v0.2.0.md)
for host integration, observation selection and recovery, upgrade guidance, and known limitations.

### Changed

- New Codex, Claude Code, and Cursor sessions read guidance and discover tool schemas, then
  call Yoetz `start` before substantive research, commands, edits, or delegation. Failed starts
  follow exact continuations and same-request recovery, including a named one-time repair,
  before asking for intro and guidance if startup remains blocked. A first non-retryable failure
  alone does not permit continuing without a task. The rule is in the 512-byte intake cue,
  MCP initialize instructions, host skills, mapped and unmapped SessionStart context, and the
  `start` tool description. Compaction in an already-started session retains status recovery.
  It is instruction delivery, not a PreToolUse deny gate (issue #692 instruction slice).

### Added

- Independent permanent installs and test snapshots (ADR-028, issue #604). An isolated root can now
  carry a sealed `instance-identity.json` naming its lifecycle (`persistent` or `disposable`),
  exact source revision, wheel digest, and bounded expiry, and a snapshot's own runtime can be
  pinned to its root with `yoetz instance create --bind-runtime`: the pinned launcher resolves
  that root even when a host, hook, or shell drops `YOETZ_ISOLATED_ROOT`, a different root in the
  environment is refused as `isolation_root_conflict`, and a re-pointed pin, an expired snapshot,
  or a labeled marker in ambient state refuses to serve before the singleton is taken. New
  connection-free commands `yoetz instance create|status|dispose` create, inspect (digest-only,
  with `binding`, `lifecycle`, and provenance), and remove exactly one marked root, stopping only
  the service that holds that root's lock; `yoetz service isolation --json` reports `binding` and
  `lifecycle`, and the singleton lock stamp names the holder's instance lifecycle and source ref.
  Contributors provision snapshots from an exact checkout revision with
  `scripts/provision_test_instance.py` (see `docs/runbooks/test-instances.md`). The everyday
  install is unchanged: it carries no marker and no pin, and `dispose` can never target it.

### Fixed

- Hook observation no longer reports a live task mapping as stale after every Claude Code
  compaction or resume. The resume/compact status probe now connects through the same consented
  workspace locator the auto-attach `start` uses (`yoetz hooks session-start` accepts `--workspace`
  and defaults to its working directory), so the service's repository fence admits the read and the
  hook refreshes the frontier. The fence's `SESSION_CONFLICT` now carries
  `repository_identity_required` or `repository_identity_mismatch`, which the hook records as
  `status_workspace_unbound` / `status_workspace_mismatch` with a keep-the-mapping advisory;
  `mapping_stale` is reserved for a session the service actually reports replaced, and that
  advisory names the replacement task, session, and writer ids (issue #578).
- The `SessionStart` context for a mapped session now names the mapped `session_id` and
  `writer_id` and says to continue the task with `start mode=attach` by that session id, and the
  guidance, Codex skill, request templates, and `start` tool description name the canonical
  absolute repository root as `workspace_ref` (never a remote URL), the value hook auto-attach
  commits. An agent following the guidance therefore lands on the auto-attached task instead of
  silently creating a sibling under a differently spelled workspace (issue #580).
- The scoped `start` post-hook binder admits the `tool_response` shape Claude Code 2.1.251 actually
  passes (a bare JSON string of the structured result, captured live), so the agent's own `start`
  re-binds the host session to its task. A scoped successful start that still binds nothing records
  `start_bind_unparsed`, `start_bind_invalid_ids`, or `start_bind_write_failed` in
  `hook_diagnostics` instead of failing silently (issue #581).

- Ended-session recovery attach no longer quarantines the predecessor's still-pending observation
  rows as `ledger_rejected`. Ingest follows `SESSION_NOT_FOUND` / `session_superseded` to the
  current task binding, persists the updated lifecycle mapping on each hop, and the shared
  Claude/Codex/Cursor hook recovery rewrites ended predecessor mappings so the next drain
  acknowledges those rows on the successor route. A superseded payload that cannot be followed
  quarantines that row as `session_superseded` (visible in `quarantine_causes` even when a mapping
  file is present) rather than `mapping_missing` or a ledger content refusal (issue #577).

- Claude Code and Cursor hook observation rows now store in the task ledger. Bundle migration
  `0009` rebuilds the observation cursor and envelope tables so their source CHECK admits
  `claude_hook` and `cursor_hook` beside the Codex sources, preserving existing rows; a fresh bundle
  and a migrated one accept every `ObservationSource` member, and a test locks the enum to the DDL.
  A deterministic task-ledger rejection inside the observation store (a CHECK or STRICT type
  failure) is now raised as non-retryable and quarantined once as `ledger_rejected`, instead of
  escaping the coordinator's catch-all as retryable `service_unavailable` and retrying the same
  row every sweep while `service status` reported `ready`. Valid pending Claude or Cursor envelopes
  can store unchanged at schema 9; delivery also requires a usable session mapping. Existing bundles require explicit migration; upgrading the
  binary alone does not migrate task bundles (issue #576).

- Yoetz-owned external Codex MCP registration now preserves ADR-026 isolation across the host
  process boundary. In isolated mode, preview and apply bind only the exact validated
  `YOETZ_ISOLATED_ROOT` through Codex's native `--env`; status reports whether the stored binding
  is exact, missing, different, or ambient, and arbitrary environment shapes remain foreign and
  are never overwritten. Dogfood parity schema 3 adds a pre-model child-start facet, and an
  installed Codex 0.150.1 regression proves the registered child receives the reviewed root even
  when the host parent does not (issue #561).

- A Codex MCP route that reverts to `strict` between install and session start no longer reports a
  bare `route_semantic_ceiling`. `yoetz integrate codex mcp install` now records the applied route
  in an owner-only state-directory record (no repository or prompt content); `mcp status`, provider
  status, and the terminal surface report `applied_profile` and `drift_since_install`, and the MCP
  bridge emits a structural `registration_drift` diagnostic at startup. A strict check served while
  that record says `policy` keeps the same `blocked_by_policy` / `route_semantic_ceiling` status,
  reason, and null provenance, and carries an additional
  `optional_semantic_review_registration_drift` coverage gap whose receipt names the recovery
  (`mcp preview`, `mcp install --route-profile policy`, a fresh Codex process) as a conditional,
  because a strict route reached outside the install ceremony is a legitimate owner action. A
  ceiling with no applied-policy record keeps its previous terminal wording byte-identical.
  `mcp remove` clears the record and every later accepted install overwrites it, so no stale drift
  claim survives. The host's own registration read stays the authority: an unread or unsafe record
  reports no drift. Claude Code and Cursor record this as not supported (issue #537).

- `yoetz provider codex-subscription setup` no longer forces a fresh Codex sign-in on a dedicated
  evaluator home that Codex already reports signed in with the exact model available. Unless
  `--switch-account` is passed, setup first runs the same structural app-server probe as `status`
  (`account/read` with `refreshToken: false`, then `model/list`) and, on success, writes the
  binding and reports `login_reused: true`; otherwise the existing login path runs and reports
  `login_reused: false`. `--switch-account` (also the prompt-loop menu and `/provider` account
  switch) always logs out and signs in again. Yoetz still never reads `auth.json`. A dedicated
  evaluator home passed by path may live outside `YOETZ_ISOLATED_ROOT` and be reused across
  dogfood runs; ADR-026 records that exemption (issue #534).

### Added

- ADR-027 ratifies task lineage and first-class project grouping: child tasks are own bundles with
  catalog-held parent, depth, lineage digest, origin, acceptance, and work state; receipts roll
  up one level by severity; `prj_` is the accepted project id. Coordination remains local
  disclosure under each source workspace's consent, with a generation-bound coordination grant
  for general or cross-repository work; the egress lattice is unchanged. `workspace_task_exists`
  and only inventory-designated shared-mutable state are named for retirement, with replacement
  invariants, in #496/#497. No wire, catalog, or admission change ships in this change (issue #494).

- Agents can now set up or change semantic review through normal conversation. When a user
  explicitly wants semantic review, the agent recommends Expanded review first, explains the
  lower-disclosure Assisted, Metadata-only, and Private alternatives, shows one complete frozen
  before/after repository privacy preview, and asks for one exact final approval; the user keeps the
  choice. Consent schemas move to 6.0.0 so the pending target binds the selected recipe, the full
  policy diff and lineage, the repository and authority, the review profile, and the provider,
  model, and endpoint, and authorization is refused when any of them drifts. Codex may authorize
  through current-chat attestation; Claude Code and Cursor carry the selected outcome into the
  shortest trusted-local continuation instead of silently downgrading it (issues #532, #533).

- One supported exact-target isolation contract for test and dogfood runtimes (ADR-026): setting
  `YOETZ_ISOLATED_ROOT` to a pre-provisioned owner-only private directory derives every identity
  root from it — config, storage bundle, state directory (service singleton lock and generation),
  control endpoints, cache, and logs — so an isolated runtime structurally cannot reach the
  normal Yoetz service. A set but unusable root fails closed instead of falling back to ambient
  platform directories. `yoetz service isolation --json` reports one exact target's digest-only
  identities without a service connection; the Codex dogfood parity gate compares separate exact
  normal and candidate snapshots (including relocated storage and the Yoetz executable) and
  rejects shared, ambient, or unknown identity before launch (issue #518).

- `claim_recorded/1.1.0` adds append-only completion-claim correction: a fresh replacement names
  prior effective claims in `supersedes_claim_refs` and records partial or failed results in
  `limitation_refs` instead of treating them as support. Dry-run rejects missing, stale, disjoint,
  contradictory, no-op, or incompletely linked replacements before append; current checks,
  candidate findings, semantic review, and receipts evaluate the replacement while status/history
  retains the original claim. Additive event-draft/publish-work request schemas and control schema
  2.4.0 carry the new event without changing released 1.0 schema bytes (issue #432). Carrying the
  additive draft union raises two reviewed byte budgets: the `publish-work-request` presentation
  ceiling from 32,000 to 34,000 encoded bytes, and the aggregate advertised-surface ceiling from
  200,000 to 205,000 encoded bytes. Both are host context costs, not new egress, and the
  instructions block itself stays inside its unchanged 20,000-byte bound.

- Consented hook capture no longer stops at encrypted observation-store references. Eligible
  secret-scanned tool output, selected changed-file bytes, workspace diffs, and bounded inspection
  snapshots now materialize as immutable ledger evidence with exact object, digest, byte-count,
  redaction/truncation limitations, and `observation_captured` provenance. Additive
  `evidence_recorded/1.2.0`, `event-draft/1.1.0`, `opaque-unknown-event-draft/1.1.0`, and
  `outbound-case/1.1.0` contracts keep their prior versions frozen; migration 0008 leaves legacy
  rows readable but weak when no inner-content binding exists. Capture remains distinct from
  verification, reproduction, and egress authority (issue #302).

- An exact Codex npm `0.150.1` macOS-arm64 app-server profile can perform ordinary privacy-gated
  semantic review with a ChatGPT subscription. Codex remains the OAuth credential authority;
  guided setup, structural status, account switch/logout, disconnect, and binding-only rollback
  expose no token to Yoetz. Every attempt binds the executable/protocol/config/capability/model/
  reasoning cell, runs one no-tool ephemeral stdio turn from an empty cwd, verifies process-group
  cleanup, and records disclosed-case/runtime evidence with upstream-body observability explicitly
  unavailable. API-key profiles remain separate and unchanged (issue #404).

### Fixed

- Codex subscription setup now resolves the exact selected executable from both supported npm
  layouts (nested native package and hoisted package under the same npm prefix), while retaining
  direct-native support, bounded path resolution, and exact capability verification. Browser login
  receives its full 600-second window and device-code login its full 900-second window; cancellation,
  timeout, malformed completion, process exit, and write failure perform bounded process cleanup and
  leave no partial Yoetz binding, while any Codex-owned authentication remains under Codex's control
  (issue #525).

- Fresh Codex subscription login now demultiplexes only the reviewed pre-disclosure notifications
  from the pinned 0.150.1 app-server cell, including its mandatory `remoteControl/status/changed`
  notice, while retaining exact `loginId`/success completion matching and fail-closed handling for
  unknown or unallowlisted notifications. Notification payloads remain unread and do not cross the
  adapter (issue #530).

- Codex subscription semantic attempts now record which closed stage stopped them. A
  `response_schema_invalid` result stays terminal and non-retryable, but its
  `semantic_provenance.runtime_evidence.failure_stage` names one registered token — malformed or
  fenced JSON (`output_not_json`), a wrong envelope, an invented enum, duplicate cited refs,
  non-citable refs, a conclusion that contradicts its challenge list, prose outside the text
  bounds, an extra or missing field, a second final message, a forbidden event or tool item, the
  event budget, or an unconfirmed cleanup — and the service writes the same token as an
  owner-only diagnostic line. No provider text is retained. The evaluator also stops rejecting
  answers Codex 0.150.1 produces legitimately: interim `commentary`-phase agent messages are
  discarded and only the `final_answer` is validated, informational notifications (thread naming,
  moderation metadata, safety buffering, deprecation and config notices, queue and compaction
  state, plan updates) are discarded unread, and the streamed-delta budget rose from 512 to 4096
  events so a content-rich judgment no longer fails as schema-invalid. A `model/rerouted`
  notice ends the turn as `refused` because the bound model did not answer. Evidence validation
  failures now raise their registered `invalid_runtime_attempt_evidence` reason instead of
  `unregistered_protocol_reason_code` (issue #527).

- `yoetz privacy show` — and every other local machine-scope privacy read: the empty-request CLI
  body, `privacy export-desired`, `privacy apply-desired`, the prompt-loop menu's effective-policy
  view, and setup's update-policy probe — now resolves the installation marker through the
  configured storage bundle, the same root the service uses, instead of the fixed platform state
  directory, so an explicit `[storage].data_dir` no longer breaks machine-scope construction. A
  missing or malformed marker (or an unresolvable bundle) stops locally with one bounded
  actionable diagnostic (`machine_scope_unavailable: <reason>: <next command>`, exit 2) before
  any service request, instead of an inadmissible error construction the CLI masked as generic
  `internal_error` exit 70. The diagnostic names no paths, marker content, or secrets
  (issue #517).

- Multi-object object-first appends now abandon every exact caller-owned stage when object
  preparation fails before ledger submission, and equally when the commit boundary refuses the
  append ahead of submission because cancellation is already pending. The rule covers receipt
  creation, cooperative publication batches, and observation materialization, so a later payload
  failure cannot strand an earlier finalized object on every retry. Cleanup still attempts both
  owned locations, preserves the original error if cleanup fails or cannot start, waits for a
  definite outcome before propagating cancellation, and never abandons after submission begins
  because the commit outcome may be ambiguous (issue #339).

- Codex subscription setup, disconnect, and rollback now recompose the local service on the CLI,
  prompt-loop menu, and `/provider` surfaces so a running daemon cannot keep dispatching after the
  binding changes. `/provider` also exposes subscription status, disconnect, rollback, and optional
  account switch. READY composition treats the exact binding, digest, and dedicated home as
  credential presence and no longer spawns a preflight Codex app-server; `account/read` and
  `model/list` stay inside `evaluate()`. Subscription CLI failures map `OSError` /
  `FileNotFoundError` to closed tokens instead of echoing native text (PR #480 review).

- Frontier-motion delivery marks now retain the announced head digest and are compared with the
  routed ledger's actual current frontier. A same-task restore below the delivered high-water (or
  a different digest at the same sequence) discards the stale mark and announces the rewound
  lineage, while an old completed-operation replay is still suppressed when the live ledger has
  not rewound. Notice and delivered-mark caps persist LRU ordinals across restarts, refresh active
  marks, and evict ended sessions before the least-recently-used live entry; legacy marks without
  lineage identity fail open to a duplicate announcement (issue #331, consolidating #332/#333).

- The native Cursor plugin's plugin-owned `mcp.json` now launches the exact Yoetz executable the
  plugin's hooks bind (the `/2` marker launcher) instead of a bare `yoetz` that Cursor's sanitized
  desktop PATH could resolve to an older ambient installation. `yoetz integrate cursor plugin
  status` adds a `launcher` section (executable `matched|drifted|missing|unbound|unobserved`,
  installed `mcp_binding`, and a bounded identity probed from that launcher's `version --json`)
  and `mcp.runtime.executable_activation`, which forces `full_restart_required` when a live Cursor
  helper child runs a different executable. Trees rendered before this fix stay marker-valid and
  report `modified` / `mcp_binding: ambient_path` until one exact previewed replace (issue #468).

- The cooperative MCP bridge latches the first availability failure of its host binding
  (`service_unavailable`, `service_incompatible`, `protocol_mismatch`, `endpoint_unsafe`,
  `peer_untrusted`). Concurrent first arrivals before that result share one on-demand attempt and
  one diagnostic; later calls under a new `request_id` — including delegated workers sharing the
  MCP process — inherit the same public error and `correlation_id` with
  `safe_details.availability: terminal_unavailable` and `availability_inherited: true`, and mint no
  new diagnostic, spawn, or supersede. The original `request_id` replay, a changed service holder,
  or one quiet successful handshake clears it. Agent guidance now carries a bounded
  `yoetz_availability` block into delegated assignments and forbids lifecycle commands from
  `INTERNAL_ERROR` (issues #469, #476).

- Codex activation recommendation decisions now bind the exact executable path/bytes/version,
  canonical home, activation preview, and rendered-cache digest. Another Codex home or a target
  that drifts back to `installed_not_activated` receives fresh actionable advice; active targets
  stay quiet, declines remain exact-target-only, legacy unscoped decisions suppress nothing, and
  activation still requires a freshly shown digest and confirmation (issue #463).

- Disposable-worktree Codex dogfood now has an executable parity gate that fails before launch on
  missing exact-worktree consent or activation and retains packaging, discovery, host delivery,
  model use, hooks, mapping, drain, session stream, semantic provenance, receipt, influence,
  rollback, and normal-target isolation as separate closed-state cells (issue #464).

- The MCP stdio bridge no longer exits on a size-valid but excessively nested JSON frame.
  Inbound nesting is bounded at the canonical codec's 64 levels with a non-recursive walk, any
  decoder `RecursionError` is converted to the fixed `invalid_json` parse error, and a valid
  request succeeds immediately after a rejected deeply nested one (issue #394).

- `yoetz integrate <host> plugin --help` no longer advertises lifecycle commands a host cannot
  run. Each command's help names its hosts (Codex: `preview`, `status`, `remove`; Cursor adds
  `install`; Claude Code has the full lifecycle plus `export`), and invoking an unsupported command
  refuses before any binary discovery or mutation with
  `<host>_plugin_command_unsupported:<command> supported=...` instead of the bare
  `codex_plugin_command_invalid` (issue #465).

- Consented `SessionStart` hooks on Claude Code, Codex, and Cursor now auto-attach a ledger task:
  the shared hook auto-start sends the paired `workspace_ref` (canonical workspace root) and
  `external_ref` (host session) selector the `start` contract requires, validated through the
  public request model before dispatch. Previously the request was always invalid and the failure
  was swallowed, so natural auto-attachment never happened and `observe status` showed no mapping
  without a cause. Every failed attempt now records a closed payload-free `hook_diagnostics`
  reason (`auto_attach_workspace_unbound`, `auto_attach_request_invalid`, `auto_attach_conflict`,
  `auto_attach_refused`, `auto_attach_result_invalid`, `auto_attach_mapping_write_failed`,
  `privacy_authority_required`, or the shared service/vault/timeout/storage tokens) (issue #459).

- Cooperative MCP calls no longer collapse typed local-control failures into opaque,
  non-retryable `INTERNAL_ERROR`. Service absence, an accepted-but-unresponsive listener,
  incompatible or mismatched installations, unsafe or untrusted endpoints, timeouts, and bounded
  protocol refusals now retain an actionable public code, truthful retryability, a structural
  `reason_code`, resolvable correlation diagnostics, and same-`request_id` recovery guidance;
  genuinely unexpected bridge defects remain `INTERNAL_ERROR` (issue #460).

- `yoetz observe status` no longer collapses bounded observation-store filesystem failures into
  generic `internal_error`. Unsafe state/lock shapes, unavailable open/permission/read-only/
  missing-parent/lock failures, and corrupt stored data retain distinct typed outcomes; fixed
  remediation omits the raw absolute state path, and unexpected non-filesystem defects still reach
  the internal-error boundary (issue #428).

- Reopening a task whose one pending check has an undecodable resume checkpoint no longer latches
  non-retryable `STORAGE_CORRUPT` for the entire ledger. Recovery quarantines that operation as
  `operation_resume_object_invalid`, stores the terminal error for same-request replay, and leaves
  events, projection, writers, and every other operation readable and writable. A corrupt event
  chain or object inventory row still fails the bundle once; an environmental `OSError` during
  rehydration still retries without latching (issue #443).

- A check parked on a standing repository-grant handoff no longer refuses every observation
  append for the rest of the session. `suspension_kind=repository_grant` expires the lease
  and is not an active frozen-case barrier, so the drain can ledger hook-observed work
  while the trusted ceremony is outstanding. Same-request replay re-installs the barrier
  and still commits if only observation moved past the frozen subject frontier; cooperative
  motion still conflicts (issue #445).

- A tracked root `CLAUDE.md` whose complete bytes are the reviewed `@AGENTS.md` alias no longer
  makes every later pull request fail the source publication-boundary gate. The exception is
  source-only and exact; nested aliases, changed content, and packaged copies remain blocked
  (issue #455).

- Codex skill install, replace, and remove now refuse a symlink at `.agents` or `.agents/skills`
  as `target_unsafe`, bind the managed parent's identity into the preview digest, and perform the
  stage/replace/remove swap through a directory-fd no-follow walk so a parent swapped between
  preview and apply fails closed (issue #396).
- `inspect_activation` / `yoetz observe status` report `installed_not_activated` for a byte-present
  modified or untrusted plugin tree instead of collapsing it to `not_installed`. `not_installed`
  remains absence only, and a modified tree is never `active`. Apply still requires a current
  renderer variant (issues #347 and #387).

- Replaying a check that was suspended on a standing repository grant no longer fails with a
  non-retryable `STORAGE_CORRUPT` after the trusted `yoetz --privacy` ceremony, and a task whose
  ledger holds `evidence_recorded/1.1.0` events (any evidence carrying a `digest_binding`) no
  longer becomes unreadable the moment a pending check has to be rehydrated from its durable resume
  checkpoint. The checkpoint's projection snapshot records no schema version and its decoder pinned
  every event family to `1.0.0`, so a digest-bound evidence record encoded fine but could never be
  decoded again; every deferred rehydration — the same-request replay after the grant, and ledger
  recovery after a service re-ready while the check was pending — was reported as corruption of an
  intact bundle. Snapshot records now decode under the newest wire version their family admits
  (issue #427).
- Cursor plugin status no longer treats installed `mcp.json` bytes as live MCP runtime. After a
  plugin-managed replace, a surviving shared Cursor helper child on `yoetz mcp serve --semantic off`
  is reported as `mcp.runtime.activation=full_restart_required` instead of looking activated, and
  agent guidance treats `route_semantic_ceiling` against an installed `policy` route as that
  mismatch rather than an owner privacy decision. Reload Window is not a sufficient activation
  instruction; recovery never authorizes egress (issue #426).

## 0.1.0 — Public alpha (2026-08-20)

Initial public alpha release. The earlier 0.0.1 registry packages only reserved the project name
and contained no usable Yoetz implementation.

### Added

- A `status` item's `freshness` scalar no longer contradicts the `coverage.ledger_freshness` in the
  same item. A check that declared a coverage gap records `partial` freshness, but the projection
  reported that only while folding the check itself and reverted to `current` on the next event of
  any family — a receipt or a re-attach was enough — while the item's coverage kept the gaps. The
  projection scalar is now derived from the retained check rather than from whichever event is being
  folded, so it holds `partial` for as long as that check governs, and the compact item reports the
  weaker of the scalar and its own coverage the way the evidence view already did. An agent reading
  the summary line is no longer told the ledger is clean while the structured coverage records the
  gaps (issue #307).

- `provenance_disputed` is a fourth `respond` disposition. It records that the responder contests
  the finding's authorship or provenance premise rather than its conclusion, requires a reason, may
  carry evidence, and is not scored as an evidence-free rejection by either deterministic policy
  pack. Like every other disposition it never resolves or erases the finding. The MCP `respond`
  surface advertises it in both the tool description and the `disposition` field rules, so a caller
  reading only the advertised schema learns the rule (issue #224).

- Status compact/readiness projections now distinguish `unanswered_finding_count` from
  `receipt_blocking_finding_count`. Responses clear the former; current actionable receipt findings
  remain in the latter for every disposition. The paired `findings_unanswered` and
  `receipt_findings_unresolved` conditions tell agents whether to respond or proceed to an honestly
  unresolved receipt, and agent guidance no longer offers the human-only `waived` disposition
  (issues #286 and #287).

- The idle relock clock now counts harness observation rows resolved by the ready sweep as
  activity, so a live workspace whose hooks keep delivering events is never relocked underneath
  an open task session — however long the run — while a workspace that truly goes quiet still
  relocks one full window after its spool runs dry. The default idle-relock interval is now 3600
  seconds (was 900, shorter than one legitimate implementation phase under the prescribed publish
  cadence), and the process-idle stop is now 7200 seconds so the in-process soft relock — which
  re-readies on the next ordinary call — always comes before the full process stop (issue #291).

- MCP success summaries now preserve the canonical frontier head digest and, for generic
  operations such as `start`, returned task/session/writer identifiers after strict shape
  validation. The bounded text fallback can therefore seed the next request even when a host drops
  `structuredContent` (issue #279).

- Local-only SessionStart observation now emits the static attach advisory without opening a
  service connection, and pending standing advice shares that bootstrap context instead of being
  starved (issue #280).

- Observation sweeps that raise now retain the exception's bounded reason and origin in owner-only
  diagnostics; only the actual sweep deadline emits `sweep_deadline_exceeded` (issue #278).

- `publish_work` rejections for a payload field placed on the wrong event family now name the
  field's one legal owning family (issue #266). When an `extra_forbidden` key byte-equals a frozen
  catalogued payload property with exactly one owner among the ordinary publish families — the
  2026-08-14 dogfood case was `attempted_items` on `claim_recorded`, owned solely by
  `action_recorded` — the error carries a flat `repair_*` fact in `safe_details`, one bounded
  ownership sentence in the authoring hint, and a `Repair:` clause on the compatible text summary.
  The request stays rejected, nothing is moved or reinterpreted, caller-invented keys are never
  echoed, and ambiguous or envelope-owned fields keep the plain admitted-key answer from issue
  #240. Agent-facing guidance now teaches the same ownership before the first call (issue #264):
  the skill, workflow, and agent instructions name `action_recorded` as the sole owner of
  `attempted_items`; the request templates show the `requested_items` → `attempted_items`
  exact-value pairing, call `decision_recorded.authority` a structural actor id, and name the
  closed `action_kind` enum with `edit` for source changes; and the model-visible `publish_work`
  description front-loads all three rules for hosts that degrade schema metadata.

- Cooperative writers now receive a one-shot, coalesced notice when the observation writer moves the
  task frontier, including the bounded sequence range and observation-record count. The notice map
  is capped, drops ended-session entries, and is reconstructed on retry from a completed append's
  frontier metadata when the local write did not land. A per-session delivered high-water
  `to_sequence`, scoped to the announced task ledger, survives notice deletion so a replayed
  append is not re-announced. Successful
  routine reads remain available in the local observation store but are rate-limited out of the
  task ledger; failures, denials, path-qualified executables, and conservatively unrecognized
  commands still materialize normally (issues #244 and #322, ADR-022 amendment).

- Consent-based Codex observation activation and durable delivery repair (issues #204 and #205,
  ADR-012 amendment): setup now distinguishes installed hook sources from an active plugin, previews
  the exact selected Codex executable and explicitly selected existing home, repository marketplace,
  append-only plugin-enable change, post-consent scoped inventory/add commands, and versioned
  byte-exact cache transition, and applies them only after digest-bound approval. Its pre-consent
  version probe runs in a disposable owner-private home; selected-home inventory and scratch effects
  begin only after approval with both Codex home variables forced to the approved target. `active`
  requires installed managed sources, exact
  marketplace/config state, Codex's installed-and-enabled inventory row for this repository, and a
  cache identical to the managed plugin tree; marketplace/config bytes alone remain
  `installed_not_activated`. A post-write failure preserves approved partial state for an honest
  retry; it never risks deleting or overwriting concurrent state through pathname rollback. Setup
  probes use isolated state instead of polluting the live outbox.
  Observation delivery no longer depends on an already-existing lifecycle mapping: READY and
  periodic service sweeps recover pending envelopes, retry metadata and bounded hook diagnostics
  explain failures, and `yoetz observe status|drain` reports and repairs undelivered work without
  silently deleting it. `[observation].enabled` is a typed local configuration gate that defaults
  on; per-workspace observation consent remains independently required.
  Observation drains preserve FIFO within each session lane, retire a lane after its head fails,
  quarantine ended unmapped sessions only after fencing against a concurrent attach, and stop a
  service sweep after one workspace-global rejection. Turn-boundary auto-attach retries are
  bounded and diagnostically visible. Transient
  ready-application activation failures after a successful soft unlock remain retryable for three
  attempts, and MCP now preserves the daemon's retryability in `VAULT_LOCKED` guidance.
  Observation hooks no longer block the session (#209/#210/#211): pure-ingress handlers are
  declared `"async": true`, advice-returning handlers get a meetable 10-second budget, the control
  handshake hashes the schema manifest without building the catalog, the local store caches its
  parse behind a stat validator, and the drain stops re-probing sessions whose rejections cannot
  heal mid-pass. Quarantined observation detail is now bounded by a clock-fenced 14-day age in
  addition to count and byte caps, `yoetz observe reclaim --workspace <path>` drops it explicitly,
  and `yoetz observe status` reports quarantine depth plus separate involuntary-eviction and
  operator-reclaim counts.
  **Upgrade note:** the hook timeout/async changes alter Codex's per-hook trust hashes. On an
  existing install every changed hook reports `Modified` and is silently skipped until re-approved
  through Codex's startup hooks review (or the equivalent trust configuration); until then only
  the unchanged hooks fire. Re-approve the yoetz hooks after upgrading the plugin tree.

- A reusable recommended-defaults advisory surface (ADR-021): releases register reviewed
  recommendations, heavy control points cache pending items, and SessionStart may ask the agent to
  explain at most one item and request user approval. `yoetz recommend list|accept|decline` is the
  only application/decision path; declines are remembered and never re-nagged, and upgrades never
  flip configuration or Codex activation silently. Initial consumers cover observation enablement,
  Codex plugin activation, and the existing policy-gated PyPI update advisory. The durable
  `update_checks` channel remains the only update-check flag, accepts only bounded package identity,
  and never auto-upgrades; Yoetz has no npm update check because the npm package delegates to the
  canonical exact-version PyPI distribution.

- Typed evidence digest provenance (`evidence_recorded/1.1.0`) records the exact closed byte
  subject, availability, byte count, and authority that established each new digest. Kind/subject
  contradictions fail closed; approved checks publish bounded service-owned receipts; legacy,
  digest-only, withheld, redacted, and semantically omitted evidence remain explicit limitations
  without changing frozen `evidence_recorded/1.0.0` bytes (ADR-020). In semantic review, a
  digest-bound evidence record with a bounded caller `description` surfaces that description as
  the excerpt text while the digest identity travels alongside on the excerpt ref
  (`digest_provenance`), so honest provenance no longer hides the content from the reviewer
  (issue #176).

- The six-operation protocol (`start`, `publish_work`, `check`, `respond`, `status`, `receipt`) over
  both the CLI and MCP, with identical request/result contracts and a shared canonical
  encoding/idempotency model.
- A persistent, per-user local service that is the sole owner of encryption keys, decrypted state,
  and SQLite writer connections, reached over an authenticated local control protocol; CLI and MCP
  are bounded clients of it.
- Local encrypted object storage (`yoetz-object/1`) and an installation vault with OS-keyring and
  explicit passphrase initialization modes.
- Generation-fenced single-writer durability for the installation catalog and every task bundle,
  built on APSW/SQLite with WAL and verified build/PRAGMA checks.
- A centrally enforced privacy and data-egress protocol: classification, policy resolution, local
  minimization/redaction/secret scanning, optional human preview/approval, and a structural
  `EgressReceipt` for every reserved decision and physical attempt. The durable product default is
  `local_only` with structural package update checks on (opt-out) and no task-content egress;
  true zero-network requires turning `update_checks` off as well.
- Interactive package-update advisory (TUI first-run finish, resume tip, `/doctor`) and
  upgrade-over-same-version-reinstall prompts on setup/`/connect`, gated by the independent
  `update_checks` channel against an allowlisted PyPI identity URL. Upgrade remains a human-run
  `uv tool upgrade yoetz` command; work receipts are unchanged.
- Widening the privacy policy is authorized only at the reauthenticated trusted terminal, which
  renders the complete `before → after` diff of every security-relevant field the proposal moves —
  destination, disclosed information, confirmation, authorization scope, limits, and local
  visibility — derived from the same comparison that classifies the change as a widening. The diff
  digest is shown as integrity evidence and labelled as such rather than as the description.
- Privacy setup opens on one recommended policy — Assisted review for an exact provider route with
  current reviewed no-training evidence and retention no longer than 30 days, Private otherwise —
  with its trade-off stated. Accepting it asks nothing further; declining opens the named recipes
  (Private, Metadata only, Assisted review, Expanded review, Custom), and only Custom configures
  individual settings, in five grouped sections. The terminal interface's `/privacy` uses the same
  rule and the same recipe names, and selects rather than authorizes.
- `yoetz privacy pending` lists the disclosure decisions awaiting a local human, with their expiry
  and nothing about what they would disclose. `privacy decide-disclosure` needs an exact pending id
  that normally arrives in the check result waiting on it; this is how that ceremony is found again
  when the id is lost. It is a CLI/UI-only ordinary control method and is not reachable over MCP.
- First run offers semantic review first and pre-selects it, in both the prompt-loop wizard and the
  terminal interface. This is a recommendation about that question only: every installation still
  seeds zero-egress `local_only`, the answer binds no provider and commits no policy, and local-only
  remains one keystroke away. The answer is now taken before the Codex MCP registration, and decides
  which route is registered.
- An optional, privacy-gated semantic review path behind the same gateway, with a reviewed OpenAI
  Responses adapter, a local-model AF_UNIX profile, and a scripted fake provider for testing.
- Codex integration as the first-party harness adapter: an explicit trusted-project skill
  install/status/remove flow, an MCP stdio bridge, and a JSONL transcript importer. The tested
  Codex version set remains empty pending exact installed-artifact capability evidence. An import
  job belongs to the writer that published it: only that writer resumes it or replays its terminal
  report, and another writer submitting the same source bytes is refused rather than shown the
  owner's report, request id, or report locator.
- Backup, restore, and forward-only migration support with frontier-pinned manifests and verified
  route switches; see [`docs/runbooks/`](docs/runbooks/) for the operator procedures.

- **Full-screen terminal interface** as the interactive entry point (ADR-017, amending ADR-013
  decisions 1–2 and ADR-012 decision 2 as ADR-013 left it). Bare `yoetz` and `yoetz menu` on a
  real terminal open one continuous surface — session header, transcript, composer, and a stack
  of temporary views — with first run folded in as its opening steps rather than a separate
  wizard pass. Slash commands `/status`, `/work`, `/check`, `/receipt`, `/connect`, `/privacy`,
  `/provider`, `/service`, `/doctor`, `/help`, `/quit` name existing operations in plain
  language. Readiness renders as fifteen independently falsifiable layers rather than one
  "connected" state; `✓` is reachable only from a layer the owning service reported as verified.

  The interface adds no authority: `yoetz/tui/runtime.py` is the sole bridge to application
  services and originates no decision. MCP registration keeps preview → digest-bound confirm →
  verify (now via `setup.apply_codex_integration`, which requires the caller to echo back the
  exact preview *and* policy digests it displayed and refuses as stale if either moved — stricter
  than `--accept`, which still activates no policy trust). A foreign MCP entry remains a terminal
  block with no force-replace path. Privacy widening renders the exact disclosure and then hands
  off to `yoetz privacy propose|decide`; the interface never widens policy itself. No secret ever
  enters the interface: credential entry suspends the full-screen app and hands the controlling
  terminal to the existing confidential ceremony.

  Non-interactive behavior is unchanged. The interface opens only when stdin and stdout are both
  TTYs, `TERM` is usable, no CI marker is set, and `YOETZ_TUI` is not `0`; pipes, redirects, CI,
  `--help`, `--json`, named subcommands, `yoetz mcp serve`, and the protocol fixtures keep their
  exact previous bytes, and a bare non-TTY `yoetz` still prints help. Installations without the
  rendering dependency fall back to the ADR-013 prompt-loop menu, which remains supported.

  Adds one pinned runtime dependency, `textual==8.2.8` (with `linkify-it-py`, `mdit-py-plugins`,
  `uc-micro-py`; all MIT, all on the reviewed-license allowlist).

- First-run setup wizard (ADR-012): bare `yoetz` on an interactive terminal with no completion
  marker launches `yoetz setup run` — Codex PATH discovery with an explicit choice when several
  installs exist, preview-and-confirm MCP registration (`codex mcp get` first; foreign entries
  preserved, never replaced; success verified by re-reading state), a service reachability check,
  and printed next steps for the privacy-setup and provider-credential ceremonies, which remain
  human-driven. `yoetz setup status` reports the same posture read-only; every non-TTY bare
  invocation still prints help.

- Interactive control menu (ADR-013): bare `yoetz` on an interactive terminal opens a
  navigable menu (first-run still gets the setup wizard once, then lands in the menu), and the
  `yoetz menu` command opens it explicitly. The menu shows a status overview (service
  reachability, vault mode, Codex MCP registration, first-run posture) and dispatches to the
  existing operations — setup wizard, harness MCP/skill integration, provider-credential
  ceremonies, privacy posture reads, and service unlock/lock/stop — with every preview/confirm
  gate and confidential ceremony unchanged. Non-TTY, piped, and CI invocations keep the
  historical help output byte-for-byte.

- First-party Codex **live observation and advice** as a required v0.1 capability (ADR-010
  amendment): dual-source ingest (hooks primary + selective session-stream reconciliation), local
  `ObservationPort` control (`yoetz observe status|grant|pause|resume|revoke|reconcile|drain|reclaim`), unified
  `yoetz hooks observe`, workspace-level observation consent via private workspace commitment,
  automatic session↔task attachment without depending on MCP `start`, descriptor-safe workspace
  inspection, approved-check runner, and deterministic `AdviceSnapshot` guidance (optional semantic
  review remains additive). Still exactly six MCP tools; observation is CLI/service control only.
  Sensitive evidence stays encrypted; no unencrypted transcript spool; `hook_observed` requires real
  observation evidence under active consent.

- TOML alternate settings surface and owner-declared OpenAI-compatible endpoints (ADR-014 /
  issue #2): `config.toml` may bind Official OpenAI (`openai-responses`) or
  `owner-declared-openai-responses` with constrained `[provider.owner_declared_endpoint].https_origin`
  (HTTPS host+optional port only; no secrets, headers, or free `base_url`). Wizard and menu collect
  the same nonsecret choice; `yoetz provider endpoint` writes it. Owner-declared data-use defaults
  to `unknown` (never inherits `assisted`). Privacy desired-state TOML via
  `yoetz privacy export-desired` / `apply-desired` classifies tighten vs widen and never silently
  widens egress. Credentials, vault unlock, MCP registration, and widening decide remain
  ceremony-only.

- `yoetz integrate <harness> mcp status|preview|install`: digest-bound, preview-gated MCP server
  registration as a first-class command, backed by the sibling `HarnessMcpPort` and Codex
  discovery/registration adapters.

- `closure_readiness` on every `status` success (`open_obligation_count`,
  finding counters, `blocking_conditions`), so an agent can see what currently bounds a
  completion conclusion before spending a `check` or `receipt` rather than learning it afterwards
  from an insufficient receipt. Derived per request: it records nothing, creates no verdict or IDs,
  and never strengthens coverage. When the compact singleton is unreadable all counts are `null`
  and the only condition is `readiness_unknown` — unknown is reported as unknown, never as zero.

- A worked `publish_work` example per ordinary publishable event family, so agents no longer
  hand-derive action/result/evidence/claim shapes from a large `oneOf`. `check`, `respond`, and
  `receipt` carry worked examples too.

- Public npm launcher at `support/npm-launcher/` for `npx yoetz`: a dependency-free delegator to
  the exact pinned `uvx yoetz==<version>`, published only after the matching Python artifact by the
  protected tagged workflow. It propagates signal
  termination as the conventional `128+n` exit code and gives actionable, platform-specific
  guidance when `uv` is absent; it installs nothing, bundles nothing, and duplicates no setup or
  interface logic.

- Public protocol documentation under [`docs/protocol/`](docs/protocol/) and the evidence-bound
  claim map at [`docs/public-claims.json`](docs/public-claims.json).

- **The registered MCP route is now observable.** Both Yoetz-owned Codex serve commands classify as
  `yoetz_owned`, so registration state alone reported a strict registration and a policy
  registration identically — and `yoetz provider status` never looked at the route at all, letting
  `semantic_ready: true` be read as "semantic review will run" on an agent route that cannot
  dispatch it. `yoetz provider status` now also reports `mcp_route` (registered profile, configured
  profile, and whether it was read) and a second, narrower `agent_route_semantic_ready` verdict;
  `yoetz integrate codex mcp status` reports `route_profile`, and `yoetz setup status` rows carry
  `registered_route_profile`. `semantic_ready` keeps its existing installation-local meaning and
  the exit code is unchanged: a strict route is a process-local ceiling (ADR-018), so CLI and
  terminal checks still dispatch, and it is reported as a blocker scoped to the agent route only.
  Route observation is fail-soft and never changes the exit code. A new
  [semantic dogfood runbook](docs/runbooks/semantic-dogfood.md) turns this into a preflight that
  declares which claim a run may make, and a provenance gate that refuses to score semantic quality
  when no provider attempt happened.

- **Influence dogfood protocol (docs/test-only).** A new
  [influence dogfood runbook](docs/runbooks/influence-dogfood.md) measures Yoetz-to-agent intervention
  without conflating operational health, authoring UX, semantic quality, and work-product influence.
  Offline unit tests lock classification rules (activation vs registration, strict-route Stream C as
  `not_tested`, early publication gate, miss taxonomy, honesty vs work-product influence, forbidden
  summary). No protocol, privacy, storage, or MCP surface change.

### Documentation and repository

- Agent-start guide: `docs/usage/agent-start.md` addresses the coding agent installing Yoetz on a
  user's behalf — why setup's questions never appear in an agent shell (TTY-gated by design), the
  exact decision list to relay to the human, the post-setup provider-credential recommendation,
  the scriptable surfaces an agent may use with explicit user instruction, and the prohibitions
  (no credential handling outside the warned consent lane, no privacy widening, no foreign-entry
  overwrite). Linked from
  `README.md` and `docs/usage/install-and-first-run.md`; fetchable raw until `yoetz.dev` hosts it.
  The two surfaces an agent actually lands on now point at it: the non-TTY bare `yoetz` help
  footer, and a `next_steps` entry in the `yoetz setup run` non-interactive dry-run report.
- User documentation: `docs/architecture.md` (topology, module map, honesty rules), `docs/usage/`
  (install and first run, the terminal interface, the six operations, privacy and semantic review,
  providers and credentials, receipts and coverage), and `docs/README.md` / `docs/adr/README.md`
  indexes. `README.md`, `CONTRIBUTING.md`, and `AGENTS.md` were rewritten — the README had still
  described the repository as containing no implementation.
- Contribution intake: issue-first process with duplicate search, design gates for
  protocol/privacy/storage/release/ADR work, mandatory PR checklist, and required disposition of
  human and code-review-agent comments (`CONTRIBUTING.md`, `.github/ISSUE_TEMPLATE/`,
  `.github/pull_request_template.md`), plus root `AGENTS.md`, root `CODEOWNERS` for trust
  boundaries, and a SECURITY threat-model / out-of-scope table.
- **Retired the spec-mirror tree.** Yoetz was built spec-first, with one Markdown owner per planned
  file at a mirrored path under `specs/` (640 files, ~63k lines) plus a CI-enforced ownership
  manifest. That method finished its job — all 626 declared files exist — so the tree was removed
  rather than maintained as a second copy of shipped code. The authority chain is now `docs/adr/` →
  `docs/INTERFACES.md` → code and tests. `INTERFACES.md` and `OPEN_QUESTIONS.md` moved to `docs/`;
  `scripts/verify_spec_manifest.py` and its CI gates are gone; required check names are unchanged.
  The full tree stays recoverable at tag `specs-tree-final` (`git show specs-tree-final:specs/…`).
- Release and PR CI no longer swallow packaging/subprocess/integration suite failures behind a
  "tests not yet present" warning; those gates fail honestly.

### Hardened before first release

These defects were found and fixed during pre-release development. No published version ever
carried them; they are listed because each one describes the behavior that now ships.

- **Workspace inspection no longer follows mutable names after validation (security).** Opening an
  inspect workspace retains an authenticated root directory descriptor for the handle's lifetime.
  Later reads open descendants descriptor-relatively with no-follow semantics and re-check the root
  identity; replacing the root directory between open and inspect can no longer redirect a read
  outside the consented workspace. Intermediate directory symlinks that escape the root are refused
  (`symlink_escape`); in-root symlink chains remain readable up to a bounded depth. Content that
  changes during a single read is refused (`read_failed`) rather than returned.

- **Publish recovery must not mask a known authoring error.** When MCP `publish_work` body
  validation fails, envelope-first operation lookup still runs so a committed same-`request_id`
  operation can be recovered. A failed recovery read (for example nested `read_projection_failed`)
  no longer replaces the field-pointed `INVALID_REQUEST` with a false “no durable state changed /
  use a new request_id” message. Lookup is a closed tri-state: found recovery results retain
  precedence; authoritative absence returns the original authoring pointer; unavailable recovery
  keeps the field-pointed, non-retryable `INVALID_REQUEST` primary and carries
  `operation_recovery_unavailable` as a `reason_code` beside the `fields`/`reasons` locations in
  the same `safe_details`, with a caveat that a prior operation under this `request_id` could not
  be checked and that resubmitting the corrected body lets the service replay or reject the
  `request_id` itself. When nothing is locatable, `safe_details` carries that `reason_code`
  alone.

- **`check` can return a finding.** A check that raised even one finding committed durably and then
  failed to project, so the caller received `INTERNAL_ERROR` / `response_projection_failed` and
  never learned the verdict, the finding, or the semantic outcome — in every mode. The public
  result models are strict, and the internal result carried each nested entry in an immutable
  mapping type strict validation does not admit; the check result's projected finding additionally
  requires `provenance` to be present as an explicit null on a deterministic finding. Nested
  mappings are now normalized structurally at the one projection boundary — no coercion, no
  reordering, no defaults, and a genuinely invalid shape is still rejected at the same field.

- **An accepted durable `publish_work` is never reported as a failure.** When full response
  projection fails after the append succeeded, the daemon returns a reduced total-acceptance
  success (`ok: true`, `response_completeness: "accepted_projection_unavailable"`) with frontiers,
  accepted event ids/digests/sequences, and a `correlation_id` — not `INTERNAL_ERROR` /
  `response_projection_failed`. The agent needs no second `status` call and no same-`request_id`
  replay to learn what landed. Unexpected exceptions also write a durable owner-only diagnostic
  ring under `log_dir()` (`yoetz service diagnostics --correlation-id err_…`).

- **A post-commit projection failure now says where the write landed.** For non-publish writes (and
  the impossible minimal-envelope path), `response_projection_failed` still carries the committed
  `sequence`, `head_digest`, and accepted event `count` in `safe_details` / `accepted_state`.

- **Invalid tool arguments name what is admitted.** The response listed field locations only; it
  now also names the admitted enum members and the required identifier pattern for the rejected
  top-level fields, and points at the tool's worked example — all from checked-in schema bytes.

- **A receipt explains why a check does or does not count.** `check_not_applicable` appearing right
  after a successful externally-reviewed check read as a contradiction. The limitations section now
  states that the recorded check tested a different subject frontier, that its verdict stands only
  for what it tested, and that re-running `check` at this frontier is what makes it contribute.
  `check_not_recorded` and `check_payload_unavailable` are explained the same way.

- **Answering a finding no longer discards the check that raised it.** `response_recorded` is a
  material family, so the guidance-mandated `check` → `respond` → `receipt` sequence always ended
  in `check_not_applicable`: a successful semantic check's
  `check_types: ["deterministic", "semantic_model_derived"]` never reached the receipt, which
  claimed only the `["deterministic"]` baseline it would have carried with no check at all. A
  response to a finding the applicable check itself returned now leaves that check attributable —
  its coverage and semantic gaps fold into the receipt — and the receipt declares the new gap
  `check_current_as_of_earlier_frontier`, stating that the verdict is current as of the subject
  frontier it tested rather than the receipt's. Responses to findings the check did not return,
  responses whose payloads are redacted or unreadable (they cannot prove which finding they
  answered), and every other material event still require a re-check. Compact status uses the same predicate, so
  status and a receipt at one frontier cannot disagree (issue #172).

- **A read is no longer told to replay a write.** A projection failure on `status` (or a privacy
  receipt read) advertised the same-`request_id` replay remedy as an accepted write, but a read
  appends nothing, so no operation record exists to replay against and the caller waited on a
  recovery that could not arrive. Reads now surface the retryable `read_projection_failed`, whose
  remedy is repeating the request. Observed in the 2026-07-27 Codex dogfood, where a compact
  `status` call failed twice and its exact replay failed again.

- **The post-commit projection window fails with bounded, named errors.** Rewriting a blocked leaf
  raised a bare `KeyError` when the omission pointer did not resolve in the body — reachable via
  the synthetic `/leaf-N` pointer produced when an origin pointer exceeds 256 bytes — and a bare
  `ValueError`/`IndexError` for a malformed or out-of-range array segment. These now raise
  `projection_pointer_unresolved`/`projection_pointer_invalid`. They are deliberately not remapped
  to `privacy_projection_blocked`: no policy blocked them, and that reason is non-retryable, so it
  would describe an already-durable append as a refusal. The projection stops before a response
  exists either way, so blocked content is never disclosed.

- **Installed guidance no longer points at files that were never packaged.** `skills/codex/yoetz/SKILL.md`
  linked four `references/*.md` paths absent from both the repository skill directory and the
  packaged resources; it now names the `yoetz://guidance/*.md` URIs the server already serves. A
  packaging test resolves every reference the installed skill names, reading only the packaged
  tree.

- **An accepted write is never reported as an unqualified failure.** A handler returning is the
  commit boundary; response shaping happens after it. An unexpected failure in that window now
  surfaces as the retryable `response_projection_failed` naming same-`request_id` replay, instead
  of a generic non-retryable `INTERNAL_ERROR` that both misdescribed the ledger and steered callers
  away from the idempotent replay that recovers it (ADR-008). Deliberate bounded failures raised in
  the same window pass through unchanged.

- Validation failures inside `expected_frontier`/`at_frontier` now name the offending leaf
  (`head_digest`, `sequence`) instead of projecting to the parent object, which reported only that
  something in the frontier was wrong. Caller-supplied extra keys are still never echoed.

- `EVENT_INVALID` now locates the rejected draft by ordinal and owning field (for example
  `/event_drafts/2/schema`), so a multi-draft batch no longer has to be re-derived to find the one
  bad member. The pointer is built only from frozen schema names and a bounded index.

- `yoetz provider status` now states which lifecycle it probed (`user_service_no_autostart`) and
  whether MCP-local composition starts on demand, so an absent service no longer reads as
  contradicting a working MCP session.

### Known limitations

- Independent security review of the vault, key hierarchy, and privacy gateway is a release gate
  that has not yet completed — see `docs/public-claims.json` for exactly which claims currently have
  evidence.
- v0.1 ships no production transport for telemetry, crash diagnostics, or capability testing;
  they exist only as denied policy vocabulary. Structural package update checks are the sole
  non-LLM exception: when independently enabled, they use the bounded allowlisted PyPI transport
  and never carry task/user content or upgrade the package automatically.
- Native `launchd`/`systemd-user` service installation and headless passphrase unlock are not
  included; see [`docs/protocol/local-service-security.md`](docs/protocol/local-service-security.md).
- The advertised platform matrix is macOS 11.0+ arm64 and glibc 2.28+ x86-64 only; other platforms
  are untested.

### Fixed

- Hook observation advice no longer tells an agent `Next: refresh_observation`. That token
  remains the snapshot next-action value, but the hook clause now names the real host-shell
  step (`yoetz observe status`) and asks the agent to disclose the gap if it persists at
  check time. `guidance/workflow.md` lists all ten next-action tokens as English next-move
  names, not tools (issue #323).

- The request-template fallback now names the closed `requested_items[].item_kind` enum
  (`change`, `command`, `file`, `source`, `url`) and shows a `change` example beside the
  existing `command` entry. Guidance's own "requested outcome" vocabulary is confined to
  `description` / `acceptance_criteria`, so `outcome` is no longer primed as a kind (issue #318).

- A finding-wording change no longer wedges an in-flight check on its own `request_id`. The
  persisted deterministic-result checkpoint requires byte-equal rendered finding text on replay,
  so any wording edit made every pre-change checkpoint replay as non-retryable `STORAGE_CORRUPT`
  ("The deterministic checkpoint is corrupt.") while the continuation kept pointing at the same
  request. The checkpoint now stamps the kernel's rendered finding-text contract digest; on
  replay, a checkpoint whose bindings verify but whose stamp is absent (pre-change format) or
  from different wording is treated as superseded and the deterministic phase recomputes from the
  unchanged digest-verified frozen case in the same invocation. Genuinely broken checkpoint
  content still replays as `STORAGE_CORRUPT` (issue #340).

- Frontier-motion notices no longer re-announce already-delivered observation appends when the
  outbox redelivers a committed envelope. The local store keeps a per-session delivered high-water
  `to_sequence` after the hook consumer receives the notice; `note_frontier_motion` drops
  candidates at or behind that mark and clamps overlapping ranges so later genuine motion starts
  from the announced head and record counts do not double-count. The mark is scoped to the
  announced task ledger: when a session's mapping moves to a different task, the stale mark is
  discarded rather than silently suppressing the new ledger's motion (issue #322).

- Receipt replay of a completed `request_id` no longer collapses object-store faults into
  unclassified `INTERNAL_ERROR`. Verification mismatches (tampered or missing envelope, wrong key
  slot) are non-retryable `STORAGE_CORRUPT` with the stored-receipt-invalid family. Environmental
  I/O on a durable valid envelope is retryable `STORAGE_UNSAFE`. Pre-append `stage`/`finalize` I/O
  on a fresh receipt is also retryable `STORAGE_UNSAFE`. Classified receipt storage faults carry a
  resolvable `correlation_id` with a bounded exception-class reason and optional `yoetz` origin so
  the corruption runbook can join the public envelope to the diagnostic ring without an
  `internal_error` diagnostic (issues #325, #336, #337).

- The MCP initialize `instructions` string had no size bound and had grown to 41 KB by inlining
  three guidance documents. Codex copies that string into the `description` of every advertised
  tool, so it was charged seven times on every turn of every session — roughly 288 KB of advertised
  surface, six-sevenths of it duplicate, which a dogfood session hit as a truncation warning.
  `instructions` now carry `agent-instructions.md` alone; `workflow.md` and
  `coverage-and-receipts.md` are reached through the catalog paragraph that document already
  carries, and through the `read_guidance` tool that has served them since the same issue the
  inlining was working around. The packaged Codex skill no longer claims the two documents are
  already in context. `SERVER_INSTRUCTIONS_BUDGET` and `ADVERTISED_SURFACE_BUDGET` now bound the
  instructions block and the aggregate advertised surface, asserted alongside the per-schema
  budgets, so the next oversized guidance edit fails CI instead of a live session (issue #300).

- Correlated Codex `PreToolUse` and `PostToolUse` phases no longer claim one SQLite logical identity
  with incompatible operation digests. The canonical host-call identity remains the content and
  ledger-dedup key, while the durable claim key is additionally scoped by the materialization
  version and exact draft-role tuple; pre-action and paired-result phases therefore cannot collide,
  and hook/stream copies of the same paired phase still merge to `source_mask == 3`. Claims record
  the source-independent materialization version rather than the source cursor version. A genuine
  claim conflict now quarantines only that envelope as `dedup_conflict`; only bundle corruption arms
  the READY-generation session latch (issue #309).

- A Codex hook with a stale lifecycle mapping treated the daemon's `SESSION_CONFLICT` or
  `SESSION_NOT_FOUND` response as proof that the service was unavailable, then repeated that false
  advisory forever because it retained the old session and writer ids. Status errors now pass
  through an exhaustive classification: stale mappings tell the agent to call `start` again while
  explicitly preserving service health, transient reads request a later status read, privacy and
  vault conditions name their actual recovery paths, and only genuine degradation says the service
  is unavailable. The stale advisory remains advice-safe and the agent's successful `start` result
  is still the only source of a replacement mapping (issue #308).

- The end-to-end hook budget was smaller than the budgets enforced inside a single pass, so
  `hook_budget_exceeded` fired on healthy hooks — 253 of 833 diagnostics on one workspace — and
  carried no signal about the regressions it was added for. The total is now derived from the
  connect preflight and drain budgets plus a local-stage allowance rather than being an
  independent constant, and events that may retry auto-attach carry that enforced budget too. A
  test asserts the derivation so the parts can no longer drift past the whole (issue #288).

- `stream_partials` was the only unbounded collection in the observation state file and was
  absent from the eviction ladder, so two entries could hold 41% of a file at 95% of its hard
  1 MiB cap while overflow evicted envelopes and outbox rows around them. A partial is a
  read-cache — the reader rereads the tail from the committed cursor whenever it is missing — so
  it is now bounded per entry, dropped with an explicit gap instead of raising (which previously
  stalled the stream while retaining the partial that caused the stall), and shed first in the
  `_save` eviction ladder, ahead of any durable row. The per-entry bound is the reader's own read
  chunk and may not fall below it: the reader assembles a source line longer than one chunk by
  holding its prefix, so a smaller bound would drop that prefix every pass and freeze the cursor
  for that session. Oversized partials persisted before this
  change are dropped on the next save; the condition projects as `source_lag` on status until a
  reconcile catches up (issue #289).

- The `store` stage of every hook pass cost ~500 ms on a full state file and the diagnostic could
  not say where it went. Canonical JSON validation and escaping walked every string one character
  at a time in Python, which was ~70× the stdlib cost on the same bytes; both hot loops now take a
  single C-level scan and fall back to the original logic only when a string actually contains an
  escape or an invalid codepoint, so output and error identity are unchanged. Measured against a
  live 1 MiB state file, one parse, hydrate, encode, and write fell from ~275 ms to ~55 ms — parse
  ~82→13 ms and encode ~155→24 ms. Timing rows now also
  break `store` into `store_hydrate`, `store_encode`, and `store_write` so any remaining cost is
  attributable, and a latency fence bounds the codec against the stdlib on a realistically-sized
  document (issue #290).

- An evidence-free rejection or waiver of a current deterministic finding minted two actionable
  findings, `questionable_finding_rejection` and `weak_or_stale_response`, doubling the response
  burden at every level. `check` now collapses that overlap when it composes the built-in packs,
  keeping only `questionable_finding_rejection`. `weak_or_stale_response` still stands on its own
  for stale responses, for unsupported current responses to semantic findings, for stricter
  work-integrity-only evidence exclusions, and whenever the research-evidence pack did not run
  (issue #285).
- Codex Step 0 treated an empty MCP `resources/read` as success and advertised that guidance URIs
  "resolve without any repository checkout". The skill now stops on an empty body, calls
  `read_guidance` with the same URI, and opens the matching installed `references/<name>.md` copy
  if that tool result is also empty. MCP registers `read_guidance` as a seventh, read-only tool that returns the
  full guidance document as tool text and is not a ledger operation. `resources/read` now
  advertises each registry `media_type` instead of hardcoding `text/markdown`.
  `docs/INTERFACES.md` no longer states that unprofiled hosts can fetch those documents
  unconditionally (issue #203).
- Codex Step 0 never named `resources/list`, but agents still called `list_mcp_resources` first
  and treated `Unexpected response type` as a missing server. The skill and initialize
  `agent-instructions.md` now say not to list: the five `yoetz://guidance/` URIs are the
  complete catalog, and a list failure is not a reason to stop or to read product source
  (issue #173). The served list payload stays spec-correct. `rmcp 3.0.0` (Codex
  `0.148.0-alpha.6`'s pin) decodes that payload as `ListResourcesResult` for every
  optional-field subset, so this does not strip list fields and does not claim a host-side
  decode fix.
- A Stop hook that selected advice completed in ~1.4s with exit 0, then Codex marked it Failed
  with `hook returned invalid stop hook JSON output`. Stop has no `hookSpecificOutput`; the
  event-agnostic emitter was writing `additionalContext` onto a wire type that only admits
  universal fields plus `decision`/`reason`. Stop advice now uses `decision: block` plus
  `reason`, with `stop_hook_active` as the host loop guard. SessionEnd no longer peeks or
  commits advice: the host discards that stdout, so a delivery there would consume text the
  agent never sees (issue #222).
- The very first MCP call after a cold start could return `SERVICE_UNAVAILABLE` from a healthy
  install: the daemon published its control endpoint and accepted connections up to ~19 seconds
  before it could answer a handshake, and the on-demand connector treated the silent socket of
  the daemon it had itself just spawned as wedged, abandoning most of its 30-second budget after
  ~8 seconds. The endpoint is now published only after activation settles — a connect during
  startup is refused, which the connector correctly treats as still-starting — and the post-spawn
  poll loop keeps polling an accepted-but-silent successor to the deadline. A genuinely wedged
  pre-existing daemon still fails fast without spawning a successor (issue #235).
- `yoetz service run` against a live daemon holding the singleton lock reported
  `internal_error: the command could not be completed` (exit 70), telling one dogfood agent the
  service had died and could not be restarted while it was alive the whole time. The refusal now
  reports `service_already_running` with the holder pid (best-effort, stamped advisorily into the
  already-held lock file) at exit 20, every known `LifecycleError` reason maps to a truthful
  bounded message before the catch-all can degrade it, and `service status` distinguishes "no
  daemon — start one" from "a daemon is listening but not answering — do not run `service run`;
  it will refuse" (issue #237).
- The daemon could starve its own control plane for 10–20 minutes with zero diagnostics and then
  recover silently: the observation sweeper ran every store call — each a blocking cross-process
  flock plus a full workspace-document re-encode — synchronously on the event-loop thread, a
  corrupt pending row made every later RPC repeat the entire failed ledger recovery, and the
  sweeper task could run before the accept loop existed. Sweeper and coordinator store writes now
  run off-loop (making the 30-second sweep deadline enforceable for the first time), a failed
  recovery latches its verdict instead of replaying the ledger per call, the first sweep waits
  for the control accept loop to arm, and a watchdog thread that cannot be blocked by the loop
  reports `control_plane_saturation_entered`/`_persists`/`_cleared` with loop lag and in-flight
  counts to the diagnostics ring while the outage is happening (issue #238).
- A `publish_work` whose body failed bridge-local validation while the service was unreachable
  returned retryable `OPERATION_PENDING` prescribing a same-`request_id` retry that could never
  succeed, burying the deterministic `INVALID_REQUEST` the bridge already held — and a declared
  `dry_run: true`, which appends nothing, still paid the ~5-second recovery lookup. A dry-run
  validation failure now returns the field-pointed `INVALID_REQUEST` with no service round-trip;
  a real submission with the oracle unreachable keeps the validation result primary and states
  both known facts — the body failed locally, and the prior-operation check could not run —
  non-retryably, alongside `reason_code: operation_recovery_unavailable` (issue #239).
- Unknown payload keys on an event draft were reported as `invalid_type_or_value` at
  `/event_drafts/N/schema/name` — a field that was correct — with a hint reciting envelope
  requirements the request already satisfied, because the jsonschema oneOf scorer weighed
  discriminator failures from branches the caller never selected and the closed
  `extra_forbidden` token was destroyed on the jsonschema-to-pydantic boundary. The scorer now
  restricts itself to the branch the discriminator selected, `extra_forbidden` survives to
  `safe_details.reasons`, and the hint states what happened — "the payload carries N properties
  the `<family>` schema does not admit" — naming the admitted keys (frozen schema content) and a
  bounded count, never the caller-controlled key names. Frozen payload property names joined the
  safe-location allowlist with an import-time completeness gate, so a bad value under one now
  points at that key instead of collapsing to the payload root (issue #240).
- A standing `provider_not_ready` advice was injected 29 times byte-identical in one 24-minute
  session: the delivery gate keyed on a suppression identity that hashes the whole retained
  envelope stream, so it churned on every tool call while the rendered text never changed. Hook
  delivery is now deduplicated on a content identity over exactly what the agent receives —
  materialization, ledger history, and `observe status` keep the evidence-sensitive identity
  untouched, and the content identity excludes evidence references because some rules cite a
  rolling window over the envelope stream — and standing machine conditions the agent cannot act
  on (`connect_provider`)
  travel only on session-boundary events, falling through to the next actionable item on
  per-tool-call hooks rather than masking it (issue #241).
- Every workspace exec call paid 3.5–7.5 seconds of synchronous observe-hook overhead — process
  startup importing the full CLI graph (~325 ms per hook) and, dominating on a lived-in store,
  10–18 full serialize-and-fsync cycles of the workspace state file per hook. The hook entry now
  goes through a minimal shim with a lazy application package (~45 ms of imports), a hook pass
  batches its state mutations into single flushes fenced before any service RPC, an unchanged
  advice snapshot is no longer rewritten, and end-to-end hook timing is measured with a
  `hook_budget_exceeded` diagnostic. Measured end-to-end: ~0.55 s against a realistic store,
  from 1.7–2.5 s (issue #242).
- `yoetz state capture` could not capture Yoetz's own repository: the pre-hash safety walk
  counted every filesystem entry under the root — including the root `.git` object store and
  gitignore-excluded trees like a vendored `.venv` — against the 10,000-entry bound, 40× more
  than the population capture actually hashes, and the failure never said which bound tripped.
  The walk now skips the root `.git`'s internals (nested `.git` rejection and every per-entry
  safety check are preserved outside gitignore-excluded subtrees) and prunes fully-ignored
  subtrees using git's own exclusion
  semantics, and any file-count limit failure reports the bound that tripped with observed count
  and limit as integers in `limit_detail` (issue #243).
- A receipt reported `semantic_review_not_requested` for a task whose semantic review had been
  requested and refused. The stop-rules make a blocked review a coverage gap rather than a retry,
  so the agent falls back to `deterministic_only` — and that successor check replaced the recorded
  one wholesale, leaving a label that blamed the agent for never asking. A deterministic-only check
  now carries the earlier attempt's gap (`optional_semantic_review_blocked_by_policy`,
  `semantic_review_not_configured`, or `semantic_relevance_review_not_run`) forward alongside it,
  so the receipt still names the environment as the cause (issue #185).
- Prose that publishes cleanly could vanish from semantic review without a word. Publish accepts up
  to 8192 bytes per field while one case item carries 4096, so text in between was silently
  shortened — or, for a whole event payload, replaced by a bounded-omission marker whose `reason`
  read `not_selected`, the same token used for material the selection policy declined to send.
  The marker now says `over_case_item_limit`, and any case that had to shorten or replace admitted
  text raises `semantic_case_content_over_item_limit` in the check and receipt coverage (issue
  #177).
- A provider credential was stored without ever being tried, so a wrong or expired API key looked
  identical to a working one until a check failed much later with a reason that could not name
  authentication. Setting a credential now dispatches one minimal authenticated request — a fixed
  literal body with a one-token ceiling, no task content — through the same hardened one-attempt
  transport a real review uses. Only the provider refusing the credential (401/403) withdraws it
  and fails the ceremony with `secret_rejected`; an authenticated rate limit counts as working,
  and a timeout, unreachable host, outage, or unrecognized model keeps the credential, because
  none of those establish that the key is wrong.
- A confidential ceremony expired after 60 seconds, which is a keystroke timeout rather than a
  human one: provisioning a provider credential means leaving the terminal for the provider
  console to mint an API key, and a minute did not cover it. The single
  `CEREMONY_EXPIRY_SECONDS` binding/challenge expiry is now five minutes. Foreground-terminal
  presence, the one-shot challenge, and the service/vault generation binding are unchanged.
- First run's questions could only be answered or abandoned. `b` now goes back one question from
  the review-mode and project-trust steps, distinct from `Esc`, which still cancels and changes
  nothing. Back is offered only on questions: it is inert on the integration approval, which
  applies a change, and a searchable picker still treats `b` as a query character.
- Semantic review reported `transport_unavailable` for every unavailable provider class except
  rate-limit and quota, so a rejected API key, a forbidden binding, a provider outage, and a real
  socket failure were indistinguishable on every owner-facing surface. The exact
  `SemanticFailureClass` is recorded as a durable owner-only diagnostic when present;
  `unclassified` is recorded when no class is available. The public taxonomy is unchanged and the
  record carries no provider-controlled text.
- The terminal interface previewed the Codex integration on one MCP route and applied it on
  another, so on a fresh installation the approved preview digest never matched and first run's
  Codex connection failed as `preview_stale`. The route now travels on the approved plan, and the
  approval screen shows the exact serve command that route registers rather than a fixed string.
- Abandoning the provider step during first-run semantic setup left the policy route registered
  with no provider behind it and no setup marker written. It now offers a local-only finish that
  re-registers the strict route through the same preview and approval.
- Changing privacy posture after setup never looked at the Codex registration, so moving to
  assisted review with an older strict registration in place produced a correct policy and a Codex
  session where every check returned `blocked_by_policy` / `route_semantic_ceiling` with nothing
  connecting the two. `yoetz privacy setup` now names the mismatch and the command that fixes it,
  and the terminal interface reports the agent-route verdict as its own readiness line.
- Ordinary store-lock contention discarded hook events as `runtime_gate_unsafe`: the runtime-gate
  read serialized on the interprocess store lock, whose two-second acquisition timeout is routinely
  exceeded by a concurrent hook's batched local pass, and the guard treated the resulting
  `TimeoutError` as an unsafe gate — dropping the event before capture with no stderr line and no
  workspace gap, on a workspace every health surface reported as covered. The gate is now read
  lock-free through a single descriptor (it is an owner-only marker replaced only atomically), a
  contended read is reported as `runtime_gate_contended` and falls back to the missing-marker
  default instead of discarding the event, and a genuinely unsafe gate still fails closed but says
  so on stderr and records an `observation_storage_corrupt` coverage gap for the bound workspace so
  `observe status` can see the drop (issue #273).

- `hook_diagnostics` in `observe status` was an all-time tally with no recency, so a failure that
  was diagnosed and fixed days earlier read exactly like one happening now: one machine reported
  `runtime_gate_unsafe: 97` for two days after issue #273's fix ended it, and a `max_ms` of 60001
  from a single pre-fix pass alongside a healthy median of 789 ms. Every count is now paired with
  a count over the last `window_seconds`, every reason carries `first_seen`/`last_seen`, and the
  all-time `max_ms` carries the `max_ts` it happened at next to a `recent_max_ms` for the live
  window. Nothing is discarded — a stale failure is dated rather than dropped — and a row whose
  timestamp cannot be read is never counted as recent (issue #310).

- The `truncated_payload` coverage gap had note call sites and no resolution path, so one
  size-pressure eviction reported the workspace as currently losing observations forever. A save
  that sheds nothing and lands with a headroom margin under the state bound now clears the active
  flag; merely landing under the bound does not, because that is the state an eviction itself
  leaves behind. Renewed shedding reopens it, and `gap_history` keeps the sighting either way
  (issue #310).

- Hook timing rows attributed as little as 14% of the pass they measured, so `hook_budget_exceeded`
  could not distinguish real work from queueing. Time spent acquiring the interprocess store lock
  is now reported as `store_lock_wait` wherever in the pass it occurs, including on the timeout
  path; the two formerly unwindowed regions — workspace resolution and the consent probe before
  the store window, advice selection and the stdout write after the drain window — are reported as
  `resolve` and `deliver`; and whatever the partition still misses is reported as `unattributed`
  rather than left for a reader to derive. A contended pass that spent 707 of 711 ms queueing
  previously showed `store: 4` and nothing else (issues #310 and #311).

### Security

- Losing the session-event monitor no longer auto-re-opens the vault on the next ordinary call.
  Idle, session-lock, and suspend locks describe conditions the service can watch recover; monitor
  loss removes the capability that produces those events for the life of the process, so
  auto-re-ready made that lock momentary and left the service running with session-lock relock
  silently no longer applying. A monitor-loss lock now holds until a trusted unlock ceremony.
- This is the first public release; see [`SECURITY.md`](SECURITY.md) for how to report a
  vulnerability. There is no prior version to carry a security fix forward from.
