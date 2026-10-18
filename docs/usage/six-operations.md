# The six operations

`start`, `publish_work`, `check`, `respond`, `status`, `receipt`. Identical request and result
contracts on the CLI and over MCP — same names, same fields, same errors
([ADR-002](../adr/ADR-002-canonical-protocol.md),
[ADR-010](../adr/ADR-010-harness-integration-port.md)).

Everything else the CLI offers — `setup`, `recommend`, `provider`, `privacy`, `consent`
(alias `elevated-bootstrap`), `integrate`, `hooks`, `observe`, `import`, `review`, `backup`,
`restore`, `migrate`, `version`, `service`, `mcp`, `state`, `menu` — is a bounded support surface,
not a seventh operation.

## Calling them

Each takes a strict JSON request and returns a canonical JSON result:

```text
finishup start --request '{"request_id":"req_...", ...}' --json
finishup check --input request.json --json
finishup status --input - --json          # read the request from stdin
```

`--deadline-ms` bounds the call. Every operation is idempotent on its request identity: **a timeout
has an unknown outcome, never a known failure.** Reuse the same `request_id` to retry, or call
`status view=operation` with that `request_id` as a state lookup without reconstructing the
original body. A `complete` publish returns stored frontiers and accepted event ids; other states
report only what is honest for that state (`pending`/`quarantined`/`absent`/non-publish). An
`absent` check page may add an `admission` stage when FinishUP refused or is still admitting it.

Field-level shapes live in [`docs/INTERFACES.md`](../INTERFACES.md); the JSON Schemas under
[`schemas/`](../../schemas/) and the golden vectors under [`fixtures/`](../../fixtures/) are the
exact wire authority.

Before starting ordinary work, read the startup core once. It is a compact operating card, under
8 KB, and it is enough for ordinary work: Codex, Claude Code and Cursor read the larger pages and
the small topics only when a result, an error or a continuation names one, or when unsure. After
compaction, reacquire the core and the topic for the current operation. Anchored guidance links
return only their named section. An anchor that is not listed but names exactly one section of
that document (the section heading written another way, an anchor the text places under it, or
words only its anchor contains) reads that section, and the result names its listed link; an
anchor that could mean several sections is refused with the document's listed anchors.

If an MCP host drops schema examples or renders required fields as unknown, read
`finishup://guidance/request-templates.md#publish-shapes` for ordinary publish, or the topic for
that one operation. It contains a complete request body. Replace every illustrative identifier,
timestamp, frontier, digest, and content string before use; the resource is an authoring fallback,
not a second wire authority.

## What each one is for

### `start`
Opens a task, or attaches to an existing one, and issues a session and a distinct logical writer
identity. Create-vs-attach is explicit in the request — FinishUP does not guess. Agents pass your
request verbatim as `task_statement` (on the command line, `finishup start --task-statement-file`);
it is recorded with the task and, when your privacy policy allows it, the AI-powered reviewer
reads it as the specification.

### `publish_work`
Records bounded, participant-published facts: plan, requested outcomes, obligations, claims,
actions, results, evidence. Publish material transitions — an assignment, a decision, a blocked
attempt, an independently useful result, a completion, a revision. Skip routine reads, searches,
formatting, and per-file mechanics.

Write each fact once. A publish needs only your session and writer, your actor and client, and
events made of a `schema` and a `payload`. FinishUP fills the rest when you leave it out. It gives
each call its own request id and names it in every answer, including errors (the command line
prints it before sending). If an answer never arrived, retry by sending that request id: FinishUP
returns the stored result instead of recording twice. Sending the same request again without the
id is a new record (switching review back on, for example). Right after the same call, FinishUP
asks you to choose instead, naming the earlier id. If you need a retry that holds even after FinishUP
restarts, send your own request id. It also fills each event id, the
event time (FinishUP's clock, never your claim, and marked as such in history), empty reference
lists and the reference lists that repeat the payload's, and the frontier: the one it reads when it
takes the request, so a change another participant makes meanwhile is refused. Reference lists are
put in canonical order for you; text lists are kept exactly as you wrote them. The result's
`server_filled` names every value FinishUP filled, and so does the operation record. Send a value
when you need it, for example the frontier you last read when what you publish depends on it.

A plan must make completion scope inspectable. Normally, list its obligation refs. If no
obligations apply, record `no_obligations_reason` as exactly `no_material_change`,
`single_atomic_change`, or `exploratory_scope_unknown`; the reason is invalid beside effective
obligation refs. A revision restates the declaration, so omission clears an earlier reason.

Reading `status` or previewing before a publish is optional: a publish that fails validation
appends nothing and names what stopped it, not every error (for events, the first rejected event
and its field), so fix that and send it again; one that succeeds returns the new frontier and the
accepted ids. When an id is the wrong kind, the message names the field, the kind it expects, the
kind that was sent when that kind is one FinishUP already uses, and a shape-valid example. The
rest of the sent value is not repeated. Before resolving an obligation, account for every
requested item that has no attempt yet. When unsure about a batch, set `dry_run: true` to
validate it and preview what would be accepted without appending. The preview is not evidential
and is not citable as a check,
publication, or coverage source. For the real publish, send the same request without `dry_run`
(and with your own `request_id`, if you set one).

To correct a recorded claim, publish a fresh `claim_recorded/1.1.0` event. Put the prior effective
claim ids in `supersedes_claim_refs`, keep supporting evidence and successful results in
`supporting_refs`, and put every relevant partial or failed result in `limitation_refs`. That field
also accepts a relevant result whose outcome is unknown, so an unknown outcome still has somewhere
to be disclosed; naming it there does not call it a partial or a failure. Read
`status view=candidate_findings`, `history`, and `results` first, then dry-run the exact replacement;
the original claim remains immutable history.

A failed run that FinishUP observed through a host hook stops needing disclosure once a later observed
run of the same command passes before the claim. A later failed or partial rerun replaces the earlier
failure's disclosure duty with its own; a rerun with unknown outcome does not. An edit by itself never
proves that a failed check was repaired.
The receipt's limitations still name it once. For every observed run, `status view=results` shows
the tool, its occurrence number, a keyed identity of the command, and its exit status, so you can
find a run that is still red and name its result in `limitation_refs`. The command text itself is
never stored or shown.

FinishUP does not watch your workspace. What is published is what exists.

To turn on AI-powered review for the current task, publish one `decision_recorded` event at
version `1.1.0` with `review_mode: "ai_powered"` (and `review_mode: "local"` to turn it back off).
Its `statement` and `rationale` say why; its `authority` is the agent's own actor id. Later checks
that omit `mode` then run with AI-powered review, within what your privacy policy allows; other
tasks are unaffected. Version `1.0.0` refuses the field.

Authoring help for MCP: tool descriptions name `finishup://guidance/publication-policy.md`; invalid
requests include nested field hints plus `finishup://guidance/request-templates.md`.

### `check`
Runs the local policy packs over the recorded state and returns findings with an exact
coverage vector. `mode` selects how much:

| Mode | Use it when |
|---|---|
| Omitted | Run in the task's review mode: local checks only until the task turns on AI-powered review, then AI-powered review. Where the task's mode is not set, the configured verification default. |
| `semantic_if_configured` | Review is known to be optional. Runs AI-powered review if it is available; degrades honestly if not. |
| `semantic_required` | The user, effective verification policy, or a named acceptance criterion requires independent AI-powered review. Preserve this choice for subsequent final checks. |
| `deterministic_only` | Explicitly local or structural checks, or a user-authorized deliberate no-egress choice. Where review is required, the check records `semantic_review_not_requested`: disclose it and the unmet required review. |
| `inspect` | You need the picture, not a verdict. Reads only: records nothing, returns no findings, runs no review. See below. |

The configured `verification.semantic` default applies only when `mode` is omitted. An explicit
mode is honored by the runtime; the default is not a persistent task-level enforcement rule.
Do not choose a weaker mode to shorten a repair check. Qualitative work alone does not make
optional review mandatory, and none of these modes widens durable privacy authority.

`semantic_required` never erases local-check truth. If the provider is absent, denied by policy,
refuses, times out, or returns stale or invalid output, you get the local findings back with
verdict `incomplete_check`, an explicit reason, and no AI-powered findings.

An unavailable required review remains an unmet requirement. Report completed implementation and
tests separately; do not silently replace required AI-powered review with local-check coverage.
Optional terminal review gaps may be disclosed while continuing the task. Pending approvals must
follow their exact continuation.

Every completed check includes compact totals for obligations, attempted requested items, observed
commands and outstanding failures, evidence strength, and findings. The totals describe the recorded
work; an attempt or a linked evidence item does not establish that a requirement passed. Missing
scope or capture stays explicit. Test-edit counters distinguish changes to existing tests from new
tests, and disclose when the task-start baseline was unavailable.

Commands you just ran reach the record through your host's hooks a moment later. To check them
without polling `status`, add `"await_observations": true` to the check request (or run
`finishup check --await-observations`). FinishUP then waits up to about three seconds for this task's
observations that are still being delivered before it checks, and the result's
`observations_awaited` says whether they all arrived (`complete`), some were still on their way
(`bounded_timeout`, with how many), or the wait could not see them (`unavailable`). On Codex the
wait also delivers session-log entries FinishUP was still holding to match with their hook reports,
marked as unmatched, so they count before the check rather than after it. The wait never fails the
check; without the option nothing changes.

#### Inspecting what is left

`"mode": "inspect"` asks FinishUP to look at its own record instead of checking it. It is a read like
`status`: nothing is recorded, no finding is returned or created, no AI-powered review runs and
nothing leaves your machine, so a lost answer is fixed by asking again. Your agent host still sees
a `check` call and approves it as it approves any check (host admission of `check` covers it); if
the host holds or refuses an inspection, nothing is waiting in FinishUP and your agent reads `status`
instead. One call answers three questions:

- **What is left to close, and whose move it is.** The same readiness, predicted receipt
  conclusion and gap split `status` shows (your gaps beside the limits FinishUP itself carries), then
  every unresolved obligation and finding with its class and reason. An open obligation names what
  it lacks: requested items with no recorded attempt (by position), no resolution evidence, an
  asserted command whose observed run differs, an unconfirmed blocker (yours), or an asserted
  command run your host's hooks never linked (FinishUP's own observation gap).
- **What the hooks observed since the last check.** Each observed command or edit after the last
  check, with its tool, outcome, exit status and write class. FinishUP's own calls and host
  bookkeeping are left out. Edits are recorded by write class, never by path.
- **Whether the evidence matches what was declared.** For each obligation that cites resolution
  evidence: which recorded action each piece of evidence came from (observed by a hook, asserted by
  the agent, or untraceable), and whether that action names a declared deliverable or the
  requested command. `evidence_off_declared_items` means the evidence came from somewhere the
  obligation never declared, for example a benchmark run that bypassed the service's declared
  supervisor. FinishUP compares only what it recorded; it reads no working directory, environment or
  service configuration.

Omit `scope`, `max_findings`, `policy_packs` and `final_review` (they are refused beside
`inspect`); `await_observations` works as for any check.

A local-only check can report “no issue detected within local coverage” while preserving
the limitation that AI-powered review did not run. Open obligations, missing requested attempts,
live failures and actionable findings prevent that result. Follow the overall next step: supply
missing input when it names something you can provide; disclose standing limitations when there is
no further agent action. The finding checklist describes findings only.

#### Approved workspace checks

`check` reads the ledger; it does not run your test suite. A project may declare fixed commands
it is willing to have run on its behalf in `.finishup/checks.toml` — an exact argv, a timeout, and
whether network is requested. Those bytes grant nothing by themselves. Trust is given per
workspace to one exact policy digest by a local human (first-run setup offers it for the policy
present at that time), and revoked the same way; if the file changes afterwards, the old trust no
longer matches and nothing runs until the new digest is trusted.

```text
finishup observe checks preview                          # policy digest and each proposed argv, without activating
finishup observe checks trust --policy-digest <digest>   # trust only the exact digest currently present
finishup observe checks status                           # trusted, untrusted, or not_configured, and which checks may run
finishup observe checks revoke                           # withdraw this workspace's check-policy trust
finishup observe checks run                              # run the trusted argv under the enforcing sandbox
```

`run` refuses an untrusted digest and records a coverage gap instead. A check that asks for
network is not run; it is reported as unsupported. Network denial is enforced by the platform
sandbox — `sandbox-exec` on macOS, bubblewrap (`bwrap`) on Linux and WSL — and `status` reports
that sandbox once under `sandbox` (`ready`, or `unavailable` with the reason and the install
step), so a missing `bwrap` is named before a check is approved rather than per rejected run. Each result carries a status and outcome, the
output digest and byte count, and whether it is current: a run is bound to the working tree and
diff state captured before and after it, so a result whose tree moved while it ran is marked not
current rather than reusable. When no enforcing sandbox is available the outcome says so.

Approved checks are optional. In a workspace without `.finishup/checks.toml`, `status` reports
`state: not_configured` and exits successfully; `preview`, `trust`, and `run` stop with
`policy_not_configured`. A file that exists but cannot be read or parsed reports `invalid_policy`.
Other local faults (for example an unreadable workspace) report `unavailable`. Configuring or
trusting a policy is the owner's choice and no finding asks an agent for it, so neither state is a
reason for an agent to stop; a limit it leaves unproven stays disclosed in the receipt.

### `respond`
Answers a finding: accept and act, supply evidence, revise the claim, dispute with evidence, or
state an unresolved limitation. **A response does not erase a finding**, and no disposition resolves
one: an actionable finding keeps the receipt conclusion at `unresolved_findings_remain` until a
later qualifying check finds the same issue absent from the repaired record, whichever disposition
is recorded. The check must cover the finding, run its owning pack to completion with nothing
suppressed, and read the proof inputs. For a local finding with readable original coverage,
case-wide `captured_object_unavailable`, `content_unselected`, `host_outcome_unavailable`, and
`unpaired_event` limits remain receipt gaps but do not veto clean structured-ledger proof; they
never relax AI-powered review proof. A resolved finding stays visible as history. Recheck after any
material edit, evidence change, or plan change. A readable response to a finding returned by the
current check does not require a recheck, nor does acknowledging an observation-authored
non-actionable finding or publishing `work_closed`; a redacted or unreadable response does.
`acknowledged_not_done` records, with a required reason, that you will not do what a finding asks;
it is not reviewed again and keeps the receipt from reading clean; use it only if you truly will not
or cannot do the work. It is not a one-way door: respond `reopened` with a reason to take it back, or
just do the work and run `check`, and a check that tests the work after your answer and finds the
issue absent resolves the finding. When the reviewer asks you to state a limit (a requirement only
a hidden evaluator or something you cannot obtain could settle), that finding is a limitation
request, not work: one reasoned `acknowledged` (or a `finishup-verification-limit:<obligation id>`
decision) discloses it, with no repair attempt required, and the receipt lists the disclosed limit
instead of reading clean. Never empty or withdraw a working deliverable over a finding. `self_verified` is for a finding you repaired that FinishUP still
cannot prove after a later check because of its own limits: say how you verified the repair in
`reason` and cite at least one recorded evidence or result id in `evidence_refs`. It is final, is
not your work any more, and keeps the receipt at best `insufficient_coverage`; FinishUP refuses it
with `finding_not_rechecked` before a later check, or `finding_not_proof_limited` while that check
still sees the issue. A finding that is already `verified_resolved`, `acknowledged_not_done`,
`self_verified`, `rejection_accepted` or `disputed_after_rebuttal` (the review repeated a finding
you rejected with a reason without citing anything newer; disclosed, not your work) takes no further
answer: `respond` records nothing and answers `finding_terminal`, naming the state and the way out
(`reopened` for `acknowledged_not_done`; a later check that finds the issue absent for
`acknowledged_not_done` and `self_verified`). The result of a `respond` includes `closure_after`, the
state your answer produced. `duplicate_of` is only for a genuine restatement of the same issue (same origin
and kind) as an earlier finding you answered: name it in `duplicate_of_finding_id`. Linking never
resolves the new finding; it stays open until its own check proves it absent, needs no separate
answer, and inherits only the earlier finding's not-done or self-verified answer. A later check
that raises it again breaks the link, and then it needs its own answer.

### `status`
Reads current state — use it after a resume, a compaction, a handoff, or any uncertainty about what
is already done. An agent's read is brief by default: one frontier, the page and the closure state
(the compact view keeps the full closure readiness and coverage). Send `detail: full` for the
complete body. `limit` defaults to 20. `view=results` accepts a filter on results recorded after a
ledger sequence, by an actor, or by you. `view=candidate_findings` is an advisory read: it creates no verdict, no IDs, no
receipt, and no event. An empty candidate list means only that no rule fired in that read; it is not
a check and cannot be cited as one. After any ambiguous write, prefer `view=operation` with
`filter.operation_request_id` set to the write's `request_id`: it looks up that operation's state
within the authenticated task without requiring a byte-identical replay body. This survives a
same-task attach that rotates the active session and writer, but never crosses into another task
bundle. Stored outcome, frontiers, and accepted event ids are present only when the operation is a
complete `publish_work`; other states omit them rather than invent detail.
`view=obligations` includes each requested item and its exact unattempted subset, subject to the
existing obligation-text projection policy, and its text states how to resolve an obligation:
publish it again with every field as recorded, `status` `resolved`, and `resolution_evidence_refs`
naming the evidence or result ids that show the work done. `view=results` resolves `res_` ids to bounded structural
facts: source event, payload availability, outcome, linked action, and linked evidence ids.

Every view also carries the task's `review_mode` when the service can read your setting: `mode`
(what the next check that omits `mode` runs in, `local` or `ai_powered`), `requested`, your
`setting`, whether AI-powered review is set up (`ai_review_available`), the latest switch's event
id and sequence, and, for a local task, `local_reason` (`conversation_default`,
`switched_to_local`, `owner_local_only`, `route_local_only`, `ai_review_not_set_up`). It is read at
the current head, not at `at_frontier`.

Before completion, read `declared_obligation_count`, `no_obligations_reason`, and
`closure_readiness`. An empty readable plan without a typed reason is blocked by
`no_obligations_declared`; a typed reason clears that readiness blocker but remains visible. If the
plan scope is unreadable, readiness is unknown rather than zero. Read the finding counters
separately: `unanswered_finding_count` is response work still to do (observation-authored,
non-actionable findings never count there), while `finding_counts` says where every current
finding stands. `to_do` is work you can still do (it includes `awaiting_ruling`, findings you
rejected with a reason that only a reviewer's ruling can settle; the next move for those is
`check`); `unmet` are requirements you acknowledged as not done; `disclosed` are final items the
receipt will disclose (a repair you verified yourself, a limit you stated, a bookkeeping finding
you acknowledged); `to_disclose` are limits a reviewer asked you to state and that you have not
yet stated (answer once with `acknowledged`; it is not work). `receipt_blocking_finding_count`
is `to_do` plus `unmet`: the findings that keep a receipt from concluding
`no_unresolved_deterministic_findings` even after every response; only a later qualifying check
of the repaired record shrinks `to_do`. Accordingly, `findings_unanswered` is answered;
`receipt_findings_unresolved` is repaired and rechecked once, and should not trigger another
response loop. After that recheck, read the finding's `resolved` value. If the issue re-fires,
or it does not re-fire but remains `resolved=false` because the check did not qualify, stop
rechecking unchanged state, request the bounded receipt, and disclose the current finding and
limiting coverage.

`closure_readiness.predicted_receipt` is the conclusion a receipt requested at this frontier would
carry, with the reasons (`reasons`, each with a code, a count and at most three ids). Status,
the check's next step and the receipt use one function, so the label you read here is the label the
receipt gets. "Nothing further to do" never means the receipt will be clean: read the sentence
after it ("The receipt will read ..."). `basis_frontier` is the frontier that conclusion was read
at. A current status read that is interrupted by new work reads the prediction again at the
newer frontier and names it there. A status read you pinned with `at_frontier`, or continued with
a cursor, stays on that frontier; if it is no longer a safe basis, the prediction is left out.

`closure_readiness.state` tells you whether anything is left to do. `action_required` lists the
work in `agent_actionable`: open obligations, unanswered findings, an unresolved finding you can
still repair, a rejected finding awaiting a ruling (`finding_rejection_awaiting_ruling`: run
`check` so the reviewer rules), a missing or out-of-date check, or a gap you can repair such as
`completion_plan_not_claimed`. `ready_with_limitations` means nothing further to do: every
remaining condition is either a `standing_limitations` code that this assistant, capture profile
or privacy policy always has (for example `host_outcome_unavailable`) or an item in
`acknowledged_not_done` (obligations and
findings you recorded as not done). Request the receipt; another check of unchanged state changes
nothing. The receipt still lists every limitation, and its conclusion follows the prediction: a
local-only check with limitations is still `insufficient_coverage`, and an acknowledged
requirement keeps the conclusion at `unresolved_findings_remain`. `rechecks` lists the questions
a Stop will ask you once to re-read (obligations you recorded as not done, a blocker you recorded,
findings you acknowledged that the review says the task requires); the status text announces
them. `acceptance_risk` lists resolved obligations whose acceptance FinishUP could not tie to an
observed verification run or a recorded verification limit, because a requested item was never
attempted or their evidence is unlinked or only your own assertion. The status text names them
once. This is never a Stop question: it never blocks a Stop on its own, met work needs no action,
and the receipt records it as a coverage limit (`insufficient_coverage`). If an output does not
meet its acceptance criteria, republish that obligation `acknowledged_not_done` with the reason;
that honest downgrade is not questioned again at Stop. A `finishup-acceptance:` line in your final
answer is not read.
`ready` means
nothing remains at all, and `unknown` means read status again once it is readable.

Local checks also report facts about the task's own work: a planned verification command (an
obligation's requested command) that was not matched to an observed run, failed on its latest
run, or last ran before your latest edit; an edit to the work after your last test, lint,
typecheck or build run stops you once at Stop. Edits under a temporary directory outside your workspace and a
FinishUP receipt you saved never count as edits for these facts. A run matches when it is the planned command or
contains it as one part, such as `cd /app && pytest -q && git diff --check`, `pytest -q > log
2>&1`, `time pytest -q`, or a line of a `bash <<'EOF'` script; when the run combined other
commands, its outcome counts for the planned command only if an `&&` chain succeeded. A requested
command with a `<placeholder>` is refused when you publish it: write the concrete command; a requested output file that is missing (a
unresolved finding, even if an action named it) or excluded from Git; one you recorded
editing (an `edit` action naming it) that is still unchanged or lies outside the repository; and
installs or writes that went outside the task's workspace. If you stop while open obligations, an
unresolved finding, or one of those planned-verification or excluded-output facts remains,
the stop is continued once with the list. When something outside your control blocks an
obligation (authority, consent, credentials, or a dependency you cannot obtain), record a
`decision_recorded` naming it in `affected_obligation_ids` with the statement line
`finishup-blocker:<authority|consent|credential|dependency_unavailable>`. A FinishUP limit (something
FinishUP cannot show or prove) is never a blocker: verify the work yourself and respond
`self_verified` instead. FinishUP cannot verify a blocker either, so the first one is only claimed:
the `publish_work` result challenges it (data the task says is recoverable, a failing test, or a
result that only looks infeasible is not a blocker, so continue the work instead), and the
obligation stays open work (`obligation_blocker_unconfirmed`) until you answer that challenge
as it describes; a confirmed blocker then reads as a disclosed limitation. A blocker that
names only finished obligations has no effect. The next stop may ask you once to confirm a
blocker, and the closing review checks it against the task once and challenges it when the
blocked obligation is the task's main deliverable.

Beyond the work `agent_actionable` lists, a Stop asks only what `closure_readiness.rechecks` named before you stopped: the acceptance
criteria of the obligations you resolved, an obligation you recorded as not done, a blocker you
recorded, or a finding you answered as not done that the review says the task requires. A blocker,
an acknowledgement and a premise are each asked once, so `ready_with_limitations` is never followed
by a surprise from those. Reading the acceptance
criteria costs one extra turn for that set of resolved obligations, and again only after the work,
its verification, or the review mode changes: if your output does not meet
them, publish that obligation again as `acknowledged_not_done` with the reason; if they can only be
checked outside this environment (a hidden verifier, a withheld artifact) and you did the work, keep
it resolved and record a decision with the line `finishup-verification-limit:<obligation id>`. An
acknowledgement you publish in answer to that question is not challenged again. A finding you
rejected that waits for the reviewer's ruling (`finding_rejection_awaiting_ruling`) is answered by
running `check` with `final_review: true`, never by acknowledging it. If you cannot finish a
deliverable, keep the working version: acknowledging an obligation never requires emptying or
removing its file, and a deliverable that held content and is now empty or gone is named at the
next Stop once, even when that Stop was already continued this turn.

### `receipt`
Projects the honest summary of what was checked, at what coverage, and what remains open. Formats:
`json`, `markdown`, `text` — all three project under the default policy. If a stricter owner policy
blocks `json`, re-request `markdown` or `text`.

See [Receipts and coverage](receipts-and-coverage.md) for how to read one.

## A whole task, in order

1. `start` — open or attach.
2. `publish_work` — plan, outcomes, acceptance evidence, assignments.
3. `publish_work` — material transitions as the work happens.
4. `status` — after any resume or uncertainty.
5. `publish_work` — the intended completion claim plus current evidence.
6. `check` — with a deliberately chosen mode.
7. `respond` — to each unanswered finding before the final check, then only to that check's
   findings that are still unanswered.
8. `check` — again, after any material change.
9. `receipt` — then publish `work_closed` when the work is complete, and keep the final answer no
   stronger than its weakest coverage, freshness, unresolved findings, and limitations.

## How often to call each one

| Operation | How often |
| --- | --- |
| `start` | Once per task, before substantive work. In a new session, read guidance and discover tool schemas first, then call `start` before other workflow operations. On failure, follow exact continuations and same-request recovery, including a named one-time repair; if startup remains blocked without an applicable recovery path, ask for intro and guidance. On resume, attach to the existing task instead of starting a second one. |
| `publish_work` | One batch per material transition, roughly one to eight events. A normal session is a handful of batches, never one per file, tool call, or message. |
| `status` | After resume, compaction, or delegate handoff, and before any completion claim. Not between routine tool calls. |
| `check` | After publishing the completion claim and its evidence, and again after any material edit or new evidence. A readable response to a finding returned by that check needs no recheck, nor does acknowledging an observation-authored non-actionable finding or publishing `work_closed`; a redacted or unreadable response does. A check with no new events since the last one adds nothing. |
| `respond` | Once per finding; `finding_frontier` may be any frontier at or after the finding's record, such as the current status frontier. |
| `receipt` | Once at the end, and again only if material state changed after the previous receipt. |

Under-publishing hides the work; over-publishing buries it. Reading, searching, formatting,
regenerating derived files, repeating a status read, and republishing unchanged state are not
publishable transitions.

### When to stop retrying

AI-powered review that does not succeed is a coverage gap, not a retry problem. `not_configured`,
`blocked_by_policy`, and `human_denied` will not change without owner action. `unavailable` and
`timeout` are retried inside a job, so by the time you see one that job already spent its attempt
budget. An `invalid` answer with reason `response_content_invalid` (incomplete or overlong provider
output) may spend exactly one in-job repair retry when the configured profile allows a retry, so a
reported one has already used it; `refused`, `failed`, and every other `invalid` reason are not
retried in-job at all. When a
second job in one session again returns no judgment, switch to `deterministic_only`, disclose the
gap with the recorded status and reason, and do not spend a third job on the same binding.

On `OPERATION_PENDING`, read `status` with
`view=operation` once and replay the same `request_id` once; if it is still pending, continue with
a new local-only request and say the earlier operation never reached a terminal result.

A check that FinishUP refused before admitting it is different: nothing was recorded under its
`request_id`, the error says so with the `check_admission_same_identity` continuation and a
`retry_after_ms` wait, and `status view=operation` reads `absent` with an `admission` stage naming
why (a capture handoff still being delivered, the same request already being admitted, a lost race,
or an import in progress). Wait that long and replay the exact same check, at most three times; if it
is still refused, report the check as not admitted rather than switching mode or minting a new
request.

The agent-facing version of this loop, including when *not* to use FinishUP at all, is
[`guidance/workflow.md`](../../guidance/workflow.md).
