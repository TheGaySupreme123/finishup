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
yoetz start --request '{"request_id":"req_...", ...}' --json
yoetz check --input request.json --json
yoetz status --input - --json          # read the request from stdin
```

`--deadline-ms` bounds the call. Every operation is idempotent on its request identity: **a timeout
has an unknown outcome, never a known failure.** Reuse the same `request_id` to retry, or call
`status view=operation` with that `request_id` as a state lookup without reconstructing the
original body. A `complete` publish returns stored frontiers and accepted event ids; other states
report only what is honest for that state (`pending`/`quarantined`/`absent`/non-publish). An
`absent` check page may add an `admission` stage when Yoetz refused or is still admitting it.

Field-level shapes live in [`docs/INTERFACES.md`](../INTERFACES.md); the JSON Schemas under
[`schemas/`](../../schemas/) and the golden vectors under [`fixtures/`](../../fixtures/) are the
exact wire authority.

Before starting ordinary work, read the startup core once. Codex, Claude Code and Cursor then load
small guidance topics when needed: publication before recording work, review before checking,
receipt before closure, and recovery on an error. After compaction, reacquire the core and the
topic for the current operation. Anchored guidance links return only their named section.

If an MCP host drops schema examples or renders required fields as unknown, read the topic for
that operation, such as `yoetz://guidance/request-templates.md#publish-work-plan-plus-obligation`.
It contains a complete request body. Replace every illustrative identifier,
timestamp, frontier, digest, and content string before use; the resource is an authoring fallback,
not a second wire authority.

## What each one is for

### `start`
Opens a task, or attaches to an existing one, and issues a session and a distinct logical writer
identity. Create-vs-attach is explicit in the request — Yoetz does not guess. Agents pass your
request verbatim as `task_statement` (on the command line, `yoetz start --task-statement-file`);
it is recorded with the task and, when your privacy policy allows it, the AI-powered reviewer
reads it as the specification.

### `publish_work`
Records bounded, participant-published facts: plan, requested outcomes, obligations, claims,
actions, results, evidence. Publish material transitions — an assignment, a decision, a blocked
attempt, an independently useful result, a completion, a revision. Skip routine reads, searches,
formatting, and per-file mechanics.

A plan must make completion scope inspectable. Normally, list its obligation refs. If no
obligations apply, record `no_obligations_reason` as exactly `no_material_change`,
`single_atomic_change`, or `exploratory_scope_unknown`; the reason is invalid beside effective
obligation refs. A revision restates the declaration, so omission clears an earlier reason.

Read `status view=obligations` first and account for every exact `unattempted_items` value. Then set
`dry_run: true` to validate a batch and preview what would be accepted without appending. The
preview is not evidential and is not citable as a check, publication, or coverage source. Reuse the
same `request_id` for the real publish after the preview succeeds.

To correct a recorded claim, publish a fresh `claim_recorded/1.1.0` event. Put the prior effective
claim ids in `supersedes_claim_refs`, keep supporting evidence and successful results in
`supporting_refs`, and put every relevant partial or failed result in `limitation_refs`. That field
also accepts a relevant result whose outcome is unknown, so an unknown outcome still has somewhere
to be disclosed; naming it there does not call it a partial or a failure. Read
`status view=candidate_findings`, `history`, and `results` first, then dry-run the exact replacement;
the original claim remains immutable history.

A failed run that Yoetz observed through a host hook stops needing disclosure once a later observed
run of the same command passes before the claim. A later failed or partial rerun replaces the earlier
failure's disclosure duty with its own; a rerun with unknown outcome does not. An edit by itself never
proves that a failed check was repaired.
The receipt's limitations still name it once. For every observed run, `status view=results` shows
the tool, its occurrence number, a keyed identity of the command, and its exit status, so you can
find a run that is still red and name its result in `limitation_refs`. The command text itself is
never stored or shown.

Yoetz does not watch your workspace. What is published is what exists.

Authoring help for MCP: tool descriptions name `yoetz://guidance/publication-policy.md`; invalid
requests include nested field hints plus `yoetz://guidance/request-templates.md`.

### `check`
Runs the local policy packs over the recorded state and returns findings with an exact
coverage vector. `mode` selects how much:

| Mode | Use it when |
|---|---|
| Omitted | You intend to use the configured verification default. |
| `semantic_if_configured` | Review is known to be optional. Runs AI-powered review if it is available; degrades honestly if not. |
| `semantic_required` | The user, effective verification policy, or a named acceptance criterion requires independent AI-powered review. Preserve this choice for subsequent final checks. |
| `deterministic_only` | Explicitly local or structural checks, or a user-authorized deliberate no-egress choice. Disclose `semantic_review_not_requested` and any unmet required review. |

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
`yoetz check --await-observations`). Yoetz then waits up to about three seconds for this task's
observations that are still being delivered before it checks, and the result's
`observations_awaited` says whether they all arrived (`complete`), some were still on their way
(`bounded_timeout`, with how many), or the wait could not see them (`unavailable`). The wait never
fails the check; without the option nothing changes.

A local-only check can report “no issue detected within deterministic coverage” while preserving
the limitation that AI-powered review did not run. Open obligations, missing requested attempts,
live failures and actionable findings prevent that result. Follow the overall next step: supply
missing input when it names something you can provide; disclose standing limitations when there is
no further agent action. The finding checklist describes findings only.

#### Approved workspace checks

`check` reads the ledger; it does not run your test suite. A project may declare fixed commands
it is willing to have run on its behalf in `.yoetz/checks.toml` — an exact argv, a timeout, and
whether network is requested. Those bytes grant nothing by themselves. Trust is given per
workspace to one exact policy digest by a local human (first-run setup offers it for the policy
present at that time), and revoked the same way; if the file changes afterwards, the old trust no
longer matches and nothing runs until the new digest is trusted.

```text
yoetz observe checks preview                          # policy digest and each proposed argv, without activating
yoetz observe checks trust --policy-digest <digest>   # trust only the exact digest currently present
yoetz observe checks status                           # trusted, untrusted, or not_configured, and which checks may run
yoetz observe checks revoke                           # withdraw this workspace's check-policy trust
yoetz observe checks run                              # run the trusted argv under the enforcing sandbox
```

`run` refuses an untrusted digest and records a coverage gap instead. A check that asks for
network is not run; it is reported as unsupported. Network denial is enforced by the platform
sandbox — `sandbox-exec` on macOS, bubblewrap (`bwrap`) on Linux and WSL — and `status` reports
that sandbox once under `sandbox` (`ready`, or `unavailable` with the reason and the install
step), so a missing `bwrap` is named before a check is approved rather than per rejected run. Each result carries a status and outcome, the
output digest and byte count, and whether it is current: a run is bound to the working tree and
diff state captured before and after it, so a result whose tree moved while it ran is marked not
current rather than reusable. When no enforcing sandbox is available the outcome says so.

Approved checks are optional. In a workspace without `.yoetz/checks.toml`, `status` reports
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
it is final, is not reviewed again, and keeps the receipt from reading clean; use it only if you
truly will not or cannot do the work. `self_verified` is for a finding you repaired that Yoetz still
cannot prove after a later check because of its own limits: say how you verified the repair in
`reason` and cite at least one recorded evidence or result id in `evidence_refs`. It is final, is
not your work any more, and keeps the receipt at best `insufficient_coverage`; Yoetz refuses it
with `finding_not_rechecked` before a later check, or `finding_not_proof_limited` while that check
still sees the issue. A finding that is already `verified_resolved`, `acknowledged_not_done`,
`self_verified`, `rejection_accepted` or `disputed_after_rebuttal` (the review repeated a finding
you rejected with a reason without citing anything newer; disclosed, not your work) is final: `respond` records nothing and answers
`finding_terminal`. `duplicate_of` is only for a genuine restatement of the same issue (same origin
and kind) as an earlier finding you answered: name it in `duplicate_of_finding_id`. Linking never
resolves the new finding; it stays open until its own check proves it absent, needs no separate
answer, and inherits only the earlier finding's not-done or self-verified answer. A later check
that raises it again breaks the link, and then it needs its own answer.

### `status`
Reads current state — use it after a resume, a compaction, a handoff, or any uncertainty about what
is already done. `view=candidate_findings` is an advisory read: it creates no verdict, no IDs, no
receipt, and no event. An empty candidate list means only that no rule fired in that read; it is not
a check and cannot be cited as one. After any ambiguous write, prefer `view=operation` with
`filter.operation_request_id` set to the write's `request_id`: it looks up that operation's state
within the authenticated task without requiring a byte-identical replay body. This survives a
same-task attach that rotates the active session and writer, but never crosses into another task
bundle. Stored outcome, frontiers, and accepted event ids are present only when the operation is a
complete `publish_work`; other states omit them rather than invent detail.
`view=obligations` includes each requested item and its exact unattempted subset, subject to the
existing obligation-text projection policy. `view=results` resolves `res_` ids to bounded structural
facts: source event, payload availability, outcome, linked action, and linked evidence ids.

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
after it ("The receipt will read ...").

`closure_readiness.state` tells you whether anything is left to do. `action_required` lists the
work in `agent_actionable`: open obligations, unanswered findings, an unresolved finding you can
still repair, a rejected finding awaiting a ruling (`finding_rejection_awaiting_ruling`: run
`check` so the reviewer rules), a missing or out-of-date check, or a gap you can repair such as
`completion_plan_not_claimed`. `ready_with_limitations` means nothing further to do: every
remaining condition is either a `standing_limitations` code that this assistant, capture profile
or privacy policy always has (for example `host_outcome_unavailable` or, when AI-powered review
is off, `semantic_review_not_requested`) or an item in `acknowledged_not_done` (obligations and
findings you recorded as not done). Request the receipt; another check of unchanged state changes
nothing. The receipt still lists every limitation, and its conclusion follows the prediction: a
local-only check with limitations is still `insufficient_coverage`, and an acknowledged
requirement keeps the conclusion at `unresolved_findings_remain`. `rechecks` lists the questions
a Stop will ask you once to re-read (the acceptance criteria of resolved obligations, obligations
you recorded as not done, a blocker you recorded); the status text announces them. `ready` means
nothing remains at all, and `unknown` means read status again once it is readable.

Local checks also report facts about the task's own work: a planned verification command (an
obligation's requested command) that was not matched to an observed run, failed on its latest
run, or last ran before your latest edit; an edit to the work after your last test, lint,
typecheck or build run stops you once at Stop. Edits under a temporary directory outside your workspace and a
Yoetz receipt you saved never count as edits for these facts. A run matches when it is the planned command or
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
`yoetz-blocker:<authority|consent|credential|dependency_unavailable>`. A Yoetz limit (something
Yoetz cannot show or prove) is never a blocker: verify the work yourself and respond
`self_verified` instead. Yoetz cannot verify a blocker either, so the first one is only claimed:
the `publish_work` result challenges it (data the task says is recoverable, a failing test, or a
result that only looks infeasible is not a blocker, so continue the work instead), and the
obligation stays open work (`obligation_blocker_unconfirmed`) until you answer that challenge
as it describes; a confirmed blocker then reads as a disclosed limitation. A blocker that
names only finished obligations has no effect. The next stop may ask you once to confirm a
blocker, and the closing review checks it against the task once and challenges it when the
blocked obligation is the task's main deliverable.

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

A check that Yoetz refused before admitting it is different: nothing was recorded under its
`request_id`, the error says so with the `check_admission_same_identity` continuation and a
`retry_after_ms` wait, and `status view=operation` reads `absent` with an `admission` stage naming
why (a capture handoff still being delivered, the same request already being admitted, a lost race,
or an import in progress). Wait that long and replay the exact same check, at most three times; if it
is still refused, report the check as not admitted rather than switching mode or minting a new
request.

The agent-facing version of this loop, including when *not* to use Yoetz at all, is
[`guidance/workflow.md`](../../guidance/workflow.md).
