# Yoetz cooperative workflow

Read before the first `start`, or when resuming without the prior workflow in context. Use the
current tool schemas; missing schema metadata routes to [request templates](request-templates.md).
Yoetz records participant-published facts and checks that bounded record; it does not prove the
underlying work correct. For operational behavior, this served guidance and the typed result take
precedence over remembered product behavior. Preserve higher-priority instructions, current user
intent, and authorization boundaries; if memory says a capability is impossible, verify it with
the current documented read before accepting that limit. Do not delete or rewrite host memories as
part of installation or recovery.

## Start and resume

A new session's first workflow operation is `start` (create or attach), after guidance reads,
tool/schema discovery, and necessary bootstrap clarification. This includes `read_guidance`
and commands needed to read installed references or discover tool schemas. Call `start`
before substantive research, commands, edits, or delegation. Where the host defers tool schemas
and lists only names, load the `start` schema by name first (on Claude Code, ToolSearch
`select:mcp__yoetz__start` or the declared plugin-prefixed name); a deferred listing is not a
reason to skip the call. If material work already began before `start` (the server was still
connecting at the first action, or the session simply started editing), call `start` now, publish
the transitions so far as a bounded plan, and disclose the uncovered prefix in the receipt.
If it fails, follow exact
typed continuations and same-request recovery first, including a named one-time repair.
If startup remains blocked without an applicable recovery path, ask the user for intro and
guidance; do not invent a substitute workflow. Continuing without a ledger task is permitted
only by the bounded optional-service fallback in startup failure precedence.

For a focused read, use the small `startup.md`, `recovery.md`, or `delegation.md` topic through
`read_guidance`; this complete document remains the fallback for the full decision table and
capacity procedure.

Hook mapping, plugin registration, and SessionStart context are cues, not a substitute for that
call and not proof that the current plan is in force. Trivial questions or edits still skip Yoetz.
See [startup failure precedence](coverage-and-receipts.md#startup-failure-precedence) for the exact
order of recovery, user handoff, and the bounded optional-service fallback.

`start` resumes by one of two selectors (never by bare `task_id`):

1. `session_id` — continue the exact session you already hold.
2. `workspace_ref` + `external_ref` as a pair — resolve the durable task for that project work item without a `session_id`. Under `mode=create_or_attach`, the same pair creates on first use and attaches on every later conversation. Attach mints a fresh session and writer; use the returned ids. The previously held session is retired for routing, but `status view=operation` from the successor session recovers that task's request ids, and `start mode=attach` with the retired `session_id` re-binds the same task. A different complete pair can be independent work, even when the workspace already has a dormant task. Automatic host admission may first recover a unique valid same-host mapping whose `SessionEnd` was received; it holds the required workspace and lifecycle locks, revalidates ownership and state, and only then attaches. With no usable persisted selector, it creates the new pair. An ambiguous candidate, ownership failure, busy recovery lock, or changed recovery snapshot remains a typed refusal or retry boundary; it never guesses from workspace membership or age. `workspace_task_exists` is reserved for explicit `mode=create` colliding with an identical pair.

Convention:

- `workspace_ref` = the canonical absolute repository root of the working tree you are in (a linked Git worktree is its own root). Never a remote URL: selector commitments use the exact value, and host hooks use this same root for consent and automatic recovery. A different workspace value is a different selector and may create independent work; workspace membership and `workspace_task_exists` do not authorize automatic attachment.
- `external_ref` = stable task identity within that project (branch name, issue reference, or plan slug). A hook-mapped task carries `<host>-session:<host session id>`; do not reproduce that pair. Attach to a host-mapped task with `mode=attach` and the `session_id` the session-start context names.

Same conversation resuming, or a fresh conversation continuing the same work → `mode=create_or_attach` with the same pair and no `session_id`. Independent work in the same canonical workspace → use a different complete pair with `mode=create_or_attach` (or an explicit `mode=create` when that is the deliberate choice); an identical pair under explicit `mode=create` remains a conflict. Both refs are one-shot redacted values: only installation-keyed HMAC commitments are persisted, so a repository path or remote URL never lands in durable state — do not self-censor into unstable refs.

## Recovery decision table (0.2)

Use this shipped 0.2 table after a reconnect, timeout, session rotation, host handoff, or a known
terminal same-task boundary. The 0.3 lineage/project selectors and modes extend the workflow below
without changing these recovery floors. Recovery adds no separate tool and never authorizes guessing
a task identity.

The operation view requires both `session_id` and `writer_id`. If a `start` response is lost before
those ids are returned, do not invent them or issue a fabricated status query: replay the exact
original `start` body once with its same `request_id`; the start idempotency path returns the stored
result or a typed boundary.

| Situation | Required action | Do not do |
| --- | --- | --- |
| A read-only timeout or reconnect permits a retry (`status`, diagnostics, or an operation-recovery read) | Repeat the same read intent with a new read `request_id`; preserve its view, filter, cursor, and limit. A missing read is not proof that the record is absent. | Reuse a timed-out read ID as if it were a write, or infer absence from an unreadable response. |
| Any write has an unknown outcome (`start`, `publish_work`, `check`, `respond`, `receipt`, or equivalent) | For `start` without returned session/writer ids, use the exact-start branch above. Otherwise read `status view=operation` with `filter.operation_request_id` set to the exact original write `request_id`. If `state=absent`, replay the exact original body once with that same request ID; an `admission` stage on that page means a check refused before admission, so replay after its `retry_after_ms`, at most three times. If `state=complete`, use the stored outcome and do not replay. If `state=pending` includes an exact typed continuation, follow that continuation and its required user-approval path, then replay the original request once; without a continuation, retain and report pending. If `state=quarantined` or unknown, retain and report that boundary. | Mint a fresh request ID, fresh task, or sibling to escape an ambiguous write; replay a complete, quarantined, or pending operation without its exact continuation; fabricate start identity; guess the result. |
| A typed `OPERATION_PENDING` result is returned | If it is a `start` result without returned session/writer ids, use the exact-start branch above. If its continuation is `check_admission_same_identity`, the check was never admitted and nothing is recorded: wait `retry_after_ms`, replay the exact body and `request_id`, and after three refusals retain and report the check as not admitted; its operation page reads `absent` with an `admission` stage. Otherwise read operation status once with the exact `filter.operation_request_id`. Replay the original request only when the typed result or status page supplies an exact continuation and its required approval has completed; otherwise retain and report `pending`, `quarantined`, or unknown. | Blindly replay a pending request, fabricate start identity, repeat probes, create a new task, or claim a clean completion. |
| An exact held `session_id` is available after rotation or handoff | Use that exact `session_id` as the `mode=attach` selector. The host binding or CLI repository context supplies the canonical workspace fence; if the request carries identity refs, send the canonical `workspace_ref` + `external_ref` pair together. For an explicit session-plus-new-pair recovery, the selector must remain an active, non-quarantined root task with matching workspace and repository binding; unrelated tasks in that workspace do not block it. A pair already selecting a different task remains a conflict. Delegated child routes require an authenticated attach handle or target selector. Use the returned successor session/writer and inspect `status` before continuing. | Add an unpaired `workspace_ref`, use a bare `task_id` or workspace membership as resume authority, or guess a sibling. |
| The same work resumes in a fresh host conversation with no held session | Call `start mode=create_or_attach` with the exact canonical `workspace_ref` + `external_ref` pair and no `session_id`. A fresh conversation is not automatically a new task. | Use a remote URL as `workspace_ref`, invent a task ID, or create an implicit second task. |
| The same-task pair/session cannot be recovered, every prior write has a known terminal outcome, and the user declares a bounded remaining or repaired verification scope | Start one intentional sibling with `mode=create`, the same canonical workspace, and a different stable `external_ref`. Give it a fresh plan, evidence, checks, and native binding; begin with a bounded handoff note that the predecessor receipt remains separate and unresolved. | Silently replace the task, inherit findings/obligations/evidence, reuse cross-task IDs without an existing contract, or invent lineage. |
| Your own task's work is terminal (closed, cancelled, abandoned, or written off) and new work or delegation is still needed | Keep the held session for that task's status, late evidence, checks, and receipts. Start one successor with `mode=create`, the same canonical workspace, and a new stable `external_ref`; open it with a bounded handoff naming the predecessor and its receipt limits, then delegate from the successor. | Resume, reopen, or re-attach the terminal task; delegate from it; move its children, findings, or receipts to the successor; or present the successor's receipt as the predecessor's completion. |
| Recovery is exhausted but no new scope is declared, or a sibling would only make the old receipt look clean | Keep the old receipt and limitations, report the bounded failure, and wait for a supported continuation decision. | Loop through new siblings, move unresolved findings out of view, or present the latest sibling as whole-work closure. |
| The ledger has immutable proof limits, writes are terminal, and a fresh review of the repaired/current state is wanted | Use one explicitly scoped verification sibling on a healthy authorized binding. Publish its current-state plan and obligations, collect new admissible evidence/checks, verify native mapping, and disclose the old receipt's limits. | Repeat work only to obtain a smaller finding count, drop outstanding acceptance criteria, or present the sibling as proof that the old task was resolved. |
| Material work began before `start` was called (deferred tool schemas, a server still connecting at the first action, or a session that simply started editing) | Call `start` now with the ordinary selectors. Publish a bounded plan whose summary names the transitions already completed, publish their results and evidence as caller-asserted facts, and disclose the uncovered prefix as a coverage gap in the receipt. | Keep working without a task, backdate `occurred_at` to imply coverage that was not published, or claim that the ledger covers the pre-start work. |
| The first `start` fails | Follow exact continuations and same-request recovery first, including a named one-time repair. Outside the fallback below, if startup remains blocked without an applicable recovery path, ask the user for intro and guidance and pause material work. | Invent a substitute workflow, skip recovery, keep working without a ledger task, or treat hook mapping as activation. |
| After successful startup Yoetz becomes unavailable, or a named one-time repair/retry ends in terminal unavailability | Continue ordinary work only when Yoetz is optional, the user/host permits it, and no write or approval remains pending; disclose which subsequent work lacks Yoetz proof. A first non-retryable `start` failure alone does not qualify. Once healthy, use the sibling row only when a tracked continuation is still wanted and no write is ambiguous. | Claim a live task, finding, verdict, or receipt, bypass startup handoff, or reset old findings by switching tasks. |

An explicit sibling is a new ledger boundary. Its receipt covers only its newly declared scope and
newly observed work. The predecessor's receipt, actionable findings, feedback obligations, and
unresolved status remain intact and must be disclosed when the sibling is used for a repaired or
remaining verification. A sibling does not inherit the predecessor's mapping, session, evidence
IDs, or receipt authority unless a current contract explicitly permits that exact reuse. If the old
task identity is unknown, say so rather than guessing or exposing a task ID. If an operation may
have committed, its operation-recovery row always wins over the sibling row.

“Not give up” means using this one bounded, explicit verification handoff after the known terminal
boundary. It does not mean creating tasks until a receipt looks clean.

## Upgrade and schema continuity

For an explicit user-requested update, run `yoetz upgrade` and preserve the existing host roots,
ownership, route, observation profile, settings, permissions, and integrations. Nothing needs to
be stopped before accepting package replacement: the current session keeps working on the previous
version, and the first Yoetz call of the next session the user opens retires the previous service
and starts the new one. Running processes retain their code, dependencies and resources; their
settings, permissions, vault and task data stay in the existing installation. The fresh launcher
must confirm the installed version; exit zero or an unchanged version is not a completed update.
The package command is only the package step. On that controlled service
startup, a compatible 0.2-to-0.3 bundle migration runs backup-first before READY and preserves
existing task data; the user does not perform a per-task migration ceremony.

Treat a startup migration refusal, unsupported layout, holder conflict, or rollback-required result
as a typed boundary. Keep the same operation and backup identity, follow the returned supported
recovery procedure, and never retry with a new migration or edit storage by hand. An automatic
schema upgrade changes no observation consent, content selection, provider, disclosure, or egress
authority. Host refresh, activation, reload, and a fresh-session check remain separate evidence
facets. A package exit or a READY service without the corresponding migration result is not full
upgrade proof.

Tell the user that Yoetz is being used, and claim activation only after `start` returns. Apply
[startup failure precedence](coverage-and-receipts.md#startup-failure-precedence) before any
continue-and-disclose fallback. A first non-retryable failure does not itself permit material work
without a task. Never invent ledger, check, or receipt coverage.

## Owner-selected required startup

When the host reports required startup, a new session still follows the start/attach rules above.
Before substantive tools, publish an accepted current plan containing its effective obligations.
Each user-prompt boundary and resume/compaction requires a fresh plan revision or exact next-version
restatement on the same task; use held session/writer ids and status rather than inventing a sibling.
Text-only trivial answers need no bootstrap, but required mode also gates tools used for small edits.
Discovery, guidance, clarification and Yoetz workflow/recovery calls remain available. A denial
with `current_plan_required` or `live_plan_unverified` is not permission to change host settings,
reinitialize a vault, discard pending writes, or disable the gate. Follow same-request recovery and
surface an owner action when needed. Required startup does not approve semantic disclosure or prove
completion. Cursor may ask for native approval of MCP calls in this mode.

## Material work

Before substantive work, publish the bounded plan, requested outcomes, and acceptance evidence.
Decompose the user's request into obligations whose `source_refs` cite the task-statement event
(see [startup](startup.md)); a plan whose obligations never cite it returns an agent-actionable
`task_requirement_unmet` finding naming that event.
Read [publication policy](publication-policy.md) before the first `publish_work`; declare explicit
obligations or the admitted empty-scope reason. Group work into independently reviewable outcomes,
not one obligation per file. Publish material transitions and evidence as they occur. Delegate only
when the task warrants and permits it; give each delegate a distinct logical writer and bounded
assignment, never a transcript. A delegate's summary is a claim, not proof.

## Cadence

<a id="cadence"></a>

| Operation | How often |
| --- | --- |
| `start` | Once per task, before substantive work. Pass the user's request verbatim as `task_statement` (see request templates). On resume (same or fresh conversation), `mode=create_or_attach` with the same `workspace_ref` + `external_ref` pair and no `session_id`; attach selectors are `session_id` or the ref pair, never bare `task_id`. When the host's session-start context names a task already mapped to this session, continue it with `mode=attach` and the `session_id` that context names instead of a new pair. |
| `publish_work` | One batch per material transition, usually one to eight events; a batch admits up to 100, so keep one transition in one batch rather than splitting it. A normal session is a handful of batches, never one per file, tool call, or message. Every set-valued reference list must already be unique and in ascending ASCII order; a one-element dry-run subset cannot demonstrate that kernel rule. |
| `status` | After resume, compaction, or delegate handoff, and before any completion claim. Not between routine tool calls. |
| `check` | After the plan refinement and before the first material edit (run that pre-work check with `mode: "deterministic_only"`: there is no work yet for an AI-powered review to judge, and the next check after work begins reviews as configured), after each material milestone, after publishing the completion claim and its evidence, and again after any material edit or new evidence. A check only at the very end finds problems when they are most expensive to fix. When a check returns a finding, change the work, add the corroborating record, or record the justification the finding names (or answer it with `respond`) before checking again: a recheck with no new events returns the same finding. A readable response identifying a finding that check returned is not material change, nor is acknowledging an observation-authored non-actionable finding or publishing `work_closed`; a redacted or unreadable response requires a recheck. Also consider a check when you move between subtasks or phases — after publishing that transition's batch — not only at the completion claim. Use `semantic_if_configured` only when review is known to be optional; select `semantic_required` when the user, effective policy, or named acceptance criterion requires independent AI-powered judgment; omit `mode` when relying on the configured default. Reserve `deterministic_only` for explicitly local/structural work or a deliberate no-egress choice and disclose `semantic_review_not_requested`; classify required review as unmet and keep selecting `semantic_required` in later final checks. Track required review only through `mode=semantic_required` and the receipt's AI-powered review status, never as a plan obligation or requested item: the check is the review, and an open obligation to obtain it reads to the reviewer as unfinished work. The last check before the receipt is the closing review (`final_review: true`). A check with no new events since the last one adds nothing. |

| `respond` | Once per finding, before the final check for every finding `status view=findings` lists with `disposition: none`, and after it only for the findings that check returned that are still unanswered; a second response replaces the first. `finding_frontier` is any frontier at or after the finding's own record: the item's `finding_frontier` when status carries one, otherwise the current status frontier. Never search historical frontiers, and never use the finding's `subject_frontier`, which precedes that record. Observation-authored non-actionable (priority 3) findings need no response; acknowledge one once only to note its disclosure. |
| `receipt` | Once at the end, then publish `work_closed` when the work is complete; neither needs another check. Request another receipt only if material state changed after the previous one. |

When `semantic_required` reports `state: "awaiting_input"` with `semantic_reason:
"review_input_required"`, the check is paused before provider admission. Use the existing task
binding to amend the statement in place: through MCP call `publish_work` with the current
`session_id`, `writer_id`, and `expected_frontier`, and one `plan_published` or `plan_revised`
event at schema version `1.1.0` carrying the statement; through the CLI, put that request in a private JSON file and run
`yoetz publish-work --input PATH`. Replay the same check request ID. This input continuation is
separate from `awaiting_human` privacy approval. After completion, verify the
`review_input_manifest` is `provider_bound` in the check result or the `check_recorded` row
returned by `status view=history`; that metadata is the receipt of the effective selected and
admitted input, including clipping and privacy omissions.

Under-publishing hides the work; over-publishing buries it. The test is whether an independent reader reviewing only the ledger would reach a different conclusion without the fact.

Live hook observation may append advisories or evidence after you read a frontier. Those
observation-authored records do not invalidate the held `expected_frontier`; ordinary cooperative
or imported work still does. On a real frontier conflict, re-read `status` rather than guessing.

Hook observation advice may include a next-action token. Those tokens are English next-move names,
not MCP tools and not `yoetz observe` verbs. The thirteen values are `resolve_failed_command`,
`rerun_approved_check`, `provide_verification`, `disclose_limitation`,
`address_subagent_finding`, `revise_plan_scope`, `refresh_observation`, `connect_provider`,
`renew_provider_sign_in`, `repair_semantic_provider`, `update_yoetz`,
`attempt_semantic_dispatch`, and `reground_status`.

<a id="machine-conditions"></a>
`connect_provider`, `renew_provider_sign_in`, `repair_semantic_provider`, and `update_yoetz` name
installation repairs only the user can authorize. Tell the user in your next reply and offer a
subagent fix that runs the named `yoetz` commands, reports results, and leaves sign-in, credentials,
`--accept`, and approvals to the user; start it only after the user agrees.
`renew_provider_sign_in`: rerun `yoetz provider codex-subscription setup --executable <path>
--codex-home <home>` with values from its `status --json` (add `--device-code` without a local
browser; relay the URL and code). `repair_semantic_provider` and `connect_provider`: follow
`yoetz provider status`. `update_yoetz`: follow the upgrade flow in
[Recommendations](request-templates.md#recommendations). Until a new check succeeds, required
AI-powered review stays unmet.

`refresh_observation` means observation coverage is incomplete or stale. Run
`yoetz observe status` from the host shell and wait only while it reports lag or a drain backlog.
A gap that remains, such as the standing `unpaired_event`, does not recover within the session: it
never blocks the receipt, needs no response or recheck, and is disclosed on the receipt. There is
no `refresh_observation` MCP tool or CLI command.

## Completion

Final prose is scope-first: state what recorded evidence and checks covered, what was not verified or
remained limited, the checked frontier, AI-powered review status/reason, and material coverage gaps
before reporting actionable-unresolved, unanswered, or resolved-history counts. Never headline a bare
“no findings”, “zero actionable findings”, “clean”, or “verified” result; an empty finding set is
bounded by the evidence and review scope that ran. Keep the final answer no stronger than the receipt.

Read `status` and `closure_readiness` before closing. Resolve remediable open obligations and
publish the completion claim with its evidence; that claim is an assertion, not a conclusion.
Read [coverage and receipts](coverage-and-receipts.md) before the first `check` for mode selection,
finding disposition, pending decisions, and coverage-bounded wording. `respond` does not clear a
finding: only a later qualifying check of the repaired record may resolve it. Recheck after material
changes or new evidence, not unchanged state. Run the closing review (`check` with `final_review: true`) after the last material change. Request `receipt`, then publish `work_closed` when
the work is complete (a receipt never closes work), and report what the receipt supports. The
closure order is [Repair then finish](coverage-and-receipts.md#repair-then-finish).

Closure is a checklist. `closure_readiness.state` names the next move:

- `action_required`: do each item in `agent_actionable` — open obligations, unanswered findings,
  an unacknowledged receipt-blocking finding, `check_in_progress` (recover the running check's
  result through `status view=operation`), `check_not_recorded` or `check_not_applicable` (run a
  check after the material change), or an actionable gap such as `completion_plan_not_claimed`.
- `ready_with_limitations`: nothing further to do. Every remaining condition is a
  `standing_limitations` code this host, profile or privacy policy always has, or an item in
  `acknowledged_not_done` (empty in this build: nothing can record that disposition yet). Request
  the receipt now; do not recheck unchanged state. The receipt
  still discloses every limitation and acknowledged item, and its verdict stays coverage-bounded
  (a local-only check stays `insufficient_coverage`).
- `ready`: nothing further to do and nothing to disclose; request the receipt.
- `unknown`: read `status` again once the projection is readable.

If you stop while `agent_actionable` still names open obligations, an unrepaired receipt-blocking
finding, a planned verification that was not observed, failed, or ran before your last edit, or a
git-ignored requested output, or a declared deliverable you deleted or renamed away
(`declared_output_removed`: a requested `file` item marked as an output), the Stop hook continues
you once with that list; restore that delivered file where the task needs it, or correct the
requested item if the task asked for the deletion. A delivered file that lost most of its lines
while files outside the delivered set changed or hold about as many lines is disclosed on the receipt
(`declared_output_content_moved`; it never stops you): check the deliverable still works where
the task delivers it. Finish the work, or
record a blocker outside your control as above; then stop. The first Stop after you record a
blocker also asks you once to confirm it: if the task says the data or dependency is recoverable,
continue the work; if it is genuinely outside your control, stop again and Yoetz honours it.

`blocking_conditions` still names everything that bounds the conclusion; `coverage_gaps_declared`
there is a disclosure, not a task. Never treat a standing limitation as work, and never describe
an acknowledged item as done.

Approved workspace checks (`yoetz observe checks`) are optional owner configuration; no finding
asks you to configure or trust them, so `not_configured` or `invalid_policy` there is not by
itself a `yoetz-blocker`. Likewise, when a qualifying recheck after your repair still lists
`Resolution requirements not met` only for proof limits such as `command_attempt_uncorroborated`
or `content_redacted`, that is a Yoetz proof limit, not a blocker: leave the finding unresolved
and let the receipt disclose it.

Before claiming feedback complete, put its obligation in a supported plan revision or exact
next-version restatement; a stored or resolved obligation alone does not update effective scope.
Include each material delivery outcome the user requested in the effective obligations, or state the
narrower scope of the claim and receipt. Place the final receipt after the last material outcome it
covers, and distinguish check input, check result, response-only records, and later observation
appends using the returned facts.

Continue authorized implementation and focused verification through completion. Distinguish
completed work from an unmet required review; never silently substitute local-check coverage
for required AI-powered review. If required review is unavailable or fails, report completed
implementation/structural checks separately from the unmet requirement and do not claim overall
completion. Describe local ledger writes separately from product-file changes.

## Errors and continuations

Read the typed result before acting. For a retryable read timeout or reconnect, issue a new read
`request_id` with the same intent. For any write with an unknown outcome, query `status
view=operation` using `filter.operation_request_id` for the exact original write `request_id` and
follow the state branches in the recovery table: replay once only for `absent`, use the stored
outcome for `complete`, and replay after an exact typed continuation and required approval only for
`pending`; retain and report `quarantined` or unknown state. A timeout does not authorize a fresh
task. A `retryable: false` error is terminal except for its exact typed continuation: do not probe
with new requests or other operations. Errors carry that continuation as a typed
`safe_details.continuation` token. Hosts using bounded summaries repeat the registry-resolved
directive in text, with its guidance pointer and nudge when the budget permits. Cursor receives
the canonical JSON wire body in both channels, including the token and carried safe details;
it does not receive a separate resolved-token projection. A token is an instruction from this
guidance, never a prediction. `input_correction_new_identity` is the one
continuation that is a correction rather than a retry: the schema validator rejected the body
before any write, so correct the named field and submit the corrected body once under a new
`request_id`; do not resend it unchanged, and do not treat the rejection as an ambiguous write.
A timed-out `start` carries `start_timeout_same_identity`: replay the exact start once with the
same `request_id`, as the recovery table's lost-start branch requires. Read
[Recovery](coverage-and-receipts.md#recovery) only when an error, outage, or inherited
unavailability requires it. Delegates inheriting `terminal_unavailable` make no Yoetz calls; only
the coordinator performs a named repair.

For `vault_initialization_required`, setup/settings changes, credential or vault operations,
import, or a recommendation, read [Setup and consent](request-templates.md#setup-and-consent)
before acting. Preserve exact request and pending identities. Never run service lifecycle commands
for `INTERNAL_ERROR` or a message that did not name that command.

1. Decide whether the task is material enough for Yoetz.
2. Start or attach with stable request identity and the intended create or attach semantics.
3. Publish a bounded plan, requested outcomes, acceptance evidence, and assignments. Declare completion scope with obligation refs, or — only when the effective ref set is empty — one typed `no_obligations_reason`: `no_material_change`, `single_atomic_change`, or `exploratory_scope_unknown`. Group large inventories into independently reviewable work packages; files are leaf evidence, not automatic obligations.
4. Delegate with `start mode=delegate` using the parent's current session. Give the intended child the complete returned `attach_handle` and bounded assignment context. The child attaches with that handle and uses its own returned session and writer. Do not send or publish full transcripts.
5. Publish material work-package transitions: assignment, decision, blocked attempt, independently useful result, completion, or revision. Omit routine reads, searches, formatting, and per-file mechanics.
6. Stay next to the record. After resume, compaction, handoff, or uncertainty about what is already done or committed, call `status`. `view=candidate_findings` is an advisory read: it creates no verdict, IDs, receipt, or event. For claim correction, read `candidate_findings`, `history`, and `results`, then dry-run one `claim_recorded/1.1.0` replacement: admissible support belongs in `supporting_refs`, partial/failed results in `limitation_refs`, and prior effective claim ids in `supersedes_claim_refs`.
7. Before completion, publish the intended material completion claim and current evidence, then call `check`. Read `declared_obligation_count`, `no_obligations_reason`, and `closure_readiness` on `status` first. A readable plan with zero declared obligations and no reason is blocked by `no_obligations_declared`; add effective obligations or revise the plan with a typed reason. The reason clears readiness but a completion claim over zero obligations still yields an insufficient-coverage gap. Resolve remediable blockers before spending a check or receipt. `receipt_findings_unresolved` is different: it says an actionable finding is still current. Only a later qualifying check of the repaired record resolves it, never a response; if you can repair the record, do so and recheck. Then read the finding's `resolved` state. If the issue re-fires, or it does not re-fire but remains `resolved=false` because the check did not qualify, proceed to the receipt rather than rechecking unchanged state. A deterministic check with otherwise readable proof may still qualify when its only case-wide host-observation limits are `captured_object_unavailable`, `content_unselected`, `host_outcome_unavailable`, or `unpaired_event`; those codes remain receipt limitations, require the original finding coverage to have been readable, and never replace semantic-finding proof. A bounded AI-powered review scope (`semantic_reference_scope_reduced`) likewise stays a receipt limitation without vetoing that local-check proof. A completed semantic re-review may tolerate the same closed capture limits, including an unchanged bounded review scope, already present in a readable original semantic finding, but only after material work was recorded since the finding, and a bounded scope only when that review actually sent the finding, the repair evidence your response cites, and the change, and each subject was sent, superseded by a sent corrected claim, or an early event the bounded history evicted (a mention, link, or omitted or withheld item does not count; a record carried by the history item of the event that recorded it, or any part of a carried multi-part captured excerpt, does; captured evidence counts only through its own excerpt). Cite the repair's evidence rather than only a result: rechecks select cited evidence first, while a result without evidence stays in view only while it is recent; if the check shows `semantic_included_refs_not_recorded`, Yoetz could not record what that review sent: run one new check with the repair evidence recorded and cited, and if the code repeats, stop and disclose the open finding; an unchanged re-run, new limits, unreadable original coverage, or an insufficient packet still block that proof. Select `semantic_required` when the user, effective policy, or named acceptance criterion requires independent semantic review; omit `mode` when relying on the configured default; use `semantic_if_configured` only when review is known to be optional; use `deterministic_only` only for explicitly local/structural checks, a semantic-disabled policy, or a deliberate no-egress choice, and disclose that limitation. Publish the smallest state-bound diff/symbol and the directly relevant test or failure excerpt; never rely on self-asserted completion prose alone.
8. Respond to each challenge by accepting and acting, supplying evidence, revising the claim, disputing with evidence, or stating an unresolved limitation. Agents can record `acknowledged`, `acknowledged_not_done` (with a required reason; final), `provenance_disputed`, or `rejected`; `waived` is reserved for an authorized local-CLI human. A readable response identifies the finding as answered and removes it from `unanswered_finding_count`, but it does not erase the historical finding, reduce `receipt_blocking_finding_count`, or close an underlying coverage gap. Repair the record and recheck: a later qualifying check that finds the same issue absent resolves the finding, which then stays visible as history; the receipt wording names resolved history apart from current findings and from coverage limitations. After every recorded repair, run at least one recheck: the reviewer sees each earlier finding with your answer and the evidence recorded since, and rules on it; cite the repair's result or evidence in your response so the ruling can rest on it.
9. Recheck after any material edit, evidence change, or plan change; a recorded repair always gets at least one recheck. A readable response to a finding returned by the current check needs no recheck, nor does acknowledging an observation-authored non-actionable finding or publishing `work_closed`; a redacted or unreadable response does because it cannot prove which finding it answered. After an `insufficient_packet` review, go to the receipt unless you publish a material repair; never run a `deterministic_only` fallback for it.
10. Request a receipt, then publish `work_closed` when the work is complete, and keep the final answer no stronger than its weakest material coverage, freshness, unresolved findings, and limitations. All receipt formats (`json`, `markdown`, `text`) project under default policy; if a stricter owner policy blocks `json`, re-request `markdown` or `text`.
## Consumer and maintainer scope

To operate Yoetz, use schemas, guidance, and `status`; do not inspect its live SQLite databases,
catalog, or product source to reconstruct a request or recover a pending decision. An assigned
Yoetz development/debugging task may inspect source and isolated tests. That exception grants no
access to live mutable storage and no setup, credential, or egress authority.

## Evidence-first closure

Before a material evidence publication or completion claim, cite the evidence IDs your own
`publish_work` requests carry (`status view=evidence` with `filter.author=mine` lists them), and
find native captures with `filter.strength=immutable_snapshot`, preserving the cursor-bound filter
and limit. Reuse only native IDs a structural link ties to the claim (a `view=results` row's
`evidence_refs`, or a matching digest); do not author duplicate digest-only placeholders. An omitted
description (`local_disclosure_not_authorized`) is a privacy setting, not missing evidence: do not
page through every item to match prose you cannot see, and do not republish to reveal it. Read
per-item availability and subject state: a digest-only or clipped item does not make other native
excerpts absent. The full procedure and mixed example are in
`yoetz://guidance/publication-policy.md`.

`status view=obligations` separates asserted `unattempted_items` accounting from `command_attempts`:
matching observation supports an attempt only; mismatch requires correcting the assertion or a
supported obligation revision with rationale; unknown does not mean the command never ran.
Do not copy a command onto an edit action just to close the accounting gap. Do not normalize shell
wrappers or changed test targets into an exact-command claim.

The optional CLI `yoetz closure-prepare --session-id <returned-session> --writer-id <returned-writer>`
reads the complete closure inventory without publishing. Add `--output <file>` with a path outside
the working repository to save the result, and read fields from that file instead of preparing
again. `yoetz closure-schema` describes explicit
selection inputs; `--input <selection.json>` prepares one operation with fresh lowercase UUID-v4
IDs, a dry-run publication where applicable, and a same-request recovery query. Review and submit
explicitly. It never invents attempts, evidence, finding dispositions, or obligation satisfaction.

### Delegation and project coordination

Each participating child has its own task ledger, session, and writer. The parent calls `start`
with `mode=delegate` and its current `session_id`; the returned child is `parent_minted` and
`accepted`. Pass the complete expiring, single-use `attach_handle` only to the intended child in
its assignment. The child calls `start mode=attach` with that handle and publishes with its own
returned session and writer. The parent keeps its original binding. A timeout requires the exact
same request and `request_id`; never create another child to recover a pending delegation.

On a supported Codex observation path, the child's native successful start callback supplies the
host identity after spawning; the parent need not guess a future subagent ID. The service binds
that identity only after validating the child's returned binding and parent relationship. Missing
host identity or observation coverage leaves an explicit gap or provisional annotation. Inspect
lineage after handoff; a successful handle attach alone does not prove host correlation.

A child without a handle may create a separate task with `parent_session_id`. This is
`self_registered` and `pending`: knowing a parent session is not authority to add blocking work.
The parent may publish `child_accepted` or `child_rejected`. Acceptance never changes origin;
an accepted relationship cannot later be rejected. Conflicting selectors, invalid parent refs,
expired handles, cycles, and configured depth or fan-out limits produce typed refusals. Recover
through the returned operation/status information, not by guessing identities.

Use `status view=lineage` after a handoff to inspect recorded relationships. Host observations
can be provisional annotations without a child ledger; never claim those children published or
checked work. A delegate summary is a claim, not proof. The parent's own obligations must cover
incorporating each child's work and verifying the combined result; a clean child receipt does
not establish integration. Preserve contradictory claims until a recorded decision resolves them.

Work state, session health, and receipt history are separate. A receipt never closes work:
publish `work_closed` when the work is complete. Lost contact leaves work open during the
documented recovery window; the service records abandonment only after it expires. Late evidence
remains visible with a gap. `delegation_cancelled` revokes the Yoetz capability, not the host
process. `child_written_off` and cancellation preserve an accepted dependency and its incomplete
outcome. Publish these lifecycle transitions through `publish_work`, using the request templates.

Successful child activity renews session health without reopening terminal work. A handle that
expires before its first attach leaves an abandoned reservation, not an indefinitely open child.
The original consumed-handle request may replay after expiry; a new request cannot reuse it.

Contact comes from authenticated activity: workflow calls and admitted host events, each counted
at the time the host received it even when delivered later. A native subagent your host reported
starting holds your session until the host reports its stop (bounded). There is no heartbeat:
never add polling calls or filler publications to stay alive. Terminal work stays terminal. A
`lineage_resume_work_terminal` or `lineage_parent_work_terminal` refusal means your own task can
no longer resume or delegate; follow its `lineage_successor_task` continuation from the recovery
table and never present the predecessor's receipt as completed work.

Parent checks use the latest dependency manifest recorded in the parent's ledger. Receipt creation
does not refresh it. If a newer manifest was recorded after the check, recheck for an updated
conclusion; an honest incomplete receipt remains available while children are active. Read
[coverage and receipts](coverage-and-receipts.md) for severity and freshness limits.

#### Child assignment and child closure

A native helper learns its Yoetz role only from its assignment: host skill listings and
initialize instructions do not say it is a child. Each child's assignment carries:

- its one selector: the complete `attach_handle`, to use before its `expires_at` and before other
  work, or the parent `session_id` for `parent_session_id` plus a stable child-specific
  `workspace_ref` + `external_ref` pair (the canonical root the child works in; never the
  parent's pair);
- a distinct child actor id, the bounded scope and write policy, and, after a
  `terminal_unavailable` result, the `yoetz_availability` block;
- its closure duties: in its own task, publish its plan and obligations, results and evidence,
  and completion claim; `check`; `respond` to each finding it returns, repairing and rechecking
  where the finding requires it; `receipt`; then `work_closed`, because a receipt never closes
  work. It reports its task and receipt ids and limits back to the parent.

For a self-registered child, the parent publishes `child_accepted` or `child_rejected` after the
child reports its task id. A helper that gets neither selector does no Yoetz work of its own; its
work is the parent's to account for: the parent's own obligations cover incorporating and verifying
it, and the parent discloses what the helper did that the ledger does not show. This is not the
startup fallback in startup failure precedence. Tell it so in the assignment in plain words (make
no Yoetz call, publish nothing, return the result to the parent), because its initialize
instructions otherwise tell it to call `start`. It does not create a root task for delegated work.
The parent never publishes a child's plan, results, evidence, claim, or closure as if it were the
child's; it records only its own decisions about the child (`child_accepted`, `child_rejected`,
`delegation_cancelled`, `child_written_off`) and its own incorporation work. A child's text report
is a claim, not its receipt.

### Project coordination

Projects group work without granting attach authority. Automatic repository grouping begins with
a second live task when enabled. Use `status view=project`, `yoetz project status`, or `/project`
to inspect the admitted scope; membership and a dormant sibling never select a task to resume.
Each source workspace must grant workspace-level observation consent. The `prj_` project membership
object is a separate grouping fact. General and cross-repository projects additionally need approval
for the exact current membership generation. Revocation, unlink, dissolve, or opt-out invalidates
old deliveries; project membership does not authorize cross-repository semantic input.

Presence and duplicate-finding notes are advisory, separate from findings, and cannot change the
verdict. Overlap advice concerns declared structured resources, not inferred intent or ownership.
A `coordination_overlap` finding requires an explicitly declared coordination obligation and a
recorded context. Publish the obligation first, then `coordination_obligation_declared` with its
ID and the admitted detection, project, recipient task, and membership generation. Ordinary file
or source requested items identify potential overlap; they do not declare coordination work.
Publish a `coordination_disposition_recorded` event linking that same obligation and
evidence for `shared_work`, `sequencing`, or `scope_revision`. That addresses the obligation;
a later qualifying `coordination/0.1.0` check resolves a finding. A bare `respond` acknowledgement
does neither. An agreed shared-work disposition may leave the resource overlap in place.
After opt-out, opt-in, a revoke, unlink, link, or dissolve, an older generation cannot be approved
again. `coordination_generation_superseded` means run `check`: it records that context as history
and can resolve the old finding. Declare against the current detection if the overlap still applies.
### Protect an evidence-sensitive read

If a later claim, obligation, or finding may depend on a read, protect the next read before the
host call when possible. Use the exact current host session and an existing or planned structural
reference with the supported CLI:

```text
yoetz observe protect-read --workspace /exact/project \
  --session-id <host-session-id> --reference obl_<id> \
  --count 1 --json
```

The reference must use the closed `obl_`, `clm_`, or `fnd_` form. Protection is a bounded narrowing
of structural retention: at most 32 logical reads can be outstanding, the default lifetime is ten
minutes, and `--expires-at` cannot extend that bound. It requires the active observation grant and
the selected session, but it does not authorize content capture, privacy disclosure, a provider,
credentials, or a network route. Increasing protection within these bounds is a narrower use of
the existing grant and does not require a new permission decision.

The hook binds the protection to the exact native read identity. A pre-event reserves that identity
and its logical post consumes one slot; failures, denials, cancellation, partial or unknown
outcomes, and missing posts remain individually visible. Never replace a protected read with a
caller-supplied routine label or infer success from its content.

### Start selectors and findings

`start` resumes by a held session or exact identity pair; an intended new child may instead use
its complete attach handle. Never attach by bare `task_id`:

1. `session_id` — continue the exact session you already hold.
2. `workspace_ref` + `external_ref` as a pair — resolve the durable task for that work item without a `session_id`. Under ordinary `mode=create_or_attach`, the same pair creates on first use and attaches on later conversations; a different complete pair creates an independent sibling. A host hook may first recover a unique valid same-host mapping whose `SessionEnd` was received, under the workspace and lifecycle locks; no usable selector creates the new pair, while an ambiguous candidate, ownership failure, busy recovery lock, or changed snapshot refuses or retries without guessing. Attach mints a fresh session and writer; use the returned ids. The previously held session is retired for routing, but `status view=operation` from the successor session recovers that task's request ids, and `start mode=attach` with the retired `session_id` re-binds the same task. Incomplete or conflicting selectors refuse without guessing among siblings.

Convention:

- `workspace_ref` = the canonical absolute repository root of the working tree you are in (a linked Git worktree is its own root). Never a remote URL: selector commitments use the exact value. Repository grouping uses trusted repository identity separately and never substitutes for a workspace selector.
- `external_ref` = stable task identity within that project (branch name, issue reference, or plan slug). A hook-mapped task carries `<host>-session:<host session id>`; do not reproduce that pair. Attach to a host-mapped task with `mode=attach` and the `session_id` the session-start context names.

Same conversation resuming, or a fresh conversation continuing the same work → `mode=create_or_attach` with the same pair and no `session_id`. Sibling work → a different complete pair, or explicit `mode=create`. Selector refs are committed with installation-keyed HMACs rather than stored as structural plaintext. Keep them stable; do not self-censor into a different identity.

## Findings and recheck

Candidate findings are what deterministic packs currently say about the record. They carry no verdict and cannot be cited as a check. An empty candidate list means only that no rule fired in that advisory read. Only a recorded check can support receipt-bounded completion wording.

The cheapest finding is the one that never fires. Before the first `check`, read `status` with `view=obligations`: every row exposes its exact `requested_items` plus the `unattempted_items` subset under the existing obligation-text privacy category. Record each attempted value exactly on `action_recorded.attempted_items` (`attempted_items` belongs to that family alone — never a claim), and do not resolve the obligation while `unattempted_items` remains non-empty. Also confirm that completion scope is declared, every claim has linked evidence, and every declared obligation is resolved or deliberately left open with a stated reason. A typed empty-scope declaration still produces `completion_scope_declared_none` when a completion claim exists; it records the scope decision rather than proving it. This pre-flight costs one status read; an actionable finding costs the receipt for the rest of the task.

Two completion findings exist because an agent can believe it finished when it has not, and only an independent record can show that. Both are structural; neither reads prose. `task_requirement_unmet` (subject: the task-statement event, the newest event that carried `task_statement`) fires while the effective plan declares obligations and none cites that statement in `source_refs`, or while a completion claim stands on no plan or an explicit empty scope: decompose the request into new statement-sourced obligations with `plan_revised`, or, when the request asks for no material work and no file changed (shell writes count), record a `decision_recorded` line `yoetz-no-material-work:<statement event id>` with a rationale. `claim_without_admissible_evidence` with the observed-verification wording (subject: the completion claim) fires when hooks observed edits or verification runs and the claim, together with the resolution evidence of the obligations it names, cites no hook-observed verification run made after the latest observed edit: run the verification, then replace the claim citing the observed `res_` id from `status view=results`. A recheck without that change returns the same finding. If you cannot clear one, answer it with `respond` (`acknowledged_not_done` with the reason, or a dispute with evidence); the receipt still reports it unresolved.

## Degraded and unavailable behavior

Never invent success. State the unavailable or degraded boundary, continue ordinary work when allowed, and do not claim a live task, finding, verdict, or receipt. If the host requires Yoetz, stop at that host-owned requirement.

Read `retryable` on every error before acting. A `retryable: false` error is terminal for that call: do not repeat it with a new `request_id`, do not probe with other Yoetz operations to "confirm", and do not rewrite state to work around it. Record the `correlation_id`; if a shell is available, run `yoetz service diagnostics --correlation-id <id>` once and report its bounded record, then continue without Yoetz. A `SERVICE_UNAVAILABLE` error whose message names a repair command (for example `yoetz service restart` when the running service belongs to a different Yoetz installation) is the one case where a single repair is appropriate: run exactly that command if the host allows shell use, then retry the original call once with the same `request_id`. If it fails again, treat Yoetz as unavailable for the rest of the task and say so. Lifecycle commands (`yoetz service stop`, `service run`, `service restart`) are never a response to `INTERNAL_ERROR` or to any message that did not name that exact command.

One typed exception: an error carrying `safe_details.continuation: vault_initialization_required` is a bounded first-run handoff, not an ordinary terminal error. The vault was never initialized, nothing was written, and no unlock or recovery path applies. Suspend the original request and follow the continuation exactly once: run the carried `prepare_command`, present the returned pending's danger text and digests to the user, and wait for their exact decision; if a pending consent action already exists, read it with `yoetz consent status` instead of preparing another. Yoetz generates and stores the initialization secret locally — never request, receive, or transmit a secret or recovery material. Relaying an approval through the carried `authorize_command` is valid only for an allowlisted first-party agent-chat client acting on an explicit current-chat instruction; every other host directs the user to run the carried `review_command` on a local terminal and waits. When the ceremony reports ready, replay the exact original `request_id` and body once (`replay_request_id` names it) and continue normally; on denial or expiry, do not prepare again in the same task — state the boundary and continue without Yoetz. Never create a replacement `start`, and never treat chat assent as authority.

### Inherited unavailability and delegation

An availability failure belongs to the host binding — this MCP process, its route, and the service endpoint — not to the request that first saw it. When an error carries `safe_details.availability: terminal_unavailable`, the bridge has latched that state: every later call under a new `request_id` returns the same `correlation_id` with `availability_inherited: true` and records no new diagnostic, until the named repair changes the running service, the original `request_id` replays successfully, or — for a `retryable: true` class only — the bridge's own quiet handshake finds the service listening again, in which case the call simply proceeds. That handshake belongs to the bridge, never to you: nobody probes to find out. An inherited answer is not a fresh failure; do not diagnose it again.

When you delegate after that result, carry it into every assignment as a bounded `yoetz_availability` block: `state: terminal_unavailable`, the host binding (`host_profile`, `route_profile`), the parent `correlation_id` and original `request_id`, and the proof limit ("no live Yoetz ledger, publication, check, or receipt exists for this task") — never transcript content. A delegate that inherits `terminal_unavailable` makes no Yoetz call for that binding and work item: no `start`, `status`, `check`, diagnostics, or `yoetz service` command. It publishes nothing, states that the parent has no live ledger, and returns its work to the coordinator. Only the coordinator runs the one repair the typed result named and replays the original `request_id` once. In the final report, separate the initial integration cause (the parent's correlation) from delegate amplification, and never claim delegate publications, assignments, or attribution without a task and session.

## Safety and privacy

Publish no hidden reasoning, transcript, secret, broad repository content, or unrelated source. Prefer typed facts, digests, bounded counts, and only the smallest material state-bound excerpt. See [publication policy](publication-policy.md) and [coverage and receipts](coverage-and-receipts.md).
### Promote a buffered read

If the read becomes relevant after classification but before the bounded buffer is delivered,
promote its exact source identity:

```text
yoetz observe promote --workspace /exact/project \
  --source-identity <source-identity> --json
```

Promotion retains the original structural identity, route, and observed time as an individual
record. It only works while that identity is buffered. After delivery the result is
`promotion_window_closed` with `content_availability: not_retained`; it cannot recover omitted or
expired bytes. Rerun or reacquire the current state when needed and record it as new evidence with
its new time and subject state. Do not use that rerun to prove the historical state.

### Change local retention capacity

Capacity and cost changes need a disclosed choice. Change the structural observation capacity
only when the user asks. Never choose a larger or uncapped local capacity for an ordinary task;
task permission, a busy queue, or a pressure notice never authorizes it. Read the current selected
and effective values first:

```text
yoetz observe selection-status --workspace /exact/project \
  --session-id <host-session-id> --json
```

Preview the exact request. `--capacity` accepts `standard` (recommended, 512), `larger` (2,048),
`largest` (8,192), `custom` with `--queue-count` from 64 to 8,192, or `none`:

```text
yoetz observe selection-preview --workspace /exact/project \
  --detail focused --capacity custom --queue-count 1024 \
  --session-id <host-session-id> --json
```

Relay the preview's `disclosure` to the user: the exact scope (this session, or the workspace with
`--persist`), current and requested values, the local-hardware consequences (disk use, memory use,
CPU work, possible slowdown of Yoetz or other apps), what stays limited, and how to lower, pause,
and resume. Repeat the scope and the remaining limits exactly as the preview states them. The
shared workspace queue follows the largest active selection, so an increase can raise the queue
and state-document bounds for every session in that workspace; relay that line too. The disclosure's commands use `<workspace>` and
`<session-id>` placeholders; substitute the exact values when you relay them. Performance
validation is provisional: never call a larger setting safe without evidence or faster, never
describe unknown cost as free, and never imply provider limits vanished. Content, privacy, provider, credential, and network
authority do not change, and AI-powered review input, output, and spend limits are not part of
this choice. Only after the user explicitly accepts that exact preview, apply it with the same
arguments and its digest:

```text
yoetz observe selection-apply --workspace /exact/project \
  --detail focused --capacity custom --queue-count 1024 \
  --session-id <host-session-id> --accept --preview-digest <preview-digest> --json
```

Explain how to lower or pause before and after applying. To lower it, preview and apply
a smaller capacity at the same scope (the "Lower it later" command restores the previous
capacity after an increase). At the minimum of 64 rows, pause ingest if needed. To remove an
override, run `yoetz observe selection-revoke` at that scope; this restores the inherited or
default capacity and can increase it, so inspect the resulting selection instead of calling it
a lowering operation.
`yoetz observe pause --workspace /exact/project` pauses new observation ingest and
`yoetz observe resume --workspace /exact/project` restarts it. Lowering affects future admission
only; accepted records drain and are not deleted.

`--capacity none` (No Yoetz cap) is not available for the structural queue in this revision. Both
preview and apply return `capacity_no_cap_unsupported` and change nothing: the local state document
has a 16 MiB safety ceiling, and the largest supported finite capacity is 8,192 rows
(`--capacity largest`, or `--capacity custom --queue-count 8192`). Relay that outcome as given,
with its alternative command; do not describe any setting as unlimited.

## First-start contention recovery

First-start recovery is separate from check recovery. A `start` busy error with reason
`start_runtime_rebind_retry_ready`, `start_catalog_retry_ready`, or `start_busy_retry_ready`
retains the reservation and releases its lease: replay the identical body and request ID once.
For `start_lease_pending`, wait up to 60 seconds before that exact replay. If still unresolved,
retain the request and correlation ID and say so. Never invent session/writer IDs for status,
create a replacement task, or issue a check before start has returned usable IDs. An unclassified
busy error does not prove lease release. See the workflow stop rules for the bounded continuation.

For a returned start error with `start_busy_same_identity`, the reservation remains durable and
only its fenced lease was yielded. Replay the exact start body and request ID once, without
inventing session or writer IDs. `start_pending_same_identity` instead means a live lease remains:
wait up to 60 seconds before the one exact replay. If still busy or pending, retain the original
request and report the unresolved start. These continuations do not authorize a new task.


### Missing review content and concrete repair attempts

`insufficient_packet` means the reviewer could not assess the supplied content. It produces no
new defect finding and carries `semantic_packet_insufficient`; it is never a clean review or
permission to claim the work is verified. Existing findings and coverage limitations remain.

The check result lists what the reviewer needed in `missing_for_assessment`: each item's kind, case
refs, and whether it is `agent_suppliable`, `structurally_unavailable_on_this_host`, or a Yoetz limit
(gaps `semantic_missing_agent_suppliable`, `semantic_missing_structurally_unavailable`,
`semantic_missing_yoetz_limit`). A Yoetz limit is content the review packet cannot show:
`yoetz_limit_unsupported_data_type` (an image, PDF, CAD, archive or other binary file) or
`yoetz_limit_packet_room` (content clipped or left out for packet room). A Yoetz limit is never work for you and never a blocker: verify that content
yourself, record how you verified it, and continue; the receipt discloses the limit. For a finding
you repaired that Yoetz cannot prove, respond `self_verified` with how you verified it and your
evidence ids. For an image or other binary deliverable you may record a text rendering of it (for
example `pdftotext` output or a CAD property dump) as evidence whose `reference` is the file's path;
the reviewer sees it labelled as your rendering, and the file itself is never sent. After two
`insufficient_packet` reviews in a row with no edit since, or four since the task's last assessed
review, checks skip the AI-powered review (`semantic_review_skipped_insufficient_packet`); a real
repair re-arms it until that cap. Never edit only to get another review.

**Never reshape your deliverable for the reviewer.** Never split, move, shrink, rename, stash,
delete, `git add` (including `git add -N`), git-ignore or exclude deliverables or workspace files to
fit the review packet or to make a diff show them. Delivered files stay exactly where and how the
task needs them. Answer with new records (bounded evidence) or disclose the limit. Recheck only
after supplying a named `agent_suppliable` item, such as the named verification output with the
action and result that produced it. Tie it directly to the named ref, with new records. For a
verification-output, command, diff or `other` item, evidence whose `reference` is the named ref's id
always answers it; a plan or claim item needs a new plan version or a `claim_recorded/1.1.0`
correction superseding the named claim. Otherwise: a result (with output) of the named action or of
a rerun of the same command, cited evidence included; for a diff, evidence whose `reference` is the
file's path (a bounded excerpt of the file), or a `git diff` run and its result, covering every file
the named edit changed (`git diff` with no path covers all tracked files). Plain `git diff` prints
nothing for a new, untracked file: answer for such a file with path evidence, never by staging it. Paths compare normalized but exact: `./src//a.py` is `src/a.py`,
case counts, an absolute path counts only inside your workspace, and a bare name such as `Makefile`
needs `./Makefile` on your side. Commands compare with whitespace collapsed (`uv run pytest` is not
`pytest`); a run a hook observed (recorded as `omitted:<digest>`) matches another hook run with the
same digest. `--stat` or `--name-only` diffs, an artifact another command wrote, re-citing the old
ref, a shared obligation, or material for another path, run or claim do not answer the item. If no
item is suppliable (only Yoetz limits remain), the reviewer named none
(`semantic_missing_items_rejected`), or
`semantic_missing_already_supplied` says it repeated a request after you published material for it,
report the named limitation instead. Hook-captured tool output never counts as supplied. A named
item is a check limitation, never a finding.

When `missing_for_assessment` contains an `agent_suppliable` item, supplying or repairing that
item is the overall next action before requesting an ordinary receipt. The structured
`overall_next` projection names that action and its bounded target refs (which may be empty for a
global input); `finding_checklist.next` remains a finding-only continuation and does not override
it. When open obligations or undisclosed live failures remain, its action is
`review_recorded_work` with bounded obligation/result/action ids. When only standing,
`structurally_unavailable_on_this_host` or Yoetz-limit items remain, `overall_next` reports
`ready_with_limitations` and the receipt endpoint remains available for acknowledging the
limitation. Such an item stays a disclosed limitation rather than an impossible to-do.

Before choosing to leave a remediable finding as an unresolved limitation, attempt one specific,
authorized resolution: publish the relevant bounded diff or test/failure excerpt, run the
relevant test/doctest/lint check, or repair the named defect. Select the target from the actual
changed files and existing project checks, never invent a command. Record the action and its
result; put exact requested items on an obligation in the effective plan and record their
`attempted_items` on the action. Do not resolve an obligation while its requested items remain
unattempted. If something outside your control prevents the attempt (authority, consent,
credentials, or a dependency you cannot obtain), record it as a blocker instead of widening
disclosure, credentials or runtime authority: publish `decision_recorded` naming the obligation in
`affected_obligation_ids` with the exact statement line
`yoetz-blocker:<authority|consent|credential|dependency_unavailable>` and a rationale. Missing or
inconsistent data the task says is recoverable, a failing test, or a result that looks infeasible
is not a blocker: deliver a best-effort result in the requested form and disclose the assumption.
Yoetz cannot verify a blocker: the next Stop asks you once to re-confirm it, and the closing review
checks it against the task and may challenge it. Only then report the remaining limitation or narrow the claim. `respond` rejects an `acknowledged` answer to an
AI-powered review finding unless `evidence_refs` cites evidence or a result recorded after the
finding (`resolution_attempt_required`); the result of the blocked attempt counts (outcome
`failure` or `partial`: there is no `blocked` outcome). An acknowledgement or
“limitation accepted” is not a repair, a verification result, or a finding resolution. Recheck after a material repair, and
avoid another identical check when the same content is still unavailable. After an
`insufficient_packet` result with no material repair to publish, go to the receipt and disclose
`semantic_packet_insufficient`; the `deterministic_only` fallback is only for optional review that
returned `unavailable` or `timeout`.

The reviewer verifies from what its packet carries. When a completed review other than
`insufficient_packet` raised nothing about verification whose readable output the packet carried,
do not re-run or re-publish it while the work it verified is unchanged; answer a finding by
repairing the defect or supplying the exact artifact it names. A reviewer request never authorizes
installing or downloading a toolchain or package, network access, or another environment change:
record the unavailable runtime or package as a `yoetz-blocker:dependency_unavailable` decision. A `ledger_stale_or_incomplete` finding
whose only subjects are Yoetz check records, or earlier findings of that kind only about such
records, is answered by the completed review recorded after it, so `acknowledged` needs no new
attempt; any other kind, even one citing only a check, and a finding naming any obligation, claim,
response, or work record, or restating a finding about the work, still does. After repairing a
finding, run at least one re-review in the same mode before the receipt.

Findings form a to-do list that ends: each is `open` or final (`verified_resolved`, `acknowledged_not_done`, `rejection_accepted`), and a final item is never re-reviewed. Final states, `finding_terminal`, the `finding_checklist` and the review-round budget are in [coverage-and-receipts.md](coverage-and-receipts.md).
