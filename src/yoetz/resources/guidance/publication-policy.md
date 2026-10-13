# Publication policy

Use the small `publication.md` topic through `read_guidance` for ordinary materiality, evidence,
and claim decisions. This complete document remains authoritative for event families and field
rules.

## Materiality checklist

Publish a fact when it changes an independently reviewable work package, a requested outcome, an obligation, a decision, a material attempt, a result, evidence, a claim, a plan, or a finding response. Keep routine navigation, searches, formatting, generated-file writes, repeated status reads, tool chatter, and per-file bookkeeping out of the ledger.

For a large inventory, create obligations per coherent work package. Publish one bounded manifest evidence item for its leaf files and one material package transition. Do not create one obligation or routine event per file.

## Cadence

Publish one batch per material transition, roughly one to eight events. A normal session is a handful of batches: the plan and its obligations, each independently useful result with its evidence, the completion claim, and any finding response. It is not one batch per file, per tool call, or per message.

State-sensitive families require `expected_frontier`. Read it from `status` and include it in the
batch; omitting it returns retryable `expected_frontier_required` without writing an operation.
The guard is task-scoped. Publication tolerates a held frontier when every intervening record is
observation-authored and then appends at the real head. Check acquisition applies the same suffix
predicate but freezes the case at that real head. Receipt may instead stay pinned to the supplied
frontier only when it names the exact ledger prefix and the observation-authored suffix contains no
finding; its append repeats that finding-free check. Any other motion conflicts. Use the returned
repair facts for a retry rather than guessing a replacement frontier.

These are not publishable transitions: reading or searching, running a command whose result you already expect, formatting, regenerating a derived file, repeating a status read, or republishing state that has not changed since the last accepted event. When in doubt, ask whether an independent reader of the ledger alone would conclude something different without the fact.

## The sixteen event families

- `session_opened` — establishes the recorded session; it does not prove workspace access.
- `session_resumed` — records a resume assertion; it does not prove continuity outside the ledger.
- `plan_published` — records the current plan; it is not completion.
- `plan_revised` — records a material plan change; it does not erase the prior plan.
- `obligation_published` — creates a requested or derived obligation; it is not evidence.
- `assignment_recorded` — attributes a bounded assignment assertion; it is not authenticated authorship.
- `decision_recorded` — records a decision and rationale summary; it is not hidden reasoning.
- `action_recorded` — records a material action assertion; it does not prove the action occurred.
- `evidence_recorded` — links bounded evidence identity; it does not upgrade its provenance.
- `claim_recorded` — records a claim to be checked; it is not a verdict.
- `result_recorded` — records an independently useful result assertion; it is not automatically accepted.
- `finding_recorded` — records a local-check or AI-powered review challenge; it is not
  self-resolving.
- `response_recorded` — records a response to a finding; it does not erase the finding.
- `check_recorded` — records a check at one frontier; it becomes stale after material change.
- `redaction_recorded` — records a bounded redaction fact; it does not prove forensic erasure.
- `receipt_recorded` — records derived completion wording and limitations; it is not proof of the work.

## Obligations, evidence, and claims

An obligation names what must be satisfied. Evidence is a bounded, provenance-labeled reason to believe something about it. A claim states a conclusion. Link them explicitly; do not substitute a file list for an obligation or a claim for evidence.

### Digest subjects and provenance


## Discover evidence before authoring replacements

Before publishing evidence for a material claim, check what already exists instead of re-authoring
it. Cite the `evidence_id`s you already published: they are in your own `publish_work` requests, and
each accepted result confirms the events were recorded. `status view=evidence` with
`filter.author=mine` lists exactly the items you published in this session, with their descriptions
returned to you. Find native captures with `filter.strength=immutable_snapshot`; every row names its
`publication_channel`. Preserve the view, filter, frontier and original `limit` with each cursor;
changing page size starts a fresh query with no cursor. Cite a native capture only when a structural
link you can read ties it to the claim: a `status view=results` row whose `evidence_refs` names it,
with that result's `action_id` and `outcome`, or a matching subject-state or byte digest. A captured
object ID alone is not a typed provenance label or evidence of relevance; if no structural link
establishes the relation, leave it unknown.

A `description` or `reference` returned as omitted with `local_disclosure_not_authorized` is a
privacy setting, not missing evidence: the item still exists, and republishing it does not reveal
it. Host-observed and other writers' descriptions stay omitted unless the owner grants
`evidence_excerpt` to agent context. Walk the unfiltered list and match on descriptions only when
the current projection shows them; never page through every item to match prose the projection
omits.

Reuse suitable existing native evidence IDs directly in the claim's `supporting_refs` and relevant
result evidence references. Do not replace matching observed bytes with a duplicate
`caller_asserted` digest-only placeholder. Publish only genuinely missing bounded assertions;
ordinary publication cannot mint `observation_captured` provenance. A published caller-asserted
digest stays an unverified provenance label that the receipt discloses with a count; it raises no
finding, and more digest-only items cannot upgrade it.

Interpret limitations per item: `content_unselected` means a retained kind was not selected;
`evidence_content_digest_only` retains identity without content; `content_capture_unavailable`
means capture is unavailable for the affected input; `semantic_case_content_over_item_limit`
bounds or clips that item. An aggregate union of those gaps does not mean no native content
reached review. A selectable excerpt proves what was observed, not command success or correctness.

For example, a synthetic inventory may span two pages: a matching source snapshot, an unrelated
stale snapshot, matching test output, a digest-only documentation item and an oversized diff.
Reuse the matching source and test IDs; exclude the stale item; disclose the documentation limit
and the diff's clipping independently. Check the selected review input and final receipt before
claiming that all needed content was reviewed. Acknowledging an evidence finding does not repair
its basis: supply admissible evidence or retain an explicitly limited receipt.

Every newly published `evidence_recorded/1.1.0` payload that includes `content_digest` must also
include a closed `digest_binding` object:

- `subject` names the exact byte class that was hashed;
- `content_availability` is `captured`, `digest_only`, or `withheld`;
- `byte_count` is the size of the exact hashed byte sequence;
- `provenance` is `caller_asserted` for ordinary cooperative publication.

The closed subjects are `approved_check_receipt`, `artifact_bytes`, `bounded_excerpt`,
`command_stdout`, `import_report`, `source_diff`, `static_analysis_report`, `test_report`, and
`test_stdout`. The subject must be compatible with `evidence_kind`. In particular,
`evidence_kind=test_result` accepts test output/report, static-analysis report, or an approved-check
receipt. It does not accept `source_diff`. Publish a source-diff digest as `evidence_kind=artifact`
with `subject=source_diff` instead.

`captured` requires the mirrored `captured_object_id`; `digest_only` and `withheld` forbid one. A
digest proves byte identity only. It does not prove that a command ran, that its exit status was
successful, that Yoetz inspected the content, or that the evidence supports a claim. `description`
is caller-authored narrative and is never treated as the bytes identified by `content_digest`.

### Making a change reviewable

When AI-powered review is expected, first cite native captured evidence that already covers the
change: `status view=evidence` with `filter.strength` set to `immutable_snapshot` narrows the
inventory to captured records, and a matching native ID goes directly into the claim's
`supporting_refs`. When no native record covers it, put the smallest problem-local changed hunk or
test slice in the `description` of one evidence record. The review excerpt shown to the reviewer is
that `description`.

You may also publish the matching `content_digest` with its `digest_binding` for byte identity; the
digest identity facts then travel alongside the excerpt as excerpt provenance. Ordinary publication
records that binding as `caller_asserted` with `digest_only` availability: Yoetz did not capture or
verify those bytes. This is a disclosed provenance label, not a finding. It raises no local finding,
and the receipt names once, with a count, the cited evidence items whose caller-asserted digests
Yoetz did not verify. No response, recheck, or further publication changes that label, so do not
publish more excerpts or digests to clear it. A digest-bound record without a `description`
contributes only its bounded provenance facts, so the reviewer sees identity but no content.

The excerpt is truncated to at most 4,096 UTF-8 bytes, silently and possibly mid-content. Keep the
slice within 4,096 UTF-8 bytes so the reviewer receives it intact; `description` itself accepts up
to 8,192 characters, so the field limit does not protect against excerpt truncation.

When the review recipe selects diff excerpts, Yoetz itself also reads the task's repository at
check time and gives the reviewer that **check-time change** first: committed and uncommitted
changes from the commit the task started on, plus untracked files Git does not ignore, including
edits made by scripts or commits that no hook captured. Untracked files already there when the task
started and unchanged since are left out, a nested repository's own change is included the same
way (when the header says its untracked files are named but not shown, give the reviewer evidence
for one it must read), and up to
four files the task statement names that the task only reads (a specification, the source being
ported) travel beside it, so they need no evidence of their own. Yoetz redacts secret-shaped content in that
check-time change, so no deliverable ever needs hiding: never git-ignore, exclude (including
`.git/info/exclude`), stash, or move a requested output for privacy. Do not paste or digest the whole diff for the reviewer;
use `description` for the problem-local hunk or test slice the claim depends on. The
`check_time_change_unavailable`, `check_time_change_base_unavailable`,
`check_time_change_truncated` and `check_time_change_redacted` coverage gaps name what that change
could not show.

Cite the evidence id in the claim's `supporting_refs`. Evidence referenced only from
`result_recorded.evidence_refs` does not qualify for excerpt selection under linked-subject
relevance unless that result is linked by a readable response to an unresolved in-scope finding.
For a repair recheck, link the repair evidence directly (or through that result) in the finding
response; the next packet prioritizes it within existing limits. A response is not proof of repair:
a semantic finding still requires a later successful, assessable semantic check to resolve.

Do not submit `approved_check` or `import_observed` provenance through ordinary publication. Those
values are reserved for the capability-proven service path and trusted importer. Historical
`evidence_recorded/1.0.0` records remain readable byte-for-byte; a historical digest without a
binding is reported as legacy/unknown and cannot silently satisfy a new completion claim.

### Claim correction and limitation linkage

Use `claim_recorded/1.1.0` for new claims and send both new arrays, even when empty. Completion
claims must explicitly send `obligation_refs`: intended obligation IDs, or `[]` for intentional
empty scope. `supporting_refs` does not declare scope. Obligation support with empty scope is
rejected; consciously declare those IDs in scope or remove them from support. Empty scope remains
coverage-incomplete and does not assert that the plan's work is complete. Keep admissible
evidence, successful results, and resolved obligations in `supporting_refs`; put partial or failed
result ids in `limitation_refs`.
To correct an append-only claim, publish a fresh claim id and name every prior effective claim it
replaces in `supersedes_claim_refs`. Restate corrected `obligation_refs`, overlapping every target
whose scope is nonempty. An already accepted empty-scope target can be replaced by either explicit
empty or populated scope. For C0 with empty scope and a later scoped C1, name **both** actual IDs in
the sorted `supersedes_claim_refs` of C2 and supply the intended scope; superseding only C1 leaves
C0 effective. Retain every relevant limitation and make a real correction, not an identical claim
under a new ID. The prior
event stays immutable and visible as history, while checks and receipts evaluate the replacement
as current.

Before append, read `candidate_findings`, `history`, and `results`, then dry-run the exact
replacement. Preflight rejects a missing or already-superseded target, a different claim kind,
disjoint scope against a populated target, omitted completion scope, misplaced obligation support,
a success/unrelated limitation, a non-success result in
`supporting_refs`, or an incomplete set of relevant partial/failed results. Do not use
`disputes_refs` or `decision_recorded.supersedes_event_id` as claim supersession; those fields keep
their existing contradiction and decision-history meanings.

## Repair then finish

Use this bounded sequence for a material repair or closure. It applies to the six existing
operations and does not add a composer or a new protocol field:

1. Read current `status` and retain its returned frontier. Before replacing evidence or a claim,
   cite the evidence IDs you published and find native captures with a filtered
   `status view=evidence` read, preserving its filter and original `limit` with every cursor.
   Reuse only native IDs a structural link ties to the claim; a missing MCP capture call, one
   digest-only item, or one clipped item does not establish that all native evidence is
   unavailable.
2. Publish the actual repair results, corrected evidence or claim, and any required plan revision.
   Do not fabricate success or infer completion scope from the prompt. A feedback obligation is in
   effective scope only after a supported `plan_revised` event or an exact next-version
   `plan_published` restatement includes it; a stored or resolved obligation alone is insufficient.
3. Before the final check, read `status view=findings` and disposition each finding with
   `disposition: none`, with the current expected frontier and a `finding_frontier` at or after the
   finding's own record: the item's `finding_frontier` when status carries one, otherwise the
   current status frontier. No historical frontier search is needed. A response is a disposition,
   not proof of repair. Observation-authored non-actionable findings need no response.
4. Run the final check deliberately. Select `semantic_required` when the user, effective policy, or
   named acceptance criterion requires AI-powered review. If relying on the configured default, omit
   `mode`; use `semantic_if_configured` only when review is known to be optional. Reserve
   `deterministic_only` for explicitly local/structural work or a deliberate no-egress choice, and
   disclose an unmet required review.
5. Respond only to findings that check returned that are still unanswered, then read
   `status view=findings` with `filter.include_resolved: true` and actual `resolved` state. “Not
   returned” is not “resolved”: call a
   finding resolved only when a later qualifying check recorded it. Those responses, acknowledging
   an observation-authored non-actionable finding, and `work_closed` need no recheck. If a recorded
   repair, a response to another older finding, or any other material record follows the check,
   run another check before requesting a receipt.
6. Request `receipt`, then publish `work_closed` when the work is complete. Read `closure_readiness.unanswered_finding_count` and
   `closure_readiness.receipt_blocking_finding_count` (findings to do plus acknowledged requirements), then report a scope-first summary of what was
   verified/not verified alongside the receipt's checked frontier, AI-powered review status/reason,
   and material coverage limits. Never lead with a bare zero-findings count. After
   one current-state recheck still fails to qualify, stop repeating an unchanged check, continue any
   distinct authorized repair, and disclose the remaining blocker.

The optional `yoetz closure-prepare --session-id <returned-session> --writer-id <returned-writer>`
command is read-only preparation. It may inventory obligations, results, evidence, findings, and
history and draft one explicit phase, but it never invents attempts, evidence, finding responses,
obligation satisfaction, or completion. `--output <file>` saves the result for repeated reading;
choose a path outside the working repository. Review and submit each draft at the new frontier.

When a requested item is not observed as attempted, do not copy its unchecked value into
`attempted_items` merely to make the draft validate. Correct the assertion or use a supported
obligation revision with rationale. When recording GitHub Actions evidence, the workflow run API
`id` is the run identity; `run_number` is a separate display counter and must not be substituted for
that identity.

## Operation-specific recovery and templates

Keep recovery requests tied to the operation that produced them. `start` has no `writer_id`; use the
returned `session_id` and `writer_id` on later calls. A `publish_work` preview uses `dry_run: true`
and the same `request_id` for the real append. A timeout or unknown write outcome uses the exact
start replay branch below when it is a `start` response without route ids; otherwise use `status
view=operation` with `filter.operation_request_id` set to the exact write request ID:
`absent` permits one replay of the exact original body and request ID (an `absent` check page with
an `admission` stage was refused before admission: replay after its `retry_after_ms`, at most three
times), `complete` uses the stored outcome without replay, and `pending` permits replay only after an exact typed continuation and
its required approval complete. A pending operation without a continuation, `quarantined`, or an
unknown state is retained and reported rather than guessed.

The operation view requires both `session_id` and `writer_id`. If a `start` response is lost before
those ids are returned, do not invent them or issue a fabricated status query: replay the exact
original `start` body once with its same `request_id`; the start idempotency path returns the stored
result or a typed boundary. Once the required route ids are known, use the exact operation filter
above.

The same start exception applies to a typed `OPERATION_PENDING` start result that has no returned
session or writer: replay that exact start request once rather than fabricating ids for an operation
query.

Pagination is a read operation: a retry may use a new read request ID, but a cursor continuation
preserves the original view, filter, frontier, and `limit`. Changing `limit` starts a new query with
no cursor. A `respond` request carries `finding_id`, `finding_frontier`, `disposition`, and `reason`;
a `receipt` request carries its own receipt fields. Never copy response fields into a receipt, and
never invent a finding disposition when a host reports that the wrong operation template was used.
The complete operation bodies remain in `yoetz://guidance/request-templates.md`.

Newly minted caller IDs (`request_id`, event/object payload IDs, and claim IDs) use the required
prefix plus a fresh lowercase UUID v4. Existing returned evidence, obligation, claim, and finding
references remain exactly as returned; retries reuse the original request/body identity. Use the
exact closed enums and field-owning event family from the current schemas; do not handcraft,
uppercase, or derive an ID from a sequence, run number, digest, or timestamp.

## Declare completion scope in the plan

The effective current plan must distinguish obligations from an intentional empty scope. Normally,
publish sorted-unique `obligation_refs` (ascending ASCII, unique members — the same set-order rule
as `obligation_ids` and every other canonical set field). If none apply, set `no_obligations_reason` to exactly one
closed value:

- `no_material_change` — the work makes no material change;
- `single_atomic_change` — one atomic change has no independently useful obligation split;
- `exploratory_scope_unknown` — exploration cannot yet declare material obligations.

Do not send a reason beside effective obligation refs. A `plan_revised` event restates the current
declaration: include the current reason when the revised effective ref set is empty, or omit it to
clear an earlier reason. When a mid-task obligation requires a full append-only restatement rather
than a change disposition, publish `plan_published` at exactly the current plan version plus one;
its refs and optional empty-scope reason become the complete effective declaration. A duplicate
root or version gap makes the chain unreadable. Yoetz never infers obligations from prompts, source
code, workspace state, or plan prose.

You decompose the request; Yoetz checks the link. When a task statement is recorded and the
effective plan declares obligations, at least one of them must name the statement event in
`source_refs`, or every whole-task check returns the agent-actionable `task_requirement_unmet`
finding (subject: the statement event) and readiness lists `instruction_requirement_unmapped`.
Cite it from every obligation that maps a stated requirement. The rule checks presence of the
link, not that every requirement is mapped: an obligation per stated requirement is your duty, and
AI-powered review, when it runs, compares the plan with the statement.

An empty-scope reason clears the `no_obligations_declared` readiness blocker, but it does not buy a
clean completion check. A completion claim over zero declared obligations remains
coverage-incomplete: `completion_scope_undeclared` without a reason or
`completion_scope_declared_none` with one. With a task statement recorded, that completion claim
also returns `task_requirement_unmet` until you either publish statement-sourced obligations or
record a `decision_recorded` whose statement holds the exact line
`yoetz-no-material-work:<statement event id>` with a rationale. The decision counts only while the
task records no edit action and the check sees no changed file in the workspace (shell writes
count); a task that changed files must map the work to obligations.

## Obligation resolution

<a id="obligation-resolution"></a>

Resolving an obligation is a one-way `open → resolved` state transition, not an edit. Publish a second
`obligation_published` event for the **same** `obligation_id` that:

1. repeats every meaning field from the open obligation **byte-for-byte**: `description`,
   `acceptance_criteria`, `evidence_expectation`, `requested_items`, and `source_refs` (omit a field
   only when the open event also omitted it);
2. sets `status` to `resolved`;
3. supplies the final bounded `resolution_evidence_refs` (one or more evidence or result ids).

Only `status` and `resolution_evidence_refs` may differ. Changing meaning fields, republishing
`status: open` for an open id, or re-resolving an already-resolved obligation is rejected with
reason `obligation_resolution_mismatch` and invariant `meaning_fields_must_repeat` (or
`open_to_resolved_only` for an invalid status transition). A resolved obligation whose work no
longer holds may be reopened (`status: open`) or acknowledged as not done
(`acknowledged_not_done` with its reason, on `1.1.0`), repeating every meaning field. The
public error names the mismatched schema field names only — never their values. A worked open +
resolution pair lives in the `publish_work` tool input schema `examples` entry. Complete request
bodies remain available at `yoetz://guidance/request-templates.md` if a host drops schema examples.

## Requested items and attempt accounting

<a id="attempt-accounting"></a>

An obligation's `requested_items` entries are objects; each entry's `value` is the exact item
string the obligation asks for. Attempt accounting for those items lives in exactly one place:
`attempted_items` on `action_recorded.payload`. No other family admits the field — a claim in
particular never carries it; claims link evidence with `supporting_refs` and obligations with
`obligation_refs`.

When you attempt a requested item, copy its exact `value` string — unnormalized, unparaphrased —
into `attempted_items` on the `action_recorded` event that attempted it, whether or not the
attempt succeeded. A requested item with no matching attempted entry is reported as never
attempted, so dropping the field to satisfy a validator silently erases the attempt record.
Two more structural payload rules travel on their own families: `decision_recorded.authority`
is a structural actor id (never approval prose — that belongs in `rationale`), and `action_kind` is
the closed enum `command`, `edit`, `research`, `review`, `other`, where source or file
modification is `edit`.

## Subject state and freshness

Bind change-sensitive evidence to the exact subject state or frontier it concerns. If a material dependency changed or its state is unknown, mark the evidence stale or limited. Absence of visible source is not evidence that nothing changed.

## Batching, sequencing, and retry

Batch facts that belong to one material transition. Preserve writer sequence and expected frontier.
For a write timeout, use the operation-specific recovery above: query the exact operation filter,
replay once only for `absent`, use the stored `complete` outcome, and follow an exact typed
continuation before replaying a `pending` request. A read timeout gets a new read request ID with
the same intent. Never manufacture a replacement event merely because a response was lost.

A `status` read and a dry run before a publish are optional, not a ritual: the write is all or nothing. A rejected batch appends nothing and names what stopped it, not every error (for drafts, the first rejected draft and its field): fix it and resubmit, since another bad draft surfaces only on the next attempt, as it would in a dry run. An accepted write returns the new frontier and the accepted event ids. Use `dry_run: true` when you are unsure a batch will be accepted (a claim correction, a plan revision, a large batch); the preview is not evidential and must not be cited as a check, publication, or coverage source, and the real publish reuses the same `request_id` with `dry_run` omitted or false. Before resolving an obligation that names requested items, account for each exact value that has no attempt yet. When you need the picture, call `check` with `mode: inspect` instead of several status reads: it records nothing and returns what is left with whose move each gap is (requested items not attempted are named by index), what the hooks observed since the last check, and whether each obligation's resolution evidence links to its declared deliverables or commands. Your host approves it as it approves any `check` call; if the host holds or refuses it, nothing is pending in Yoetz, so read `status` instead. `status view=obligations` shows the exact `unattempted_items` values.

Worked examples for each ordinary publishable family — and a cross-linked
action/result/evidence/claim batch — live in the `publish_work` tool input schema `examples` entry
and as complete fallback bodies at `yoetz://guidance/request-templates.md`. Example `occurred_at`
values are illustrative shape only; do not copy them into live drafts.

### Event draft skeleton

<a id="event-draft-skeleton"></a>

A host may drop the tool schema `examples` entry, so the envelope shape is restated here. Every
draft carries exactly these seven keys, and nothing else:

```json
{
  "event_id": "evt_<uuid4>",
  "schema": { "name": "<family>", "version": "1.0.0" },
  "occurred_at": "<RFC 3339 UTC, millisecond precision>",
  "causal_parents": [],
  "payload": {},
  "artifact_refs": [],
  "evidence_refs": []
}
```

`schema.name` is the family discriminator and selects the payload shape. There is no top-level
`event_type`, `family`, or `type` key. The ordinary publishable families are `plan_published`,
`plan_revised`, `obligation_published`, `assignment_recorded`, `decision_recorded`,
`action_recorded`, `result_recorded`, `evidence_recorded`, and `claim_recorded`.

The illustrative `event_id` and `occurred_at` above are shape only: mint a real UUIDv4 and use the
best real time available, exactly as for the schema examples.

### Set-valued reference lists

<a id="set-valued-lists"></a>

Every canonical set field is admitted only when its members are unique and already in ascending
ASCII order. The kernel does not sort them. JSON Schema `uniqueItems` does not express this order
rule, so a bridge-side schema hint cannot catch it. Authoring order (the order ids were minted) is
the usual failure. A rejection names `unsorted_set_field` or `duplicate_set_member` at the owning
field. A one-element `dry_run` subset is trivially sorted and cannot locate this rule.
Sort the named field as ASCII bytes and retry; do not reverse-engineer order from a one-member subset.

The rule applies to payload lists including `obligation_refs`, `obligation_ids`,
`affected_obligation_ids`, `supporting_refs`, `limitation_refs`, `supersedes_claim_refs`,
`disputes_refs`, and `source_refs`, and to envelope lists `causal_parents`, `evidence_refs`, and
`artifact_refs`. Publish sorted-unique members; do not rely on the kernel to reorder them.

### Reference mirrors

<a id="reference-mirrors"></a>

Some families mirror a payload reference into the draft envelope, and the two must match exactly —
the same ids in the same ascending ASCII order, with no extra and no omitted member. A mismatch is
rejected with reason `ref_mirror_mismatch`, and the public error names the envelope field:

- `result_recorded` and `response_recorded`: envelope `evidence_refs` equals the payload's own
  `evidence_refs`, or both are empty.
- `evidence_recorded`: envelope `artifact_refs` is exactly `[captured_object_id]`, or empty when
  the payload declares no captured object.
- `receipt_recorded`: envelope `artifact_refs` is exactly the payload's `receipt_object_id`.
- `redaction_recorded`: envelope `artifact_refs` equals the payload's own `target_object_ids`.

## Event time claims

`occurred_at` is a caller assertion of when the event happened. Never guess it or round it to a convenient future value: use the best real RFC 3339 millisecond UTC time available. If the exact time is unknown, use an honest bounded approximation and understand that it remains a claim — the service does not check outside clocks and does not reject far-past, future, or out-of-order caller times.

The service independently stamps `accepted_at` on acceptance. Both values are durable and bound into the entry digest. Ledger order, causality, supersession, optimistic concurrency, and receipt freshness use ingestion sequence and frontier, not caller time. `status` with `view=history` returns both clocks plus `occurred_at_consistency` on each item. The closed classification is `within_forward_skew_allowance` when caller time is no more than five seconds ahead of service acceptance and `ahead_of_forward_skew_allowance` otherwise. It exposes only that exact comparison; it does not verify the caller timestamp or make wall clock authoritative. The same two clocks and classification are carried into a new check's bounded frozen timeline so AI-powered review can see forward drift.

## Multi-agent work

Publish bounded assignments in the parent task, and let each child publish with its own returned
session and writer in its own task. Pass the complete `attach_handle` privately to the intended
child; never publish it as evidence or structural prose. Treat delegate summaries as claims. Link
their accepted evidence separately and record a decision when resolving a contradiction.

`child_accepted`, `child_rejected`, `child_written_off`, and `delegation_cancelled` target a direct
child from the parent. `work_closed`, `work_cancelled`, and `work_written_off` describe the current
task. These are ordinary `publish_work` events; keep mutually exclusive transitions in separate
requests. Service facts such as `delegation_declared`, `work_abandoned`,
`child_dependencies_recorded`, and `coordination_context_recorded` are not ordinary publication
authority, even if an actor field or payload claims to be the service.

An overlap notice or ordinary file obligation alone declares no coordination obligation. Publish
the obligation and an explicit `coordination_obligation_declared` event binding its real ID to the
admitted detection, project, recipient task, and current membership generation. Then record
that same binding and evidence in
`coordination_disposition_recorded`. Choose `shared_work`, `sequencing`, or `scope_revision` to
record the agreed remedy. An acknowledgement through `respond` is only a finding response;
it does not supply the coordination remedy or resolve a finding. Recheck the repaired record.

## Forbidden content

Never publish chain-of-thought or hidden reasoning; full prompts, transcripts, or conversation history; credentials or secrets; whole files, repositories, or broad unrelated source. When AI-powered review would otherwise be blind, publish only the smallest problem-local changed hunk or enclosing symbol needed, with source, state, and coverage labels. For material completion checks, publish the smallest state-bound diff/symbol and the directly relevant test or failure excerpt; never rely on self-asserted completion prose alone.

## Mini-flows

### Code change

Publish one obligation for the behavior, one material implementation result, a bounded changed-symbol digest or excerpt, and focused test evidence. The implementing action uses `action_kind: edit` and carries the exact `attempted_items` values for the requested items it attempted. Do not publish the repository or every edit.

### Research

Publish the question, source identities, bounded supported and contradicted claims, limitations, and the conclusion. Do not paste articles or browsing transcripts.

### Plan revision

Publish the original obligation, the material new fact, and one plan revision explaining which outcome or dependency changed. Restate the current empty-scope reason or omit it to clear the declaration; omission never inherits the prior reason. Routine schedule adjustment needs no event.

### Conditional output

A file the request asks for only under a condition (a quarantine log written only for a malformed
input) is runtime behavior: declare a `change` item that names the condition and the path, plus the
source files that implement it as `role: output` `file` items. If you already declared it as a
`file` and the final state does not meet the condition, `requested_output_absent` names it:
publish the corrected obligation, supersede the old one with `plan_revised` (`change: superseded`,
`reason`, `replacement_obligation_ids`), record the work with the new item values in
`attempted_items`, resolve the new obligation, and replace the completion claim with one naming it.
Never write an empty or placeholder file, or change when the deliverable writes the file, to
satisfy the declaration. A file the request asks for unconditionally is never re-modelled this way.

### Large generated inventory

For 100 files, group them into independently reviewable packages, record partial package status when useful, attach one bounded member manifest per completed package, and publish one final package transition. One obligation or routine event per file is invalid.

### Check completion scope before append

To see these diagnostics before appending, preview a completion claim with `publish_work
dry_run=true`. A `completion_claim_outside_plan` gap means its `obligation_refs` extend beyond the effective plan;
`completion_plan_not_claimed` means declared plan refs remain outside that claim. These diagnostics
also appear after append and in status/check/receipts; they never auto-include obligations.

To add a newly intended obligation, publish `plan_revised` with `plan_version` equal to the current
version plus one, `supersedes_plan_version` equal to the current version, and an
`obligation_changes` entry `{"obligation_id":"<actual new obligation ID>","change":"carried"}`.
Alternatively publish `plan_published` at exactly the next version with the complete sorted-unique
`obligation_refs`. Supply the normal bounded reason/summary and envelope fields. Preview the plan
and claim together before committing. To narrow/correct an existing claim, publish
`claim_recorded/1.1.0` and name its actual ID in `supersedes_claim_refs`.

A partial completion claim remains permitted, but the omitted plan scope is not covered by that
claim even if those obligation rows are resolved. Separate partial claims do not automatically
combine into a whole-plan completion claim. Explicitly replace older completion claims after
scope changes when their assertions no longer describe the intended current scope. A later
`waived` plan change removes an obligation from the current plan but leaves an older effective claim
intact; that claim therefore continues to report `completion_claim_outside_plan` until superseded.
