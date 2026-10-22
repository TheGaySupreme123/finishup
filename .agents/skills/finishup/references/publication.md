# Publication topic

Read this topic when a result or error names it, or when deciding whether a transition, result,
evidence item, obligation, or claim belongs in the ledger. Publish the smallest material,
state-bound facts needed for another participant to understand and check the work.

Follow [startup.md](startup.md) for the plan: after bounded exploration, before the first material
edit, map each requirement to a testable obligation and refine the current plan with
`plan_revised`. It owns versions, immutable meaning and statement-sourced obligations. Then publish
material transitions, results, evidence and the completion claim, one transition per small batch.
Close with `work_closed` as [receipt.md](receipt.md) says; a receipt never closes work. A `publish_work` body may omit `request_id`,
`expected_frontier`, each draft's `event_id`, `occurred_at`, `causal_parents`, `artifact_refs` and
`evidence_refs`, and, on `claim_recorded/1.1.0`, an empty `limitation_refs` or
`supersedes_claim_refs`, and a plan's empty `obligation_refs` beside `no_obligations_reason`.
Payload ids and evidence `observed_at` stay yours to send. FinishUP mints a request id for that one
call, mints event ids, records its own clock, copies the payload mirrors, guards the batch with the
frontier it reads when it admits it, and names every filled envelope value in the result's
`server_filled` (an omitted empty claim or plan set is simply the empty set). Every result and error
names that request id. After an unknown outcome, retry by sending that `request_id` with the body:
it replays instead of appending twice. Resending the body without it is never a retry: right after
the same call FinishUP refuses it and names the id, and otherwise it is a new publication. Send a
value only when you need it: an explicit `expected_frontier` (the `frontier` `start` returned for
the first plan, then the `result_frontier` of your last accepted write) also refuses a change made
since you read it; a `causal_parents` entry cites an earlier event id.

## Before you send a batch

Check each line. Each one names the refusal or finding it prevents.

1. Omit `expected_frontier` (guarded at admission), or send the frontier you hold; never `null`
   (`expected_frontier_required`).
2. Every `action_recorded` has a `result_recorded` naming its `action_id`, normally in the same
   batch, with `outcome` `success`, `failure`, `partial` or `unknown` (`action_without_result`).
3. A `result_recorded` lists only `evd_` ids in `evidence_refs`. A `res_` id belongs in a claim's
   `supporting_refs` or `limitation_refs`, or in an obligation's `resolution_evidence_refs`.
4. Each `digest_binding.subject` fits its `evidence_kind`. `artifact` takes `artifact_bytes`,
   `bounded_excerpt` or `source_diff`. `command_output` takes `command_stdout`, `test_stdout`,
   `test_report` or `static_analysis_report`. `test_result` takes `test_stdout`, `test_report` or
   `static_analysis_report`. `research_source` takes `artifact_bytes` or `bounded_excerpt`.
   `other` takes `bounded_excerpt`.
5. Write each reference once. FinishUP sorts and de-duplicates reference-set fields (never text
   lists such as `alternatives` or `attempted_items`) and copies the envelope mirrors; a mirror
   you do send must match the payload (`ref_mirror_mismatch`).
6. `attempted_items` appears only on `action_recorded`, and each value is copied exactly from a
   `requested_items` `value`.
7. An obligation is resolved once. Do not republish a `resolved` obligation as `resolved` to add
   evidence (`obligation_resolution_mismatch`); cite the new evidence from the claim. If its work
   no longer holds, republish it `open`, or `acknowledged_not_done` with the reason, repeating
   every meaning field.
8. Omit `occurred_at`; FinishUP records its clock. Never run `date` for it. An `occurred_at` you
   send is your claim. `evidence_recorded` always needs `observed_at`: when you saw the evidence,
   as a time you already hold (a time the output printed, or else the `accepted_at` of your last
   accepted write, an earlier bound rather than the moment you saw it), never a template's example.
9. A file the task writes only under a condition is a `change` item that names the condition and
   the path. Never create an empty or placeholder file for it.

Do not publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history,
credentials, secrets, whole files/repositories, or broad unrelated source. A digest is provenance,
not content inspection. Use bounded excerpts with the directly relevant file, symbol, test, or
failure; user-controlled titles, paths, prompts, and model output never become structural table or
error text.

When hooks record an edit that stales verification or a verification run with a known outcome,
a completion claim must cite verification recorded after the latest such edit, if any. Cite it through
`supporting_refs`, `limitation_refs` for a limiting result, or the resolution evidence of a resolved
obligation the claim names; otherwise the check returns `claim_without_admissible_evidence`, which
a recheck alone does not clear. A hook-observed command result or the captured output it links
counts unless its runner class is `exploration` or `vcs`: test, build, lint, typecheck and
unclassified commands can qualify. The fallback is your own admissible command result or
`test_result`/`command_output` evidence, published after that edit; a published exploration or VCS
command does not qualify. An edit's output and a standalone hook capture that no verification run
links do not qualify. An observed run with no exit status can still corroborate that it ran after
the edit; find its `res_` id in `status view=results` and cite it in `limitation_refs`, disclosing
the missing outcome.

For completion scope, put admissible evidence in `supporting_refs`, partial/failed/unknown results
in `limitation_refs`, and the named in-scope obligations in `obligation_refs`. Leave the envelope
`evidence_refs` and `artifact_refs` out: FinishUP copies the payload mirrors. Record every
requested item attempted on `action_recorded.attempted_items`; it does not belong on a claim.
Publish each action's outcome as a `result_recorded` whose `action_id` names it, normally in the
same batch as the action; evidence and decisions do not link an action.

Do not change an existing test's assertion or expectation, rename it, skip it, or delete it to make
the implementation pass. Change pre-existing test code only for broken setup, an outdated fixture,
or an explicitly changed behavior, and record the instruction line and reason. When the user's
request asks for a change to an existing test file (for example "add a regression test in
`tests/regression_test.cc`"), list that path as a `requested_items` entry with `item_kind` `file`
on an obligation whose `source_refs` cite the task-statement event: that structural link justifies
the edit, and the path may be repository-relative or absolute. If the obligation does not exist
yet (the test-edit finding fired), the full repair is: publish a new obligation citing the
statement with that file item, carry it with `plan_revised`, record an `edit` action whose
`attempted_items` list the path with its result, republish the obligation `resolved` citing the observed
verification run after your last edit, and supersede the completion claim with one naming it in
`obligation_refs`; then check. Otherwise, for a justified
pre-existing test edit, put this exact line in a later decision statement, after the edit action:
`finishup:test-change:<action_id>:sha256:<path_digest>`. `<action_id>` is the exact edit action id;
`<path_digest>` is `sha256:` plus the lowercase SHA-256 of the captured path's UTF-8 spelling. Do
not rely on free-form prose or repeat the raw path: generic prose does not clear the structural
edit finding.

Before replacing evidence or a claim, read `status`, cite IDs from your own publication, and link
the replacement with the prior effective claim. A claim is an assertion, not a conclusion. Read the
complete event bodies and field ownership in [`publication-policy.md`](publication-policy.md).
When schema metadata is missing, read
[`request-templates.md#publish-shapes`](request-templates.md#publish-shapes) for the ordinary path;
the page opens with a map from each operation and event family to its section.
