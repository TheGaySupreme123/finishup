# Publication topic

Read this topic when a result or error names it, or when deciding whether a transition, result,
evidence item, obligation, or claim belongs in the ledger. Publish the smallest material,
state-bound facts needed for another participant to understand and check the work.

Publish a bounded initial plan and its explicit obligations before substantive work. After bounded
exploration and before the first material edit, publish one `plan_revised` refinement; map
instruction requirements to testable obligations and carry, supersede, or waive earlier obligations explicitly.
Each obligation's `source_refs` cites the task-statement event (see `startup.md`), and its
`requested_items` name the files and commands the request names. `source_refs` cannot change on
an existing obligation: to map a missed requirement, publish a new obligation.
Then publish material transitions, results, evidence, and a completion claim. Keep one transition together in a small
batch. `work_closed` closes work; a receipt never does. A `publish_work` body may omit
`request_id`, `expected_frontier`, and each draft's `event_id`, `occurred_at`, `causal_parents`,
`artifact_refs` and `evidence_refs`. FinishUP mints a request id for that one call, mints event
ids, records its own clock, copies the payload mirrors, guards the batch with the frontier it reads
when it admits it, and names every filled value in the result's `server_filled`. Every result and
error names that request id. After an unknown outcome, retry by sending that `request_id` with the
body: it replays instead of appending twice. Resending the body without it is never a retry: right
after the same call FinishUP refuses it and names the id, and otherwise it is a new publication.
Send a value only when you need it: an explicit `expected_frontier` (the `frontier`
`start` returned for the first plan, then the `result_frontier` of your last accepted write) also
refuses a change made since you read it; a `causal_parents` entry cites an earlier event id.

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
8. Omit `occurred_at`; FinishUP records its clock. Never run `date` for it. An `occurred_at` or
   `observed_at` you send is your claim: a time you already hold, never a template's example.
9. A file the task writes only under a condition is a `change` item that names the condition and
   the path. Never create an empty or placeholder file for it.

Do not publish hidden reasoning or chain-of-thought, full prompts, transcripts, conversation history,
credentials, secrets, whole files/repositories, or broad unrelated source. A digest is provenance,
not content inspection. Use bounded excerpts with the directly relevant file, symbol, test, or
failure; user-controlled titles, paths, prompts, and model output never become structural table or
error text.

When hooks observe your work, a completion claim must cite at least one hook-observed verification
run made after your last observed edit (find it in `status view=results`), in `supporting_refs`,
or in `limitation_refs` when it failed; otherwise the check returns an agent-actionable
`claim_without_admissible_evidence` finding that a recheck alone does not clear. Only a test or
build run counts, never an edit's output or an exploration or VCS command. When the host recorded
no exit status for that run (a long run that outlived the tool's wait), cite its `res_` id in
`limitation_refs`: it still shows the run happened after your last edit.

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
