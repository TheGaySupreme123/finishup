# Publication topic

Read this topic before the first `publish_work` or when deciding whether a transition, result,
evidence item, obligation, or claim belongs in the ledger. Publish the smallest material,
state-bound facts needed for another participant to understand and check the work.

Publish a bounded initial plan and its explicit obligations before substantive work. After bounded
exploration and before the first material edit, publish one `plan_revised` refinement; map
instruction requirements to testable obligations and carry, supersede, or waive earlier obligations explicitly.
Each obligation's `source_refs` cites the task-statement event (see `startup.md`), and its
`requested_items` name the files and commands the request names. `source_refs` cannot change on
an existing obligation: to map a missed requirement, publish a new obligation.
Then publish material transitions, results, evidence, and a completion claim. Keep one transition together in a small
batch. `work_closed` closes work; a receipt never does. Every retryable write carries its
idempotency identity and expected frontier. Reuse exact request and event ids only for the allowed
same-body recovery path.

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
in `limitation_refs`, and the named in-scope obligations in `obligation_refs`. Mirror
`evidence_refs` and `artifact_refs` exactly where the event family requires it. Record every
requested item attempted on `action_recorded.attempted_items`; it does not belong on a claim.

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
`yoetz:test-change:<action_id>:sha256:<path_digest>`. `<action_id>` is the exact edit action id;
`<path_digest>` is `sha256:` plus the lowercase SHA-256 of the captured path's UTF-8 spelling. Do
not rely on free-form prose or repeat the raw path: generic prose does not clear the structural
edit finding.

Before replacing evidence or a claim, read `status`, cite IDs from your own publication, and link
the replacement with the prior effective claim. A claim is an assertion, not a conclusion. Read the
complete event bodies and field ownership in [`publication-policy.md`](publication-policy.md) and
use [`request-templates.md`](request-templates.md) when schema metadata is missing.
