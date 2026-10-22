# Review topic

You are the working agent using FinishUP.

Read when a finding, pending review or closing check needs more than the operating card.
A check evaluates only the recorded, readable, frontier-bound packet.

Select `semantic_required` when the user, effective policy, or named acceptance criterion requires
independent AI-powered review. Omit `mode` to run in the task's review mode (below). Use
`semantic_if_configured` only when review is known to be optional. Use `deterministic_only` only for
explicit local/structural work, a semantic-disabled policy, or a deliberate no-egress choice, and
disclose `semantic_review_not_requested` where review is required; never use it merely to shorten a
follow-up.

Host authorization and a FinishUP disclosure decision are separate. A host auto-review refusal or hold
before invocation is not a FinishUP result: FinishUP did not run. Preserve the exact proposed `check`
body and `request_id`; host approval authorizes this invocation only. While pending, do not publish a
completion claim, request a receipt, create a fresh check, or switch mode. After approval, invoke
the same body and request id. After denial, cancellation, or expiry, continue without review only
after the user explicitly chooses that fallback. A host gates an inspection (`mode: inspect`) like
any `check` call, but it requests no review: if the host holds or refuses it, nothing is pending in
FinishUP, so read `status` instead and continue.

`awaiting_human` is nonterminal, neither a gap to disclose nor a retry to spend. Do not create a new
check request. Read `status view=operation` for the original request, show the exact continuation,
and replay it only after the decision. `awaiting_input` likewise waits for the named missing input;
do not infer it from source or stored databases.

A missing repository grant is an authority boundary. If chat authorization is not advertised, use
the exact trusted `finishup --privacy` route; agent chat text grants nothing. A standing grant is
separate from host approval, `confirm_every_request` is one-use, and no dispatch occurs without the
grant. Keep the same request id and never create a fresh request to escape the decision.

`full_restart_required` is an activation mismatch. Fully restart the exact host process and verify
the live route before a new check; it never authorizes egress. Read the check result's coverage and
review status as reported, not as proof that the underlying code is correct. Details and recovery
limits remain in [`coverage-and-receipts.md`](coverage-and-receipts.md#check-mode-and-ai-powered-review-coverage).

When AI-powered review is selected, a check before your first material edit runs local plan checks
only and sends nothing (`semantic_review_deferred_before_first_edit`); the next check after an edit
reviews as configured.
If the work needs no edit and review is required, readiness asks for the closing review instead.
While work is in progress the reviewer judges incomplete work only; its correctness concerns come
back as advisory notes in the review summary, not findings. `agent_criterion_unmet` is a criterion
you set yourself beyond the task's stated scope: fix it, or narrow it with `respond` `acknowledged`
and the reason (a disclosed limitation that does not block); a `finishup-verification-limit` decision
does not narrow it.
If `missing_for_assessment` names an `agent_suppliable` item you can supply, publish exactly that item once, linked to any named target, then `check` again. If it is already supplied, or it is a packet, type or authority limit, go to the receipt and state that specific limit. Only new material counts; tie it to any named target. The captured output of a re-run of the target's exact command FinishUP observed counts only once it reaches the reviewer, so publish the result even after a re-run; a respond counts only when the target is a finding, and a description never does. Output FinishUP adds itself, from a run made before the request, is observed, not something you supplied.
For verification output, cite the run's observed output (its `evd_` from `status view=evidence`) on a result; when FinishUP observed none for the run, publish the result summary as its remedy says. The reviewer reads a summary as your account of the run, not as the output. A file outside the workspace reaches the reviewer only beneath a directory the owner admitted (`finishup privacy input-roots`); you cannot admit one. If a check reports `task_input_outside_not_admitted`, do not copy, move or restate that file into the workspace for the reviewer; name the folder and the command `finishup privacy input-roots add <folder>` to the owner in your final answer.
The reviewer is told to treat the output FinishUP observed from a check you ran as that check's witness, even when the check's own file is outside the workspace: have a check print the values and cases it compares, not only PASS.

When readiness names `closing_review_required`, run `check` with `final_review: true` after the
last material change. It judges stated requirements and outputs against the task.
Answer each open AI-powered finding with `respond` and a reason (optional for `decision_needed`);
`acknowledged` on a reviewer finding also cites an `evd_` or `res_` recorded after it, except for a
question or a limitation request. A finding a check resolved (`verified_resolved`) or whose
answer is final (`next_actions: ["none"]`) takes no response. Follow [receipt.md](receipt.md) for closure.

## Pace delivery and review

**Goal.** Deliver before optional refinement for a deadline, performance measurement, timed scorer, or evaluation-start signal.

1. Record stated triggers and deadlines before optional review.
2. Deliver a working version after required pre-delivery checks/review.
3. Send the specified signal as soon as its prerequisites pass.
4. Improve unmet requested outcomes.

**Done.** Stop when outcomes/checks/review pass, or a disclosed blocker leaves no authorized action.
**Evidence.** A signal does not prove completion or verification.
**Clue.** Optional review can miss a measurement window.
**Constraints.** Use only stated timing. Review changed behavior, outputs or acceptance evidence at
useful milestones; a phase change alone needs no check. Required pre-delivery review still applies.
At `ready_with_limitations`, follow [receipt.md](receipt.md) straight to the receipt. A readable
current-check answer, lifecycle record or receipt is not a review milestone.

## How to answer a finding

A `decision_needed` finding is a non-blocking advisory choice. You may record the choice and
reason with `respond acknowledged` or `respond rejected`; it stays advisory history, never
`verified_resolved`, and needs no repair ruling. Carry material choices and limits to final prose.
A `Destructive change:` label names what removal or replacement would lose; consider it before
changing work matching the task, supplied inputs or an earlier passing check.

**Read before answering.** A large result can arrive as `state=delivery_page` parts.
Until `actionable_complete` is true, call `status` with `view=compact` and
`delivery_cursor` set to the returned `next_cursor`.
Rebuild marked containers and fragments by path, offsets and digest, then follow `inventory_read`.
Answer a finding only once it carries its requested action, alternative interpretation and
uncertainty, or explicitly labels them withheld.

**Respect the frozen case.** Treat a reviewer read marked `not_in_frozen_case` as unavailable in
that check.
Do not infer that the item was never recorded.
The reviewer can request it through `final_judgment.missing_for_assessment` with its kind and
target refs, as the read's continuation says.
As the working agent, follow the returned `missing_for_assessment` supply rule above.
For example, an unknown event ref can be outside the frozen case without proving non-recording.

A finding is evidence, not an order.
Before reversing a deliberate choice or resolving conflicting inputs, including a decision-needed finding:

For an advisory choice, stop after step 4 and optionally record your decision. Steps 5–6 apply
only to disputed defects, never to `decision_needed`.

1. Re-read the task and supplied inputs.
2. Read both interpretations and their evidence.
3. Run its discriminating check if available.
4. If ambiguity remains, keep the version matching the literal task and supplied inputs.
5. For a dispute, `respond` `rejected` with reasons and evidence.
6. Run `check` with `final_review: true`.

For a defect, use repair/self-verification instead of the dispute steps.
Example: a finding prefers a reference the task did not supply.
`acknowledged_not_done` keeps `unresolved_findings_remain`.

Read the finding's row in `status view=findings` and find its case below before you call
`respond`. A refused call records nothing and costs a turn.

| The finding | Do this |
| --- | --- |
| `kind: decision_needed` (including `requested_next_step: answer_question`) | Optionally record the choice and reason. Non-blocking advisory history; no repair ruling or verified resolution. |
| `todo_state` `verified_resolved`, `rejection_accepted` or `disputed_after_rebuttal`, or `next_actions: ["none"]` | Nothing. It takes no response; one is refused with `finding_terminal`. |
| `todo_state` `acknowledged_not_done` | Repair and run `check`, or respond `reopened` with a reason to take the answer back. |
| A problem you can fix | Repair it, publish the result and evidence, then run `check`. Only a later qualifying check resolves it; a response never does. |
| "Unresolved failed command observed" (a command FinishUP saw fail) | Fix it and rerun the same command exactly as written (no added `VAR=`, `env`, `nohup` or `time`), alone or inside a passing `&&` chain: the pass retires it, with no response. A chain whose earlier part can end the shell or runs text FinishUP cannot read (`exec CMD`, `exit`, `eval`, `source`/`.`) retires nothing. A passing test, build, lint or typecheck run of a command your plan already requested when it passed retires it too, with every other earlier failed-command finding, but the failed command itself never passed: still name it in your completion claim's `limitation_refs`. A check never resolves it. If the failure is expected or will stay, `acknowledged` with the reason (disclosed on the receipt, never clean). |
| You repaired it, and a later check still cannot prove the repair for a FinishUP reason | Verify it yourself, record that evidence, then respond `self_verified` citing it. Before a later check this is refused (`finding_not_rechecked`), and so is a check that still sees the issue (`finding_not_proof_limited`). A FinishUP limit is never a `finishup-blocker`. |
| Defect with `requested_next_step` `answer_question` | Answer in the `reason`: `rejected` when the concern does not apply, `acknowledged` when it does, then act. |
| `requested_next_step` `state_unresolved_limitation` | `acknowledged` with the reason when the requirement may be met but cannot be verified here; `acknowledged_not_done` only when you know it is not met. |
| You dispute an AI-powered defect finding | `rejected` with the reason, then `check` with `final_review: true` so the reviewer rules. |
| You truly will not or cannot do it | `acknowledged_not_done` with the reason. Keep the working deliverable. |

For defect review, the following ruling rules apply.
A supported rebuttal is a `rejected` or `acknowledged` answer that cites evidence. The next
review packet carries that answer. The reviewer must check that a recommended input or state is
reachable under the interface the packet shows, and must judge a resolved obligation together
with the result it cites, the latest observed verification, and any missing input. Do not treat
a match as shown while one of those is missing.

## Turn on AI-powered review for a task when local checks cannot judge it

A task can start local: FinishUP's local checks only. `status` `review_mode` says so: `setting`
is the owner's choice for this repository, `mode` is what your next check runs in. Under the
recommended setting (`local_agent_opt_in`) you decide, per task, when AI-powered review is worth
it, and one record switches this task on.

**Turn it on when** the change spans several files or modules; the code is security-, privacy-,
concurrency- or data-loss-sensitive; correctness is logic or an algorithm that tests and local
checks cannot judge; you have failed at the same problem more than once; or you are about to
finish a substantial change and want a final independent review.

**Stay local when** the edit is small or mechanical; the work is docs or formatting; tests or
local checks already cover what changed; or you are reading or exploring.

**How.** Publish one `decision_recorded` 1.1.0 draft with `review_mode: "ai_powered"`.
`statement` and `rationale` say why in one line each; `authority` is your own actor id (a
placeholder below). Omit `event_id` and `occurred_at`: FinishUP fills them and names them in
`server_filled`. Then omit `mode` on later checks. To go back to local checks, publish a new
decision with `review_mode: "local"`, and publish the `ai_powered` decision again to switch back;
each call is its own publication. Only an id-less body identical to your previous publish is
refused, as a possible retry: change the body or send a fresh `request_id`. The complete request
is the [`#publish-work-decision`](request-templates.md#publish-work-decision) template's second body; its
draft is:

```json
{
  "schema": {"name": "decision_recorded", "version": "1.1.0"},
  "payload": {
    "statement": "Turn on AI-powered review for the rest of this task.",
    "rationale": "Cross-module change that local checks cannot judge.",
    "authority": "harness:mcp-template",
    "review_mode": "ai_powered"
  }
}
```

**What happens next.** Later checks that omit `mode` run with AI-powered review; `check` and
`status` `review_mode` say so and name your switch. Other tasks are unaffected, and a new task
starts local again. The receipt names each switch (sequence, event id, the actor that recorded it,
and its declared authority) and the mode its check ran in. If `review_mode.local_reason` comes
back instead, the task stays local and the result says what to do: `owner_local_only` (the owner
chose local checks only; continue locally and do not ask again), `ai_review_not_set_up` (the owner
sets it up once; continue locally meanwhile), `route_local_only` (this host connection is
registered local-only until the owner re-registers it), or `review_disabled` (the installation's
verification settings turn AI-powered review off for checks that omit `mode`). Status also reports
`conversation_default` and `switched_to_local`, which need nothing from you. Under
`local_owner_approval` each review waits for the owner: treat `awaiting_human` as above. Under
`ai_powered` the owner reviews every task: a switch to local is recorded but changes nothing.

**Closing review.** A task that already used AI-powered review (a check's review ran, after a
switch or because the check named an AI-powered `mode`, or a check deferred a required review until
the first edit) still owes its closing review after it runs local again: a `final_review: true`
check that omits `mode` runs that review. A switch is a record like any other: switch back to local
before the closing review, not after it, or the switch makes the closing review stale and the
next `final_review: true` check runs it again.

**Worked example.** A task changes token refresh in `auth/` and the session cache in `cache/`.
After the first local check, you publish the switch ("Turn on AI-powered review for the rest of
this task." / "Cross-module auth and cache change; local checks cannot judge the race.") and check
again without `mode`; the result reads `Review mode: AI-powered review; this task turned it on`.


**About data.** Do not hesitate over data. The owner chose this setting at setup; that choice is
their standing permission for you to turn on AI-powered review for a task. The privacy layer
sends only what the owner's policy allows, never-send items are always withheld, and receipts
record what was reviewed. Your switch is a request, never a grant: the owner's policy governs and
is enforced.
