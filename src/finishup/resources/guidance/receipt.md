# Receipt topic

Read this topic when closure or final prose needs more than the operating card, or a result names
it. A receipt reports the recorded scope and its limits; it is not a pass and never closes work.

## Closing sequence

This topic owns the closing procedure. Start with readiness: at `ready_with_limitations`, request
`receipt` now; do not restart the check sequence. Otherwise follow the steps for the work still due.

1. Publish the completion claim and current evidence. When hooks observe your work, cite a
   verification run made after your last edit (`status view=results`).
2. Read what is left: `check` with `mode: inspect` records nothing; `status` also shows it.
3. Before the final check, answer each unanswered finding; [`review.md`](review.md) has a table
   for each case. Answer each finding once; its `finding_frontier` may be the current status
   frontier, so no historical frontier search is needed. Non-actionable observation-authored
   findings need no answer. `decision_needed` is an optional advisory decision, not repair work.
4. If readiness requires a closing review, check the repaired/current record with
   `final_review: true`. Keep any required review mode; do not downgrade it to finish.
5. After the check, answer only the findings it returned that remain unanswered. Then read
   `status view=findings` with `filter.include_resolved=true` and inspect `resolved`. Not returned
   is not resolved.
6. Recheck only when a material record follows the check. A response does not repair a finding; a
   material repair needs a qualifying recheck. Responses to the check's own findings,
   acknowledgement of an observation-authored non-actionable finding, and `work_closed` do not need
   a recheck when the response is readable. A redacted or unreadable response does need one.
7. Request `receipt`. At `ready_with_limitations`, nothing further is to do: request the receipt
   without another check and disclose its standing limitations. The status sentence after the stop
   instruction says what the receipt will read (`predicted_receipt`).
8. Only when the work is complete and the advertised lifecycle continuation permits it, publish
   `work_closed`. On `lineage_work_transition`, read lineage state once; follow only a supported
   continuation, not a blind repeat. Report an unavailable close separately from the receipt.
   Lead final prose with the receipt's conclusion and `conclusion_basis` reasons.

## Stop conditions

- Do not repeat a check on unchanged state: it returns the same findings. After one current-state
  recheck still cannot qualify, stop rechecking and disclose the gap.
- After `insufficient_packet`: If `missing_for_assessment` names an `agent_suppliable` item you can supply, publish exactly that item once, linked to any named target, then `check` again. If it is already supplied, or it is a packet, type or authority limit, go to the receipt and state that specific limit. Only new material counts; tie it to any named target. The captured output of a re-run FinishUP observed counts only once it reaches the reviewer, so publish the result even after a re-run; a respond counts only when the target is a finding, and a description never does. Observed test, build, lint, or typecheck output reaches the reviewer only when a repository excerpt would be sent.
- Review changed behavior, outputs or acceptance evidence at useful milestones; a phase change
  alone needs no check. The exceptions in step 6 also apply at closure. An advisory choice needs
  no repair review merely to make it resolved; it remains advisory history.
- Never empty, delete or withdraw a working deliverable to close a finding or a Stop message.

## Final prose

Receipt and final prose are scope-first. Lead with what recorded evidence/checks covered and what was
not verified or remained limited. Name the checked frontier, AI-powered review status/reason, and
material coverage gaps before counts. Then report actual actionable-unresolved, unanswered, and
resolved-history counts. Never headline a bare “no findings”, “zero findings”, “clean”, or
“verified” result. Say what the evidence covers and what it leaves unverified in plain language.

Do not save the receipt as a file in the task workspace or in any output directory: the ledger
keeps it, and a stray file can break a grader that lists an output directory. Put its conclusion
in your final message instead. FinishUP never counts its own receipt or export files as an edit.

Preserve the original acceptance criteria: "Resolved implementation obligation; hidden accuracy
unverified" is different from acceptance passing. Name remaining unmet criteria, and retain
material advisory choices and the agent's reasons without calling them independently verified.

Keep `insufficient_coverage`, digest-only provenance, clipped or omitted evidence, unavailable
provider review, and observation gaps explicit. A clean local check cannot strengthen a receipt past
its weakest material coverage. The complete vector, finding classification, and rendering fields
remain in [`coverage-and-receipts.md`](coverage-and-receipts.md#receipt-format) and the receipt
template.

Keep incidental verification logs and evidence reports outside the workspace and outside declared
output directories, then publish their evidence through the ledger. A report the task requires is
a deliverable: keep and declare it. Byte-identical in-workspace shell rewrites preserve freshness
only when FinishUP's trusted complete before/after comparison proves it; changed or newly created
reports can still require verification. Do not rerun an expensive verification merely to reproduce
identical evidence without first reading the task's readiness and named stale-input facts.

`unavailable / round_limit_unassessable` means AI-powered review was requested and stopped after
repeated unassessable rounds; it does not mean review was never requested. Required review remains
incomplete. Self-verification reports the agent's own evidence about a concern; when the retained
position rejected it, the receipt identifies it as a concern the agent reports disproved, without
claiming an implementation repair or independent verification.
