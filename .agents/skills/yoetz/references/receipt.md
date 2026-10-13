# Receipt topic

Read this topic when closure or final prose needs more than the operating card, or a result names
it. A receipt reports the recorded scope and its limits; it is not a pass and never closes work.

## Closing sequence

Do these steps in order.

1. Publish the completion claim and current evidence. When hooks observe your work, cite a
   verification run made after your last edit (`status view=results`).
2. Read what is left: `check` with `mode: inspect` records nothing; `status` also shows it.
3. Before the final check, answer each unanswered finding; [`review.md`](review.md) has a table
   for each case. Answer each finding once; its `finding_frontier` may be the current status
   frontier, so no historical frontier search is needed. Non-actionable observation-authored
   findings need no answer.
4. Check the repaired/current record with the closing review: `check` with `final_review: true`.
5. After the check, answer only the findings it returned that remain unanswered. Then read
   `status view=findings` with `filter.include_resolved=true` and inspect `resolved`. Not returned
   is not resolved.
6. Recheck only when a material record follows the check. A response does not repair a finding; a
   material repair needs a qualifying recheck. Responses to the check's own findings,
   acknowledgement of an observation-authored non-actionable finding, and `work_closed` do not need
   a recheck.
7. Request `receipt`. At `ready_with_limitations`, nothing further is to do: request the receipt
   without another check and disclose its standing limitations. The status sentence after the stop
   instruction says what the receipt will read (`predicted_receipt`).
8. Publish `work_closed` when the work is complete, then write the final prose. Lead it with the
   receipt's conclusion and its `conclusion_basis` reasons, not with "nothing further to do".

## Stop conditions

- Do not repeat a check on unchanged state: it returns the same findings. After one current-state
  recheck still cannot qualify, stop rechecking and disclose the gap.
- After `insufficient_packet`, go to the receipt rather than a deterministic fallback.
- Anything material you publish after the closing check needs another check before the receipt.
- Never empty, delete or withdraw a working deliverable to close a finding or a Stop message.

## Final prose

Receipt and final prose are scope-first. Lead with what recorded evidence/checks covered and what was
not verified or remained limited. Name the checked frontier, AI-powered review status/reason, and
material coverage gaps before counts. Then report actual actionable-unresolved, unanswered, and
resolved-history counts. Never headline a bare “no findings”, “zero findings”, “clean”, or
“verified” result. Say what the evidence covers and what it leaves unverified in plain language.

Do not save the receipt as a file in the task workspace or in any output directory: the ledger
keeps it, and a stray file can break a grader that lists an output directory. Put its conclusion
in your final message instead. Yoetz never counts its own receipt or export files as an edit.

Keep `insufficient_coverage`, digest-only provenance, clipped or omitted evidence, unavailable
provider review, and observation gaps explicit. A clean local check cannot strengthen a receipt past
its weakest material coverage. The complete vector, finding classification, and rendering fields
remain in [`coverage-and-receipts.md`](coverage-and-receipts.md#receipt-format) and the receipt
template.
