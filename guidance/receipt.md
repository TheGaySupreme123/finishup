# Receipt topic

Read this topic when closure or final prose needs more than the operating card, or a result names
it. A receipt reports the recorded scope and its limits; it is not a pass and never closes work.

Before the final check, publish the completion claim and current evidence, read what is left
(`check` with `mode: inspect` records nothing; or `status`), answer each unanswered finding, and check the repaired/current record. Answer each finding once; its
`finding_frontier` may be the current status frontier, so no historical frontier search is needed.
Non-actionable observation-authored findings need no answer. After the check, answer only the
findings it returned that remain unanswered, then read `status view=findings` with
`filter.include_resolved=true` and inspect `resolved`. Not returned is not resolved. A response does
not repair a finding; a material repair needs a qualifying recheck. Responses to the check's own
findings, acknowledgement of an observation-authored non-actionable finding, and `work_closed` do
not need a recheck. At `ready_with_limitations`, nothing further is to do: request the receipt
without another check and disclose its standing limitations. The status sentence after the stop
instruction says what the receipt will read (`predicted_receipt`); lead the final prose with the
receipt's conclusion and its `conclusion_basis` reasons, not with "nothing further to do". After `insufficient_packet`, go to
the receipt rather than a deterministic fallback.

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
