# Review topic

Read this topic when a check needs more than the operating card: a finding or pending review
appears, a final check must be recovered, or a result names it. A check evaluates only the
recorded, readable, frontier-bound packet.

Select `semantic_required` when the user, effective policy, or named acceptance criterion requires
independent AI-powered review. Omit `mode` for the configured default. Use
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

A check before your first material edit runs the local plan checks only and sends nothing
(`semantic_review_deferred_before_first_edit`); the next check after an edit reviews as configured.
If the work needs no edit and review is required, readiness asks for the closing review instead.
While work is in progress the reviewer judges incomplete work only; its correctness concerns come
back as advisory notes in the review summary, not findings. `agent_criterion_unmet` is a criterion
you set yourself beyond the task's stated scope: fix it, or narrow it with `respond` `acknowledged`
and the reason (a disclosed limitation that does not block); a `finishup-verification-limit` decision
does not narrow it.

Before the receipt, run the closing review: `check` with `final_review: true`. It judges each stated
requirement and requested output against the task, with or without a completion claim; closure
readiness lists `closing_review_required` until one is current after the last material change.
Answer each open AI-powered finding with `respond` and a reason; `acknowledged` on a reviewer
finding requires one, plus an `evd_` or `res_` you recorded after it in `evidence_refs` (not for a
question or a limitation request). A finding a check resolved (`verified_resolved`) or whose
answer is final (`next_actions: ["none"]`) takes no response. A finding whose
`requested_next_step` is `answer_question` is a question: answer it in the reason (`rejected` when your answer shows the concern does not apply, `acknowledged` when it
does, then act). The next check shows the reviewer your answer, and it rules on it. Limitations
outside your control (authority, credentials, unavailable external resources) stay acceptable when
disclosed; a limitation you could reduce is work, not support.

## How to answer a finding

Read the finding's row in `status view=findings` and find its case below before you call
`respond`. A refused call records nothing and costs a turn.

| The finding | Do this |
| --- | --- |
| `todo_state` `verified_resolved`, `rejection_accepted` or `disputed_after_rebuttal`, or `next_actions: ["none"]` | Nothing. It takes no response; one is refused with `finding_terminal`. |
| `todo_state` `acknowledged_not_done` | Repair and run `check`, or respond `reopened` with a reason to take the answer back. |
| A problem you can fix | Repair it, publish the result and evidence, then run `check`. Only a later qualifying check resolves it; a response never does. |
| You repaired it, and a later check still cannot prove the repair for a FinishUP reason | Verify it yourself, record that evidence, then respond `self_verified` citing it. Before a later check this is refused (`finding_not_rechecked`), and so is a check that still sees the issue (`finding_not_proof_limited`). |
| `requested_next_step` `answer_question` | Answer in the `reason`: `rejected` when the concern does not apply, `acknowledged` when it does, then act. |
| `requested_next_step` `state_unresolved_limitation` | `acknowledged` with the reason when the requirement may be met but cannot be verified here; `acknowledged_not_done` only when you know it is not met. |
| You dispute an AI-powered finding | `rejected` with the reason, then `check` with `final_review: true` so the reviewer rules. |
| You truly will not or cannot do it | `acknowledged_not_done` with the reason. Keep the working deliverable. |
