# Review topic

Read this topic before the first `check`, when a finding or pending review appears, or when a final
check must be recovered. A check evaluates only the recorded, readable, frontier-bound packet.

Select `semantic_required` when the user, effective policy, or named acceptance criterion requires
independent AI-powered review. Omit `mode` for the configured default. Use
`semantic_if_configured` only when review is known to be optional. Use `deterministic_only` only for
explicit local/structural work, a semantic-disabled policy, or a deliberate no-egress choice, and
disclose `semantic_review_not_requested`; never use it merely to shorten a follow-up.

Host authorization and a Yoetz disclosure decision are separate. A host auto-review refusal or hold
before invocation is not a Yoetz result: Yoetz did not run. Preserve the exact proposed `check`
body and `request_id`; host approval authorizes this invocation only. While pending, do not publish a
completion claim, request a receipt, create a fresh check, or switch mode. After approval, invoke
the same body and request id. After denial, cancellation, or expiry, continue without review only
after the user explicitly chooses that fallback.

`awaiting_human` is nonterminal, neither a gap to disclose nor a retry to spend. Do not create a new
check request. Read `status view=operation` for the original request, show the exact continuation,
and replay it only after the decision. `awaiting_input` likewise waits for the named missing input;
do not infer it from source or stored databases.

A missing repository grant is an authority boundary. If chat authorization is not advertised, use
the exact trusted `yoetz --privacy` route; agent chat text grants nothing. A standing grant is
separate from host approval, `confirm_every_request` is one-use, and no dispatch occurs without the
grant. Keep the same request id and never create a fresh request to escape the decision.

`full_restart_required` is an activation mismatch. Fully restart the exact host process and verify
the live route before a new check; it never authorizes egress. Read the check result's coverage and
review status as reported, not as proof that the underlying code is correct. Details and recovery
limits remain in [`coverage-and-receipts.md`](coverage-and-receipts.md#check-mode-and-ai-powered-review-coverage).

Before the receipt, run the closing review: `check` with `final_review: true`. It judges each stated
requirement and requested output against the task, with or without a completion claim; closure
readiness lists `closing_review_required` until one is current after the last material change.
Answer every AI-powered finding with `respond` and a reason; `acknowledged` on a reviewer finding
requires one. A finding whose `requested_next_step` is `answer_question` is a question: answer it
in the reason (`rejected` when your answer shows the concern does not apply, `acknowledged` when it
does, then act). The next check shows the reviewer your answer, and it rules on it. Limitations
outside your control (authority, credentials, unavailable external resources) stay acceptable when
disclosed; a limitation you could reduce is work, not support.
