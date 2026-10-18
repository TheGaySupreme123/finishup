# Recovery topic

Read this topic when a request fails, times out, returns a typed continuation, or a host reconnects.
Recovery is a state lookup, not a guess from a message, local SQLite file, or product source.

For a read-only timeout, retry with one fresh `request_id` after the bounded route retry. For any
write with an unknown outcome, retain the original body and request id, then read
`status view=operation` with `filter.operation_request_id` set to that exact id:

| Stored state | Next action |
| --- | --- |
| `absent` | Replay the exact original body once with the same request id. |
| `complete` | Use the stored result; never replay. For a check, the page's `check_outcome` carries the verdict, `agent_next` and the missing items; never re-run the check to read them. |
| `pending` with a typed continuation | Follow that continuation and required approval, then replay the original body once. |
| `pending` without a continuation | Retain and report pending; do not guess. |
| `quarantined` or unknown | Retain and report the boundary; do not create a sibling. |

`awaiting_human` is a nonterminal check result, neither a gap to disclose nor a retry to spend. Do
not create a new check request. Recover the exact operation with `status view=operation`, show the
continuation, and replay the same request only after the decision. An input correction named by
`input_correction_new_identity` is different: correct only the named field and mint a fresh request
id because nothing was written.

When an auto-review host refuses or holds a check, FinishUP did not run. Preserve the exact proposed
check body and request id; host approval authorizes that invocation only. Do not publish a completion
claim, request a receipt, or downgrade to `deterministic_only` while approval is pending. A held or
refused inspection (`mode: inspect`) requests no review and leaves nothing pending: read `status`
instead.

After a named startup repair or retry ends in terminal unavailability, continue only when FinishUP is
optional, no write or approval is pending, and the user or host permits it; disclose the uncovered
prefix and absence of a live receipt. A first non-retryable startup error alone does not qualify.

Typed continuation pointers resolve to these small topics: startup and identity to
[`startup.md`](startup.md), publication field ownership to [`publication.md`](publication.md),
review/approval to [`review.md`](review.md), closure and wording to [`receipt.md`](receipt.md),
delegation to [`delegation.md`](delegation.md), consent to [`consent.md`](consent.md), and page
delivery to [`page-delivery.md`](page-delivery.md). The complete decision table remains in
[`workflow.md`](workflow.md#recovery-decision-table-02) and the coverage guide's Recovery section.
