# Recovery topic

Read this topic when a request fails, times out, returns a typed continuation, or a host reconnects.
Recovery is a state lookup, not a guess from a message, local SQLite file, or product source.

This topic owns unknown-write recovery. For a read-only timeout, retry with one fresh
`request_id` after the bounded route retry. For an unknown write, retain its original body/id.
If a `start` response is lost before session/writer ids return, replay the exact original `start`
body once with the same `request_id`; do not invent ids for status. A typed start
`OPERATION_PENDING` with no route ids uses that same branch. Otherwise read `status view=operation`
with `filter.operation_request_id` set to the exact write id and follow this table:

| Stored state | Next action |
| --- | --- |
| `absent` | Replay the exact original body once with the same request id. |
| `complete` | Use the stored result; never replay. For a check, the page's `check_outcome` carries the verdict, `agent_next` and the missing items; never re-run the check to read them. |
| `pending` with a typed continuation | Follow that continuation and required approval, then replay the original body once. |
| `pending` without a continuation | Retain and report pending; do not guess. |
| `quarantined` or unknown | Retain and report the boundary; do not create a sibling. |

A check refused before admission (`check_admission_same_identity`, or an `absent` operation
with an `admission` stage) recorded nothing: wait its `retry_after_ms` and replay the exact body/id,
at most three times; then retain/report "not admitted". Do not switch mode or mint a new request.

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
prefix and absence of a live receipt. A first non-retryable startup error alone does not
qualify; the user's own choice in [When FinishUP is not working](#when-finishup-is-not-working) does.

Typed continuation pointers resolve to these small topics: startup and identity to
[`startup.md`](startup.md), publication field ownership to [`publication.md`](publication.md),
review/approval to [`review.md`](review.md), closure and wording to [`receipt.md`](receipt.md),
delegation to [`delegation.md`](delegation.md), consent to [`consent.md`](consent.md), and page
delivery to [`page-delivery.md`](page-delivery.md). The complete decision table remains in
[`workflow.md`](workflow.md#recovery-decision-table-02) and the coverage guide's Recovery section.

## When FinishUP is not working

When `start` still has no task after the continuation, same-request recovery and any named repair
above, pause material work and tell the user plainly that FinishUP is not working, with the error
code and `correlation_id`. A pending write, pending approval or vault setup is not this case. Offer
three choices and let the user pick one; never pick for them:

1. **Restart or fix it locally.** Run `finishup service diagnostics --correlation-id <id>` and
   `finishup service status`, and explain the failing stage in plain words. Only with the user's
   go-ahead, apply the local fix that points to: `finishup service restart`, `finishup upgrade`,
   or the repair command the diagnostics name. Then replay the original `start` once with the
   same `request_id`. After `finishup upgrade`, do not replay here: this session keeps running the
   previous version, so ask the user to open a new session and call `start` there. Fixing a defect
   in FinishUP's own source is a separate task the user requests. Never kill FinishUP processes by name or pattern, and never edit or delete files in
   FinishUP's data folder.
2. **Report it.** If it looks like a FinishUP defect, offer an issue at
   <https://github.com/orgFinishUP/finishup/issues>. Search for an existing one first. Draft the
   title and body with `finishup version`, the OS, the host, the error code, the correlation id,
   the failing stage and exception class, and the steps; leave out source, prompts, transcripts,
   private paths and credentials. File it only after the user approves that exact text.
3. **Continue without FinishUP.** Only when the user says so: do the requested work, claim no
   task, finding, check or receipt for it, and end by saying FinishUP recorded none of the work
   done without it. Their choice covers this task only. A required AI-powered review stays unmet.
   If FinishUP recovers later, `start` may record the rest; the final reply then names the
   uncovered prefix separately from the later task and receipt. Under required startup, tools
   stay blocked until the owner returns startup to optional.
