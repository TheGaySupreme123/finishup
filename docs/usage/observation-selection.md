# Observation selection

Observation selection controls how much structural host activity FinishUP keeps for a workspace. It
is a retention and capacity choice. It does not change what the host is allowed to do, what content
may be captured, or what an AI-powered review provider may receive.

Focused with the standard capacity is the default. In Focused mode, FinishUP can account for proven
successful routine reads, searches, and inventory calls in bounded summaries. A summary keeps the
native identities and source positions it represents, but it is not per-call content evidence or a
verification result. Detailed mode keeps eligible routine calls as individual records and allows
more bounded optional detail while pressure remains healthy.

The classifier is deterministic and conservative. Failures, denials, cancellations, interrupted,
partial, and unknown outcomes remain individual observations. Edits and side effects, declared tests and
checks, negative verification, and reads explicitly linked to an obligation, claim, or finding
remain individual observations in both modes. A read-only command can still be important evidence.
Caller prose or an action label cannot make an unknown, ambiguous, or failed operation routine.

Capacity is independent from detail:

| Capacity | Queue-count target | Availability |
| --- | ---: | --- |
| standard | 512 | Default and recommended, with Focused or Detailed |
| larger | 2,048 | Explicit owner choice, with Focused or Detailed |
| largest | 8,192 | Explicit owner choice, with Focused or Detailed |
| custom | 64 to 8,192 | Explicit owner choice with `--queue-count`, with Focused or Detailed |
| none (No FinishUP cap) | — | Not available for this queue; see below |

Each choice also has finite byte, state, pending-pair, protected-reserve, fair-share, diagnostic,
and capture budgets. The queue allows 1 KiB per row, so 1,024 rows allow 1 MiB of queued records.
The local state document may grow to twice the queue bytes, with a 1 MiB minimum and a 16 MiB
safety ceiling. Every choice keeps the same 256 pending pre/post pairs and the same capture limits
of 512 tickets and 128 MiB. The larger and custom choices are bounded, but their performance has
not been validated; use the preview and status output to see the selected and effective values
and their current pressure. A larger queue does not promise higher sustained throughput.

Sessions in one workspace share one queue. Its size is the largest of the workspace setting (or
the 512 default when there is none) and every active session selection. A session selection can
raise the shared queue for every session in the workspace but never lower it: a session count
below it, such as a custom count under 512, limits only that session's own admission, never another
session's. Status reports both
the value you selected and the value in effect, which limit is closest to full, and whether No
FinishUP cap is available.

## No FinishUP cap

Choosing `--capacity none` does not remove the limit. The structural queue has no uncapped mode in
this version: all observation state is kept in one local document with a 16 MiB safety ceiling,
and an "unlimited" queue would still stop at that ceiling. Preview and apply both answer with the
outcome `capacity_no_cap_unsupported` and change nothing. The explanation reads:

```text
No FinishUP cap is not available for the structural queue in this revision: the local state
document has a 16 MiB safety ceiling. The largest supported finite capacity is 8,192 rows
(--capacity largest or --capacity custom --queue-count 8192).
```

With `--json`, the failure carries the same facts under `error.capacity` (`no_cap` and
`alternative_command`) beside the standard `error.recovery` guidance.

AI-powered review limits are not part of this choice. Their input, output, and spend limits stay
fixed or are set by your privacy policy, and provider limits always apply.

## Choose a selection

Inspect the current choice for a host session:

```text
finishup observe selection-status --workspace /exact/project \
  --session-id <host-session-id> --json
```

Preview a temporary session choice first:

```text
finishup observe selection-preview --workspace /exact/project \
  --detail detailed --capacity larger --session-id <host-session-id> --json
```

Apply the exact `preview_digest` returned by that preview:

```text
finishup observe selection-apply --workspace /exact/project \
  --detail detailed --capacity larger --session-id <host-session-id> \
  --accept --preview-digest <preview-digest> --json
```

For a custom count, add `--queue-count` to both preview and apply:

```text
finishup observe selection-preview --workspace /exact/project \
  --detail focused --capacity custom --queue-count 1024 \
  --session-id <host-session-id> --json
finishup observe selection-apply --workspace /exact/project \
  --detail focused --capacity custom --queue-count 1024 \
  --session-id <host-session-id> --accept --preview-digest <preview-digest> --json
```

### What the preview discloses

FinishUP never raises capacity on its own, and permission to run an ordinary task is not permission
to raise it. Every preview shows the scope (this session, or the workspace), the current and
requested queue rows with their queue and state byte limits, and the consequences. For an
increase, the preview says:

```text
Larger local retention can increase disk use, memory use and CPU work, and may slow FinishUP or
other apps.
```

Because sessions in a workspace share one queue, an increase also says:

```text
The shared workspace queue follows the largest active selection, so this can raise the queue and
state-document bounds for every session in the workspace.
```

It then lists what stays limited (256 pending pairs, 512 capture tickets and 128 MiB of captured
content, and the 16 MiB state document), states that content, privacy, provider, credential, and
network authority do not change, gives the commands to lower the setting, to pause new observation
ingest, and to resume it, and marks performance validation as provisional. Those commands show
`<workspace>` and `<session-id>` placeholders rather than your typed path; put in your project path
and session id when you run them. For a decrease, it says that lowering affects future admission
only: accepted records drain and are not deleted. The JSON output carries the same facts as a
structured `disclosure` object, and the preview digest binds the requested count, so a different
count needs a new preview.

An agent may relay a capacity change only after you accept the displayed preview. It should
repeat the preview's scope, values, consequences, remaining limits, and lower, pause, and resume
path rather than describing the change as safe, free, or unlimited, and it should never imply that
provider limits no longer apply.

### Lower or pause

To lower a setting, preview and apply a smaller capacity at the same scope (the preview's
"Lower it later" command restores the capacity you had before an increase). At the minimum of
64 rows, pause ingest if needed. Revoking an override restores the inherited or default setting
and can increase capacity; check the resulting selection. To stop new observation ingest while
keeping consent and evidence, run
`finishup observe pause --workspace /exact/project`; `finishup observe resume --workspace
/exact/project` restarts it.

### In the terminal interface

In the terminal interface, `/observe` shows the current selection status and effective budget,
then asks **Change local retention capacity?** The options are to keep the current setting,
recommended (512), larger (2,048), largest (8,192), custom (you type a count from 64 to 8,192), or
No FinishUP cap. The terminal interface changes the workspace default and keeps the current detail
mode. After you pick a value it shows the same disclosure as the CLI preview and asks you to apply
or cancel. Cancelling or pressing `Esc` changes nothing. Choosing No FinishUP cap shows the
explanation above and changes nothing.

### Scope and lifetime

The default is a temporary session override. It is tied to the selected host session and can have
an optional RFC3339 UTC `--expires-at` deadline. To make an explicit workspace default, preview and
apply with `--persist` and omit `--session-id`:

```text
finishup observe selection-preview --workspace /exact/project \
  --detail focused --capacity standard --persist --json
finishup observe selection-apply --workspace /exact/project \
  --detail focused --capacity standard --persist \
  --accept --preview-digest <preview-digest> --json
```

Revoke the setting at the same scope:

```text
finishup observe selection-revoke --workspace /exact/project \
  --session-id <host-session-id> --json
finishup observe selection-revoke --workspace /exact/project \
  --persist --json
```

Expiry, revoke, or a lower capacity changes future admission. Accepted records continue through
the bounded drain and are not rewritten or deleted just to match the new target. While they are
above the new target, new input is refused and each refusal is recorded as loss. Delivery attempts
and session ends are still recorded too, even when the accepted records hold more than the new
setting's storage budget. That extra room is finite and follows only the accepted records. It
shrinks as they drain and ends when they fit the new target. Under pressure,
the effective mode can temporarily be Focused even when Detailed remains selected. Status exposes
both values, the setting origin and expiry, pressure, accounting, capture backlog, and historical
loss. At a hard limit, replayable input pauses for retry and non-replayable input receives bounded
loss accounting; the host is not held up to preserve an observation.

After current usage falls below every hard threshold, pressure moves from `hard_limit` to `high`
and structural admission can resume when the next input fits. Optional detail stays reduced until
all dimensions remain at or below 45% for ten seconds. Retained history still consumes the byte
budget: an empty pending queue does not imply healthy pressure or restored historical coverage.
Ending a host session retires its pressure snapshot, while preserving pending work and history.

## Protect evidence and promote a buffered read

When a later claim or finding will depend on a read, protect it before the read occurs:

```text
finishup observe protect-read --workspace /exact/project \
  --session-id <host-session-id> --reference clm_<existing-id> \
  --count 1 --json
```

The reference must be an existing or planned `obl_`, `clm_`, or `fnd_` identifier. Protection is
limited to 32 outstanding logical reads, is bound to the exact native read identity, and consumes
one slot only when its logical post event is admitted. It expires after ten minutes by default;
an explicit `--expires-at` cannot extend that bound. The command requires active observation
consent and narrows retention only. It grants no content, privacy, provider, credential, or
network authority.

Before a buffered routine read is delivered, its native source identity can be promoted:

```text
finishup observe promote --workspace /exact/project \
  --source-identity <source-identity> --json
```

Promotion preserves the original identity, route, and observed time as an individual structural
record. It is available only while that identity remains in the bounded buffer. Once the buffer
has been delivered, the result is `promotion_window_closed` and `content_availability` is
`not_retained`. If the historical bytes are needed, rerun or reacquire the current state and label
it as a new observation with its new time and state; promotion cannot recover old bytes or prove
the earlier state retroactively.

## Content, pressure, and deadlines

Selection runs before optional native content extraction and structural admission. Native content
capture is a separate authority decision. Claude Code and Cursor require their exact ordinary
profile to be selected and separately enabled; Codex's supported hook capture arm follows active
observation consent and is profileless. See [Privacy and AI-powered
review](privacy-and-semantic-review.md) and the [Codex](../runbooks/codex-integration.md), [Claude
Code](../runbooks/claude-code-integration.md), and [Cursor](../runbooks/cursor-integration.md)
runbooks for host-specific setup and limits.

The native capture lane has workspace-wide limits independent of the selected queue: at most 512
staging or pending capture tickets and 128 MiB of captured content. A larger structural profile
does not raise either limit. Capture is bounded by each host hook's deadline and drain window. A
timeout, cancellation, missing post event, or incomplete content group remains incomplete, partial,
unknown, or unpaired as appropriate and is surfaced as a content gap when the boundary permits; it
is not silently converted into a successful routine summary. Capture status describes configuration,
not proof that bytes were captured or selected for a check.

Captured content waits in a short handoff until its structural record is delivered. If that record
can no longer deliver it (it was already recorded without the content, refused, or quarantined),
FinishUP retires the handoff instead of letting its age hold the whole workspace at the pending-age
limit. The local service does this in the background, normally within about a minute and a half,
even when no new host input arrives; a new check does it for its own task. The retired content is
not attached, so status reports `content_capture_unavailable`, and `finishup observe status --json`
lists recent retirements under `capture_handoff_retirements` with the ticket identity, stage, the
reason, and the handoff's age. The service commits that account before releasing the ticket's
reservation; a failed or cancelled account leaves the handoff available for retry. A handoff whose
record is still waiting keeps counting toward the unchanged pending-age limit.

A single hook event is also bounded. FinishUP fully reads a host body of at most 1 MiB; very large
content inside it is kept only up to the capture budget and marked truncated. Images, audio, and
video inside a tool result are never kept: FinishUP replaces their bytes with a short placeholder,
so viewing a screenshot records the call, its outcome, and its text, but not the picture.
For each image (up to eight per call) FinishUP instead records a fingerprint: its SHA-256, size in
bytes, image type, and pixel width and height. That record appears as evidence on the call's
result, so you or the agent can point to it as proof the image was inspected. The picture itself
never leaves your machine and is never sent for AI-powered review. An
event can still exceed 1 MiB without its images, for example a very large file write or command
output. On every host, FinishUP then keeps the event's identity when the complete event fits in
8 MiB: the session, tool, call, outcome, and, for a completed edit with a short path, a path
commitment, with the content left out. That row is `payload_content_omitted`. FinishUP's own tools
are the exception: their content is never captured anyway, so their row is complete and carries
no gap. An event over 8 MiB, or one that is not a complete valid document, is an unparsed
`payload_too_large` gap. Either way the rest of the session keeps ingesting, and a receipt cannot
report the omitted or dropped bytes as captured work.

Summary coverage, current pressure, capture availability, delivery, and selection for a particular
check are separate facts. A summary or an empty queue cannot support a claim of full per-call
content observation, and selection does not replace a check or receipt.

Self-observation has a narrower boundary. Explicit FinishUP MCP workflow names are recognized as
service-owned reads, so their successful projections stay local. A host shell event such as
`exec_command finishup observe status`, `finishup observe selection-status`, `finishup observe
selection-preview`, or `finishup closure-prepare` does not carry an authenticated identity for the
launcher that actually ran. Even an absolute path written in the command text is untrusted at this
boundary. These local CLI reads therefore remain ordinary shell observations and can consume the
structural, capture, or materialization work available to that host. Failures, mutations, and
ambiguous shell remain individually retained. This is a current support boundary; use an explicit
MCP status or receipt route when that non-amplifying self-read path is available, and account for
local CLI reads in coverage and capacity.
