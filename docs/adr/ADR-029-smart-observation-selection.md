# ADR-029 — Smart observation selection and bounded observation budgets

**Status:** Proposed for issue #687; the maintainer requested the complete implementation in one
draft PR on 2026-09-10. Product direction is acknowledged; measured performance acceptance and
the larger-profile rollout remain review decisions on that issue. Amended 2026-09-24 for #828
(configurable capacity policy, custom counts, and the typed no-FinishUP-cap outcome) and 2026-09-25
for #843 (a finite over-target drain bound that keeps accounting writable) and #836
(stranded capture handoffs are reconciled as admission-independent maintenance); 2026-10-13 for
the tb4n5 observation follow-ups of #1038 and #1041 (yielded and tool-less code-mode cells, expired
and rejected attempts, local retention, held rollout rows before a check, drain counter and
delivery lag).

**Relates to:** ADR-009, ADR-010, ADR-014, ADR-016, ADR-022, and issues #687, #753, #828, and #843.

## Context

The observation queue is shared by host sessions in a workspace. The previous implementation
coalesced successful routine reads only when materializing the task ledger, after local capture,
serialization and queue admission. Its 512-row target was independent of a 1 MiB bound on the
entire state file and a separate 512-ticket capture limit. Increasing the row constant cannot
increase sustained throughput, preserve content, or expand the evidence selected for a check.

Normal drain means delivering accepted observations and continues in the background. Discard is
loss of observation data and is a last resort. Observation must not prevent the host from working.

## Decisions

### Selection and authority

Focused is the default detail mode. Detailed retains individual routine operations and additional
bounded eligible context. Both modes retain failures, denials, cancellation, interrupted and
unknown outcomes, mutations, declared verification, and evidence explicitly protected for an
obligation, claim or finding. A read-only command is not necessarily routine verification.

Classification is deterministic, versioned, and conservative. Unknown tools, ambiguous shell
composition, nonzero read results, and conflicting outcome facts remain individual observations.
Caller prose and caller-supplied routine labels cannot downgrade protection. An explicit request
to retain evidence can only increase its protection within existing authorization.

Selection precedes optional content extraction and admission. A pre-event has no successful
outcome: its minimum native identity must be durable before it can be paired with a post-event.
Only a proven routine success can contribute to a summary. A later failure retains its original
attempt and outcome identity, including the failure before a successful retry.

Content permission, structural retention, and AI-powered review disclosure are independent. No
detail or capacity setting enables a content category, a provider, a credential, or network
disclosure. The existing redaction, encryption, never-send exclusions, and authority generations
remain mandatory in every mode.

### Summary identity and delivery

A summary is a bounded account of represented source inputs, not evidence of their content.
Its durable identity binds every represented input identity and source position. Counts describe
the actual represented inputs and completed calls; they are not estimates of discarded traffic.
Summaries cannot cross workspace, routed task/session/writer, host session, delegate, source,
source generation, consent generation, restart, or material subject-state boundaries.

One definition decides whether a routine read succeeded. The classifier resolves it from the host
payload and records that decision on the envelope; a later caller re-derives the same state from
the fields the envelope retains rather than applying a second, stricter rule to a lossy copy of
them. Where the two disagreed, the buffer admitted an input the summary then refused (issue #753).

Refusing to summarize a buffered lane is an accounting loss for that lane alone. Its members are
still accepted observations: they are admitted individually with the durable
`routine_summary_invalid` coverage gap, the remaining lanes commit, and the buffer drains. The
workspace retains one bounded, deduplicated account of the refused lane so the cause is named
once. An invariant failure while summarizing must never stop ingestion for the session.

The pending representation and source cursor commit together. A replayable input cannot advance
past an input for which neither an individual record nor its summary account is durable.
Source-order delivery and existing fair drain selection remain unchanged: selection priority does
not authorize reordering. Before a later protected record is admitted, any earlier pending summary
in its lane is flushed. Background maintenance also flushes bounded pending work, so another hook
is not a prerequisite for progress.

Successful summaries flush after two seconds or 16 completed calls. An unresolved routine pre
becomes an individual pending action after five seconds; this does not invent its outcome.
Pairing identities remain available for ten minutes so longer tool calls can still be linked.
Expiry or a fenced session end records `pending_attempt_expired` before retiring that pairing
state. A later post retains its actual outcome as an unpaired observation with explicit coverage
limits. These wall-clock deadlines survive restart; a retry cannot extend the original deadline.
A host call whose host never sends a post is pre-only (issue #1041): a Codex shell
`apply_patch <<EOF`, which Codex intercepts after firing only its `PreToolUse`. Its pairing state
is closed, without the gap, by an observed file change of the same session (a rollout
`FileChange` item): the attempt whose call id it names; an item naming another call the session's
hooks reported is that call's change and closes none; an item naming no reported call closes the
session's oldest pre-only attempt. One no observed change closes expires as above.

Accepted outbox rows are immutable pending delivery. Automatic degradation affects future
optional work; it does not rewrite accepted individual rows as summaries or move protected rows
into quarantine merely to fit the state file. Disposable read caches and bounded diagnostic
detail are reclaimed first. When a safe write cannot preserve accepted records, it fails without
replacing the previous durable state.

### Capacity, pressure, and setting lifetime

Detail and capacity are separate controls. Queue-count profiles are 512, 2,048, and 8,192; 512 is
the default. Every active profile must also have finite queue-byte, aggregate-state, pending-pair,
capture, diagnostic, and protected-reserve bounds. The shared workspace ceiling and per-session
admission accounting are visible. A capacity override never changes a sibling's detail mode or
capture authority.

The initial numerical budget proposal is:

| Queue profile | Queue bytes | State bytes | Protected reserve (rows / bytes) | Session share (rows / bytes) |
| --- | --- | --- | --- | --- |
| 512 | 512 KiB | 1 MiB | 128 / 128 KiB | 128 / 128 KiB |
| 2,048 | 2 MiB | 4 MiB | 512 / 512 KiB | 512 / 512 KiB |
| 8,192 | 8 MiB | 16 MiB | 2,048 / 2 MiB | 2,048 / 2 MiB |

All profiles share a 256 pending-attempt limit and an independent 512-ticket / 128 MiB capture
budget. These are finite engineering limits, not measured throughput guarantees. The byte and
session bounds can stop admission before the selected row count. Optional routine detail is
bounded to 16 KiB in Focused fallback and 64 KiB in Detailed, within the pre-existing content
permissions. Protected failure and evidence content retains its existing capture bounds.

Capture admission counts both retained tickets and outstanding reservations across task bundles
in the workspace. A new service generation requires a complete inventory before admitting new
content. Missing or unreadable relevant routes leave accounting unknown; a partial task update
cannot clear that state. Reservation overlap requires exact ticket and retained-byte bindings.
When older state lacks those bindings, pressure uses a conservative upper bound rather than
subtracting bytes that might belong to another ticket. Content refusal preserves the structural
observation and records both capture-budget and content-unavailable gaps.

Unknown capture inventory is also durable service-maintenance demand, even when the outbox
and selected buffer are empty. The READY observation sweep can reconcile that demand before any
new native input is admitted (#695). It uses an existing unambiguous lifecycle mapping and the
same authoritative catalog/bundle inventory as capture reservation; it does not invent a source
event, a task binding, or a zero-backlog proof. Missing mappings and unreadable or inactive relevant
routes remain unknown and are retried without requiring another hook. A healthy proven workspace
does not request another recovery scan.

A known inventory can still hold one stranded handoff: a ticket and reservation whose structural
row was already acknowledged or quarantined, so nothing will consume it. Its age alone held the
oldest-age dimension at the hard limit with an empty queue, closing admission and content for the
whole workspace until an unrelated authority change (#836). A handoff at least 30 seconds old is
therefore also maintenance demand. After inventory is known, the same sweep turn opens at most
eight owning task routes through the catalog, oldest first, and retires a handoff only when current
authority no longer backs it or no outbox row or selected input can still deliver its row. The
ordering (structural rows read before tickets, under the capture lock) cannot retire a handoff that
is about to be consumed. Genuinely pending handoffs keep their pressure: this does not relax the
pending-age limit, raise a capture ceiling, or clear pressure directly. Once the stranded age is
gone, hard admission reopens at once and optional detail follows the unchanged recovery dwell. The
coordinator rotates a bounded per-workspace cursor through that deterministic candidate order after
each attempted batch, so an unavailable prefix cannot starve a later route. The cursor is only a
scheduling hint and does not change route, task, or capture authority.

Retirement accounting is a durable boundary before destructive cleanup. The local
`content_capture_unavailable` marker and payload-free retirement record commit under the stable
ticket identity before the ticket is tombstoned or its central reservation is released. A failure
or cancellation leaves the handoff active and retryable. A retry reuses the ticket identity and
does not duplicate the loss count or diagnostic when accounting already committed before the
failure. Replay identities for tickets with active reservations are pinned within the bounded
outstanding-ticket set, so repeated retirement failures cannot evict an accounted handoff's key.

A sweep rotates through at most four workspace candidates with a shared five-second cooperative
recovery budget inside its ordinary sweep budget. A workspace turn rotates through at most eight
existing session candidates, then performs at most one complete inventory bootstrap. Session
cursor hints are bounded to 256 workspaces; eviction loses a hint, not accounting or authority.
Recovery does not hold the general workflow/control gate or an outbox drain lease. Publication
uses the same capture lock as reservation. Both complete catalog scans use worker-owned read-only SQLite connections; opening,
querying, decoding and closing happen in the worker, never through the shared catalog writer.
Synchronous task metadata reads and local publication also run off the service event loop; cancellation joins started worker operations before releasing
the lock or runtime. These joins can exceed the cooperative deadline. The deadline is not a hard
promise about a contended storage operation's elapsed time. Every opened runtime must match
its catalog task/session identity. The service/vault generation is checked before inventory reads,
after the final catalog reread, and under the local publication lock, so an obsolete READY
instance cannot mint a replacement proof after waiting for that lock. Partial ticket enumeration
cannot authorize releasing a reservation merely because its identity was not returned.

A recovered inventory proves accounting, not spare capacity: real count, byte, pending-pair and
capture ceilings still govern admission. Recovery neither deletes loss/quarantine history nor
creates complete task coverage. Retained, fully routed loss lanes are now independent durable
maintenance demand (#695). Before capture recovery, each workspace turn attempts at most eight
pending loss lanes, rotating past unavailable routes. A lane binds source, native session,
source generation, original task/session/writer and capture-authority generation. One permanent
`observation_input_loss` evidence marker per lane is appended through the existing observation
writer and encrypted-payload commit path, followed by an internal task observation gap and advice.
Only then is the local lane acknowledged. Reporting never replays the rejected input, advances a
source cursor, grants content capture, changes loss counts/identities, or claims recovered bytes.
The marker says at least one input was lost; exact cumulative counts remain in local accounting.
Retries and restarts resolve the same task-wide operation before staging another payload.

New checks reconcile this task's pending routed losses before freezing their case. Existing
check operations preserve their original frozen inputs and idempotent results. Transient or
unrecoverable publication failures remain fail-closed instead of omitting known task loss. A
terminal route drift or quarantined marker operation may use the already authenticated runtime
for the same task and a distinct deterministic recovery operation identity; the marker retains
the original route and never retargets the loss. Route-valid lane-digest mismatches receive an
explicit unreconciled loss marker; ranges whose route or source identity cannot be authenticated stay in local
accounting and are never assigned to a task from a parser failure. Historical loss attribution survives
same-task session supersession; it is never rebound to a new task or represented as a new
observation under the current capture grant. Original authority identity remains part of the
report even after that grant changes: reporting already-recorded loss is structural maintenance,
not new observation or content permission.

The existing 64-range retention bound still applies. Unrouted input and overflow-only aggregate
history have no provable task attribution and remain visible locally; they are never broadcast
to every task or assigned to a later mapping. A recovered/empty queue is not evidence that earlier
losses were absent. Lane acknowledgement adds only private, bounded retry state; an older writer
forgetting it can cause a replay but cannot duplicate the stable ledger marker.

**Amendment (tb4n1 B3): bounded inheritance and a recorded cause.** One refused startup input
used to mark every later observation of its lane (source, native session, generation and route)
with `observation_input_loss`, so a single refusal made a whole task's evidence unprovable. The
lane marker above is unchanged: the task still learns once that its lane lost input. What later
evidence inherits is now bounded to what the lost input could affect. Each loss lane keeps a
private, content-free detail beside its range: up to 16 pairing commitments (the same
source/session/generation-scoped digests used for pre/post pairing) of the host calls whose inputs
were lost. A later input inherits the gap only when its own call, or the call that spawned it,
matches one of them: the post of a lost pre, any later input of a call whose post was lost, or
a child of a lost call. An input with no host call identity (a prompt, a session boundary) has no
partner and marks no later input. A lane that loses more than 16 paired calls, a range recorded
before this detail existed, or a range advanced by an older writer (which drops the detail; the
detail's count must equal the range count to be trusted) keeps the previous route-wide
inheritance. Only commitments and closed codes are stored; raw call ids never enter the detail.

The detail also records the closed refusal cause: `queue_count`, `queue_bytes`,
`session_queue_count`, `session_queue_bytes`, `protected_reserve`, `session_fair_share`,
`pressure_count`, `pressure_bytes`, `pressure_capture_backlog`, `capture_scope_unknown`,
`state_bytes`, `flush_failed`, or `unknown` for a range recorded before causes existed. The wire
loss-range shape in observe status is unchanged. The cause is surfaced through the hook notice
(`...; see observe status; cause=<cause>`) and the closed `admission_loss_<cause>` hook-diagnostic
reason in `hook_diagnostics.reasons`, recorded at the same once-a-minute cadence as
`outbox_overflow`. The lane's causes also travel with its pending loss report, so the
service-authored lane marker evidence (task `status view=evidence`) ends its fixed description
with `Refusal cause: <codes>.`, and a receipt whose coverage carries `observation_input_loss` adds
`Recorded refusal cause: <codes>.`, read only from `hook_observed` marker evidence and only as
closed tokens. The marker's lane and operation identities are unchanged. Bounding the loss's
proof effect on findings (the lane marker still folds `observation_input_loss` into every later
check) is follow-up #1014.

The tb4n1 startup refusals had a concrete source. A capture reservation is created unconfirmed and
confirmed only after its staging ticket commits outside the store lock. Admission pressure treated
any unconfirmed reservation as unknown capture scope, drove the capture dimension to its hard
limit, and refused every native input in that window (one run recorded a refusal 28 ms after a
1.4 s reservation hold). Under a proven inventory, admission pressure now charges an unconfirmed
reservation at its reserved byte bound instead. Reservation and recovery keep their stricter view:
a new reservation still waits for the confirmation, the unconfirmed reservation remains recovery
demand, and an unproven inventory still refuses admission (now recorded as
`capture_scope_unknown`).

Detailed and larger capacity default to a current-session override. Workspace persistence is an
explicit owner choice. A preview precedes non-default authority and describes scope, expiry,
finite budgets, and increased storage and processing costs. Expiry, revoke, reset, and lowering a
setting affect future admission. Accepted records drain under a finite over-target transition;
they are not deleted to make occupancy match a lower selection. The transition's byte bound is
defined in the #843 amendment below.

Selection is local operational state under ADR-014, not an artifact replacement or a privacy
grant. The preview binds the requested detail, capacity, exact scope and expiry to an acceptance
digest. Local CLI/TUI apply requires that digest; ordinary MCP status is read-only. This records
an owner-attested operational choice and does not authenticate OS user presence. An agent may
relay it only after the owner explicitly accepts the displayed scope and costs. Repository
configuration cannot silently grant Detailed or a larger session override. Content and disclosure
changes continue through their independent ADR-012/ADR-016 authority paths.

Pressure is driven by the worst relevant count, byte, pending-pair or capture-backlog
constraint. Rising pressure reduces optional content first. High pressure temporarily makes a
selected Detailed session effectively Focused. A hard limit pauses replayable ingestion at the
last durably accounted input and records bounded loss for non-replayable input. Sustained low
pressure restores only a still-valid owner selection, with hysteresis and a recovery dwell.

The initial thresholds are 65% rising pressure, 85% high pressure, and a hard stop at 100% of
the worst relevant budget. Under `observation-budget-v3-capacity`, leaving every current
hard threshold transitions `hard_limit` to `high` immediately. Structural admission reopens only
when the whole proposed buffer/outbox transition also fits the selected count and byte limits.
Optional detail remains reduced until all dimensions stay at or below 45% for ten seconds.
Retained diagnostic or quarantine bytes can therefore keep optional detail reduced without
indefinitely reporting a hard admission stop after pending work drains. Background maintenance
advances the dwell even when no new hook arrives; a status read never starts it.

New native input is checked at the shared selected-admission commit under the store lock.
Already accepted buffered transfers and raw outbox replay remain drainable. A generation-fenced
session end removes its pressure snapshot; ended lanes do not keep idle maintenance scheduled.
An unfinished session keeps its snapshot across restart. Ending a session does not erase its
pending rows, quarantine, or loss history.

Status distinguishes selected and effective settings, origin, scope and expiry, current pressure,
and historical loss. A downgrade and a recovery each produce one notice; actual loss and stalled
recovery use bounded aggregation. Status reads and successful redundant FinishUP bookkeeping must
not amplify their own observation traffic.

### Evidence and receipts

The stages observed, retained or summarized, delivered, and selected for a particular check are
distinct. Summary coverage does not claim per-call content coverage or a successful verification.
An empty queue and recovered pressure do not erase historical loss.

Promotion can use only retained native identities and their original subject-state provenance.
Where historical bytes are no longer retained, reacquisition is a new observation of a new time
and state. It cannot retroactively prove the earlier state. Unrecoverable history remains a
coverage limitation. No universal raw-content cache is introduced.

JSON, markdown and text receipts describe the same bounded coverage. Existing AI-powered review case
capacity refusals, exclusions, provenance and unresolved findings remain independent of queue
depth and detail mode.

## Validation and rollout

Performance acceptance uses synthetic or public-safe replay with measured upstream capture,
serialization and writes, rather than ledger row counts alone. The owning issue records the
baseline, proposed numerical targets, measured profile budgets, native-host acceptance, and any
remaining limits before this draft is marked ready. Larger profiles are not validated merely by
passing a count-boundary unit test. No live installation or private corpus is changed by the
implementation or its synthetic benchmarks.

## Amendment — configurable capacity policy, custom counts and the no-FinishUP-cap outcome (2026-09-24, #828)

Issue #828 asks for explicit larger, custom and no-FinishUP-cap choices for multi-agent capacity,
each with a resource and cost disclosure on the terminal interface, the CLI and agent guidance.
This amendment delivers the local structural observation queue dimension end to end and records
the policy for the other dimensions. It does not change any default.

### Capacity dimensions

| Dimension | Owner-selectable finite values | No FinishUP cap | Status |
| --- | --- | --- | --- |
| Structural observation queue | `standard` 512, `larger` 2,048, `largest` 8,192, or `custom` 64..8,192 rows | Unsupported: typed `capacity_no_cap_unsupported`, reason `state_document_ceiling` | Implemented |
| Pending pre/post pairs | Fixed at 256 | Unsupported | Unchanged |
| Native capture lane | Fixed at 512 tickets / 128 MiB per workspace | Unsupported | Unchanged |
| AI-powered review input, output and spend | Hard product constants and privacy-policy fields only | Unsupported: provider and egress ceilings still apply | Out of scope; a separate privacy/egress design change |

A custom count uses the same byte ladder as the three profiles. For a queue count `N`:

- queue bytes are `N × 1 KiB`;
- the aggregate state document is `max(1 MiB, 2 × queue bytes)`, never above the 16 MiB
  `STATE_DOCUMENT_CEILING_BYTES` safety ceiling that the local store also enforces;
- the protected reserve is `max(64, N / 4)` rows and `max(128 KiB, queue bytes / 4)`, each capped
  at half the queue so a small custom count still admits unprotected rows;
- the per-session fair share is `max(1, N / 4)` rows and `max(1, queue bytes / 4)` bytes.

The 512, 2,048 and 8,192 profiles produce exactly the limits in the profile table in Capacity,
pressure, and setting lifetime. The pending-pair,
capture, diagnostic, optional-detail and pressure-threshold values are the same for every count.

### No FinishUP cap

The local observation state is one document that is re-encoded on every save. Its 16 MiB safety
ceiling is a product quota that would defeat any "unlimited" queue selection downstream, so this
storage revision does not offer an uncapped structural queue. A no-cap request is still accepted
as input on preview and apply and answered with the non-retryable typed outcome
`capacity_no_cap_unsupported` (`invalid_request` class). The outcome names the state-document
ceiling and the largest supported finite capacity (8,192 rows, `--capacity largest` or
`--capacity custom --queue-count 8192`) and changes nothing. Status projects the same availability
as the closed `no_cap` object. No surface may label a setting unlimited while this ceiling or a
provider limit applies. Incremental persistence of the state document is the prerequisite for
revisiting this and is not part of this amendment.

### Explicit increases and one disclosure contract

No capacity increase happens automatically, and ordinary task permission never authorizes one. Every
change goes through the existing preview and digest-bound apply. The preview carries the closed
`yoetz.capacity-change-disclosure/1` record: dimension, scope, change (`increase`, `decrease`,
`unchanged` or `unsupported`), current and requested counts with their queue and state byte limits,
closed consequence tokens, the limits that still apply, the unchanged
content/privacy/provider/credential/network authority, the lower, revoke, pause and resume commands,
and `validation_status: not_validated`. Every command in the disclosure and every `next_command`
uses the literal `<workspace>` and `<session-id>` placeholders rather than the typed path or session
id. The CLI human output and the terminal interface render that record through one shared renderer,
and agent guidance tells agents to relay those lines, so the three surfaces cannot drift. An
increase names possible disk, memory and CPU use and possible slowdown of FinishUP or other apps, and
carries the consequence token `workspace_aggregate_raised` with the line that the shared workspace
queue follows the largest active selection, so it can raise the queue and state-document bounds for
every session in the workspace. A decrease affects future admission only; accepted records drain and
are not deleted. The preview digest binds the requested queue count and the change token, but not
live pressure. The selection-preview payload schema tag is `yoetz.observation-selection-preview/2`.
The CLI no-cap failure is a standard ADR-030 failure: `error.recovery` carries the continuation and
directive, and `error.capacity` carries the facts as `{no_cap, alternative_command}`.

Status and the local control projection add a `yoetz.observation-effective-budget/1` record: the
selected and effective counts and labels, why they differ (`selected` or `workspace_aggregate`),
every finite limit, the limiting dimension and its utilization, and the no-cap availability. MCP
status stays read-only and does not expose or change capacity; an agent relays a change only after
the owner accepts the displayed preview through the local CLI or terminal interface.

The shared workspace queue is the largest of the active workspace setting's count (or the 512
default when none is active) and every active session selection's count. A session selection can
raise that aggregate but never lower it, so a session-scoped custom count below 512 lowers only
that session's own admission and never a sibling's.

### Defaults, allocation and upgrade

Focused with `standard` (512) remains the default. The benchmark phase in
[the performance runbook](../runbooks/observation-selection-performance.md) still owns any default
change, and the custom ladder has not been measured.

The intended multi-agent allocation model is a per-task reservation plus a shared burst pool.
That model is recorded as direction only; per-session fair share remains the implemented
allocation.

Saved selections are preserved across upgrade and the settings document keeps the queue count as
an integer. Local control schema `2.9.0` accepts custom counts, capacity labels and the
effective-budget record; both peers must run the `2.9.0` manifest to exchange them. An older
revision reading a saved custom count treats it as malformed, drops that selection to the default,
and does not report the drop. That is a disclosed limitation of downgrade, not a supported path.

## Amendment — a finite over-target drain keeps accounting writable (2026-09-25, #843)

### Problem

Lowering, revoking or letting a larger selection expire, or ending the session that held it, can
leave the state document above the 1 MiB fallback. The store used the current file size as the
byte bound for that drain. Accepted rows were kept, but no write could grow the file. Accounting
for refused input (`outbox_overflow`, `observation_input_loss`), delivery-attempt metadata, and
a local session end all failed as `storage_unsafe`. A hook's capture batch rolled back with them,
so the hook reported a refusal as accounted when it was not. The native `SessionEnd` hook
discarded the failure, so the session and its temporary override stayed active.

### Decision

While accepted rows exceed the lowered selection, a write that does not fit the ordinary bound
may use a finite over-target bound. Accepted rows exceed the selection when their count is above
its queue count or their admission bytes are above its queue bytes. The bound is:

- the selected state bytes;
- plus the persisted bytes of accepted pending rows and buffered inputs above the selected queue
  bytes;
- plus a fixed 128 KiB accounting reserve;
- never above the 16 MiB `STATE_DOCUMENT_CEILING_BYTES` and never below the current file size.

Accepted rows carry their own persisted bytes, including delivery-attempt metadata. Everything
else has the lowered selection's non-queue budget plus the reserve, including loss and lifecycle
accounting. That accounting is count-bounded (at most 256 session gap maps and 64 loss ranges),
so recording refusals cannot raise the bound. Only admission and drain change accepted rows, and
admission is closed while the queue is over target. The bound shrinks as rows drain. It ends when
they fit the selected target, and the ordinary bound applies again.

The bound is never used outside an over-target transition. An ordinary full queue keeps the
standard retention ladder, and the standard pressure seam is unchanged. Retention still trims
disposable classes to the bound first. When protected state cannot fit even then, the write
still fails without replacing the previous durable state. Landing within the over-target bound
is not evidence of health: an active truncation gap clears only with headroom under the ordinary
bound.

Admission is unchanged. New host input, including protected and lifecycle observations, is
refused and accounted while accepted rows exceed the selected target. The 600-rows-over-512
backlog still reports `outbox_overflow` and keeps its rows.

A `SessionEnd` hook whose local session end still cannot persist stays fail-open. It prints
`hook_observe_degraded: session_end_unrecorded` and records the bounded `session_end_unrecorded`
hook diagnostic instead of discarding the failure.

### Unchanged

No wire field or schema changes. Status keeps reporting the lowered selection's limits. The
transition shows as over-100% utilization with `pressure_state: hard_limit`, beside the queue
counts and bytes, gaps, and loss accounting. The per-write cost of a large state document is also
unchanged: each acknowledgement during a 2 MiB drain rewrites the whole document. Incremental
persistence remains the prerequisite for revisiting that.

### Amendment: delayed delivery is not exhausted capacity (#887)

Oldest pending age remains diagnostic and maintenance demand; it is not an admission or content
budget. A delayed row or capture handoff must not refuse later input, force Detailed to Focused,
or disable content while real capacity remains. This supersedes the pending-age pressure policy
above, including the historical #836 description. Existing handoff retirement and authority
checks remain unchanged. Count, byte, session-share, pending-pair and capture ceilings still
refuse unsafe admissions; existing losses remain reported. The shared policy applies to Codex,
Claude Code, Cursor and session-stream observation on every supported OS.

A persisted old hard-pressure snapshot reopens structural admission as soon as current resource
usage is below its limits; optional detail recovers through the existing low-water dwell. Age
continues to be reported unchanged, including across retry and restart, so sluggish draining is
visible without turning a delivery delay into unrecoverable evidence loss. It does not claim
unbounded retention. Because content is no longer disabled at 60 s, a stall can keep capturing
content up to the existing 128 MiB per-workspace capture ceiling.

Retaining input moves the steady-state backlog from about one minute of input to the session fair
share (2,048 rows at `largest`). Two measures keep that affordable and drained:

- **Hook-side cost.** Pressure sampling on each hook admission now reads one memoized size and
  protection fact per retained row and derives each delivery unit's length arithmetically, instead
  of re-encoding every row. On an Apple-silicon reference run at 2,048 retained rows (1.37 MB
  state), `commit_selected_admission` fell from about 28 ms to about 10 ms median. The remainder is
  the single-document rewrite, which stays bounded by the 16 MiB state ceiling and is still
  proportional to state size; incremental persistence (an append-only outbox segment) remains the
  prerequisite for a write cost that is independent of backlog size.
- **Drain cadence.** Every hook observation ingest arms a coalesced sweep wake (at most one early
  pass about every second), and while idle the service polls a lock-free, read-only probe every
  5 s and sweeps as soon as any outbox row is waiting that no drain has attempted. Rows that
  already failed an attempt keep the 60 s idle interval, so the poll cannot become a retry storm.
  Consecutive progressing passes continue as before. The 0.2 s hook drain budget and the 60 s
  idle interval are unchanged and remain non-configurable.

Loss at real ceilings is still counted in `unrecoverable_input_count` and reported by status.

## Amendment — one action per host call and the standing orphan record (2026-09-30, #917)

The maintainer acknowledged this design-gated scope on issue #917 on 2026-09-30. Codex sessions
recorded about 1.8 `action_recorded` rows per real tool call: a pre that was delivered on its own
minted a pending action keyed on its envelope, its post minted a second action keyed on the call,
and each code-mode `exec` cell added an independent action beside its nested calls. Separately,
the append-only `unpaired_event` record kept raising a "wait for drain to recover" advisory that no
wait could clear.

### One action per host call

A paired profile's individually delivered pre now keys its pending action on the host call
(lane, session, source generation, correlation, family), the identity the post's action already
used. The phase that reaches the task ledger first records the action. The service appends the
later phase without the action draft only when the task ledger already projects that exact action
event, so its result and captured evidence link to the committed action; any other state appends
the full batch as before. This is a delay, not a drop: an individually flushed pre still becomes a
pending action at its five-second deadline, a post whose pre never reached the ledger (for example
a FinishUP-owned call, #564) still records its own action, and no post or its outcome is dropped. The
dropped duplicate is not an input omission and is not counted as one.

The materialization mapping version stays `obs-ledger/1.7.0`: every other identity, including
every Claude Code and Cursor post-only record, is byte-identical. The pre's operation digest is
unchanged, so a pre committed before the upgrade replays its committed operation; a call spanning
the upgrade keeps its historical second action, never a third, and no history is rewritten.

A Codex code-mode `exec` cell fires no hook of its own; each nested `tools.*` call fires its hooks.
The session-stream reader decides per cell. It always keeps the cell's call row in the local store,
since whether the nested calls are hook-recorded is known only later, and keeps the output local
too only when a Codex tool hook (`PreToolUse`/`PostToolUse`; lifecycle hooks do not count) of the
same host session was ingested after it read the call and before the start of a complete stream
pass that still did not see the output. Such a hook fired while the cell ran, so the nested hook
rows are the ledger's record of the cell; a hook ingested after the output was written (the next
cell's) never settles before the output is read, so it cannot remove this cell's record. Otherwise
the output is delivered and records the cell, so a cell whose tools fire no hook keeps its record
in any session. The decision is durable per cell and does not use the session's earlier hook
history: a first decision taken before the cell's evidence could exist would be irreversible, and a
manual or early reconcile, or a session forgotten by the bounded map, would then record a hooked
cell twice. The per-session hook stamps and cell decisions are bounded maps that forget the least
recently active entry, which can only make an output deliverable; cells stored in the earlier
count format are migrated. The option of recording the cell as the explicit parent of its nested
actions was not taken: nested hook payloads carry no cell identity to link. Residual limits: a cell
mixing hooked and unhooked tools stays local, so its unhooked tool is not recorded; the decision
follows the order in which the reader sees rows relative to hook ingestion, so a hooked cell whose
call is read only after all its nested hooks, whose nested hooks no complete pass settled before
its output, whose hooks fired before an upgrade from the count format, or whose entry the bounded
maps forget before its output keeps its own action (a second record, not a loss), and a hook
landing while an unhooked cell runs can keep that cell local; an interrupted cell whose output
never reaches the rollout adds no record of its own; a retained wrapper counts in `observed_count`
without an accounting bucket.

### The standing `unpaired_event` record (decisions for the set)

- **B1.** The durable record is unchanged: an orphan post keeps `unpaired_event` in the observation
  store, check coverage, `status` coverage and the receipt, through resume and restart. It is no
  longer a stale-observation cause: it does not raise `observation_gap_or_stale` and does not keep
  the lifecycle `degraded`. The advisory names its live cause first (`cause:<gap>`). For source
  lag, cursor stale, drain backlog, service unavailable and vault locked it clears on recovery.
  `unsupported_event` and `unsupported_format` keep their pre-#917 advisory; they never clear in
  session, and classifying them as standing records is a follow-up (owners #917/#913).
  `host_outcome_unavailable` is a ledger coverage code that never fed the advisory; it stays
  disclosed either way.
- **B2.** A distinct new gap is a new `(source, session, source generation)` orphan scope. The first
  orphan in it queues one local notice, delivered once in hook `PostToolUse` context and not
  repeated, across restart. The notice map holds 256 scopes and makes room for a new scope by
  forgetting its oldest delivered notice, so new scopes keep getting notices; only a scope older
  than 256 newer announced scopes can be announced again, and again after further churn. It is informational, not a ledger record or finding: it never counts
  as unanswered, never adds `findings_unanswered`, and cannot be answered or supersede a check.
  Count growth inside a scope is not re-announced.
- **B3.** The optional one-time acknowledgement depends on #905's `acknowledged_not_done`
  disposition, which has not landed. Until it does, no acknowledgement is requested; the standing
  gap is disclosed on the receipt whether or not the agent acts. Receipt naming stays with #913.
- **`finding_frontier`.** Every `status view=findings` item carries the frontier of the ledger event
  that carries the finding's current record (sequence plus that event's entry digest), for every
  origin. `respond` accepts it as-is (status result schema 1.4.0, golden vector CAN-014). #911 owns
  the matching guidance and `respond` error text.
- **Deferred.** The optional disclosure-only orphan count and last-seen time in observe status and
  receipt coverage needs a control-schema revision and is not part of this amendment. The advice
  policy version is unchanged so existing advice finding identities do not churn; the historical
  advisory finding already in older ledgers is #911's.

## Amendment — separate standing coverage from recoverable observation health (2026-10-04, #974)

The maintainer acknowledged this follow-up under tracker #961. The durable observation record and
the operator status surface must retain coverage limits, but a standing limit must not manufacture
agent work. The local fallback store and SQLite store therefore use one shared material-gap set;
`unpaired_event`, `truncated_payload`, `content_capture_unavailable`, `pending_attempt_expired`,
and `content_unselected` remain visible coverage records while a source is mapped, fresh, and
draining. A recent, progressing outbox drain is healthy even when one row is still pending; a
missing or stale drain, a freshness timeout, an unmapped source, a material acquisition gap, or an
unsupported event can still keep lifecycle status degraded or stale.

Only the named recoverable causes `source_lag`, `cursor_stale`, `service_unavailable`, and
`vault_locked` produce the agent-facing `observation_gap_or_stale` / `refresh_observation` advice.
Unsupported formats and events remain disclosed to operators and in coverage, but an agent refresh
cannot repair them. A lifecycle label by itself, an empty observation path, a standing gap, or a
pending outbox row never creates that advice.

The one-time orphan notice remains available to local operator inspection after restart, but is no
longer copied into Codex, Claude Code, or Cursor hook context. Codex `PreToolUse` observation is
synchronous so its pairing identity is committed before the matching `PostToolUse`; the other
pure-ingress hooks retain their asynchronous behavior. This is a timing and presentation change,
not a new capture grant or a claim that every native call is observable.

## Amendment — optional bounded wait for the caller's hook observations before a check (2026-10-07, #1012)

The maintainer approved this protocol change on #1012 (TB4 run tb4n1 follow-up P3-1). In tb4n1, 39
of 40 Stop-gate texts said hook observations were still draining, checks carried
`check_current_as_of_earlier_frontier`, and agents polled `status` (790 calls in the 30 blocker
attempts) hoping the record would catch up. The Stop drain (#994) settles a task's rows at Stop;
a mid-session `check` still froze whatever the ledger held.

### Decision

- `check` accepts an optional boolean `await_observations` (check-request 1.1.0, unreleased,
  additive in place; MCP `check` and `finishup check --await-observations`). Omitted or `false`
  keeps today's behaviour and bytes.
- When `true`, the service, before it takes either dispatch gate and before the case freezes,
  snapshots the local hook outbox rows that belong to the check's task: rows of every host session
  whose lifecycle mapping names the check's FinishUP session, across all workspaces with pending
  delivery work. This is the same task rule the Stop gate uses (`observation_task_pending`),
  minus the Stop hook's own unmapped host session, which the service cannot name. The service
  wakes its observation sweeper and polls that real local state until none of the snapshot rows is
  still pending, re-waking the sweeper about once a second. Rows that arrive after the snapshot
  are not waited for. (Extended on 2026-10-13 to the task's rollout rows held for pairing; see
  the tb4n5 amendment below.)
- The wait is bounded by about 3 s and by a tenth of the request's deadline, whichever is
  smaller. It runs inside a detached semantic check's own operation, so an MCP call's bridge
  deadline (#886) still covers it.
- The check result carries the closed `observations_awaited` member (check-result 1.4.0,
  unreleased, additive in place) only when the request set the flag:
  `{"state": "complete" | "bounded_timeout" | "unavailable", "pending_count": "<decimal>"}`.
  `pending_count` is how many snapshot rows were still pending when the wait ended; `complete`
  and `unavailable` (the local outbox could not be read) carry `"0"`. The CLI human rendering
  and the MCP check summary show one short line.
- The wait never fails, refuses, or reorders a check. A `bounded_timeout` means the check used the
  record as it stood; the existing freshness gaps still say so.
- The flag is outside the operation identity: the check request digest and the detached-check
  identity drop it, so a same-request recovery may set or omit it, and requests without it keep
  their digest. `observations_awaited` is not recorded in the ledger or in `check_recorded`; it
  describes only the call that asked for it, and a replayed request runs and reports its own wait.

### Surfaces

MCP `check` (all three hosts: Codex, Claude Code and Cursor reach the same tool) and the CLI.
The terminal interface does not set the flag: its checks are operator-initiated and not tied to
an agent host session's outbox; it still renders the line if a result carries it. Receipts do not
carry the member.

## Amendment — image tool results as local digest-only evidence (2026-10-07, #1013)

Owner decision (P3-2): "just ack the image, don't send it".

### Problem

tb4n1 lost image tool results (`view_image`, screenshots read back, MCP image blocks) at the old
hook ingress cap, and an agent that inspected its rendered deliverable then had no FinishUP-held
record that it had looked. The review packet cannot carry images, so the agent had nothing to cite.

### Decision

- Every host's observation ingress (Codex `read_hook_ingress`, Claude Code through the same reader,
  Cursor `read_cursor_hook_ingress`), at any body size up to the skim cap, finds image strings
  before it drops media bytes: a decodable base64 string inside an image block (MCP and Claude
  `image`, Responses `input_image`, an object declaring an `image/` media type) or an image
  `data:` URL anywhere. For at most 8 images per event it records the SHA-256 and byte count of
  the decoded bytes, a media type sniffed from the bytes (`image/png`, `image/jpeg`, `image/gif`,
  `image/webp`, else `image/unknown`), and the pixel width and height read from the header only
  (PNG `IHDR`, JPEG `SOFn` with a bounded segment walk, GIF, WebP `VP8`/`VP8L`/`VP8X`). An
  unreadable or zero-size header is `image/unknown` with no dimensions. A string that does not
  decode is not attested. The host's own media label never decides the type.
- These facts travel as the closed structural `observed_images` member of a `PostToolUse`
  envelope (control-request 2.9.0, unreleased, additive in place): 1-8 objects with exactly
  `content_digest`, `byte_count`, `media_type`, and optionally both `width` and `height`. The
  name is reserved; a host value under it is always discarded at ingress.
- The service materializes one `evidence_recorded` 1.2.0 per image beside the call's result:
  `evidence_kind: artifact`, `strength: content_digest`, the image digest, `digest_binding`
  `{subject: artifact_bytes, content_availability: digest_only, byte_count, provenance:
  observation_captured}`, a stable id from the envelope's source identity and the image index, and
  the fixed description `Observed image tool result <media_type> <w>x<h> (<n> bytes); pixels were
  not captured or sent`. The call's `result_recorded.evidence_refs` lists it (an unpaired post
  parents it to its standalone evidence instead). The accepted-event validator admits
  `observation_captured` in exactly this digest-only shape (strength `content_digest`,
  `digest_only`, subject `artifact_bytes`, no captured object, coordinator author on
  `hook_observed`) beside the captured-bytes shape; anything else is refused.
- No pixel is stored as captured content, persisted locally, or sent to any reviewer. The agent may
  cite the evidence id when it states it inspected the output; reviewers see it as present and
  not sent.

### Unchanged

Content selection, consent, and the content budget are unchanged; the image bytes themselves stay
replaced by the media placeholder in any captured tool output.

## Amendment — tb4n5 observation follow-ups (2026-10-13, #1038, #1041)

The maintainer requested this scoped work for the tb4n5 observation lane on 2026-10-13 and decided
two of its questions: a code-mode cell with no tool call and no file change counts as no workspace
activity, and the 0.2 s hook drain budget stays while its counter is renamed and delivery lag is
measured instead.

### Yielded code-mode cells keep their identity until they end

A Codex code-mode `exec` cell that outlives its yield window returns the host-written header
`Script running with cell ID <id>` as its output, keeps running, writes its nested calls after that
output, and returns its further output on later `wait` calls that name the cell in their `cell_id`
argument; the terminal one begins `Script completed`, `Script failed` or `Script terminated`. The
#917/#1038 rule decided a cell at its first output, so in tb4n5's semantic arm a cell whose only
call was FinishUP's own `check` was delivered as an unclassified `exec` action after that check (20
such cells in 5 of 9 attempts; 3 final receipts kept `check_current_as_of_earlier_frontier`).

Decision: the session-stream reader reads exactly two host-written facts, never the cell's
JavaScript: the status header (the first text item of an `exec` or `wait` output, which the cell's
own output follows and cannot forge) and a `wait` call's `cell_id` argument. A yield output is held
with its still-open cell (`runtime_cell`, the `wait` calls that named it, and the held output are
durable in the local store). Nested items read while it is the session's only open cell mark it as
before; overlapping cells keep the no-borrowing rule. The terminal `wait` output decides the cell
by the same rule as an unyielded cell's output; a cell nobody waited on is decided at the turn's
end (`task_complete` or `turn_aborted`). Only a cell that is neither FinishUP's own, nor tool-less, nor
recorded by its nested hooks then delivers its held yield output as its record, stamped with the
position of the row that decided it. The bounded cell map forgets a cell holding an output last.
`wait` polls stay `no_tool_activity`, and Codex's `clock.sleep` (hook spelling `clocksleep`, a
built-in control tool that only pauses the turn) joins the closed no-activity list
(`host_sleep_tool`).

### A cell with no observable tool call is no workspace activity

Owner decision. A cell between whose call and output (or terminal `wait` output) the rollout wrote
no tool item, and while which no tool hook of its session was ingested, made no observable tool
call; its output stays local and it adds no `exec` action. "Tool item" is any completed item family
other than a message, reasoning, compaction or hook prompt (an unknown family counts). The rule
applies only where absence is evidence: the admitted rollout profile records completed tool calls
as items, and the session's rollout has already written one. Elsewhere such a cell keeps its record
as #917 decided. A tool that neither fires a hook nor writes an item (`update_plan`) is
indistinguishable from none and reads the same; FinishUP still never parses the cell's source.

### A pending attempt that ends without its post names itself, and FinishUP's own rejection closes it

`pending_attempt_expired` appeared in 17 of 18 tb4n5 attempts and no export could name the call:
expiry kept only the aggregate gap. A host fires no `PostToolUse` for a tool result that is not a
success (Codex runs post-tool hooks only when the output's `success_for_logging` holds, and an MCP
result with `isError: true` is not one; read in `codex-rs/core/src/tools/registry.rs` and
`tools/context.rs` on the 2026-08-29 `main` branch, not pinned to 0.159.3). In every tb4n5
attempt the `PreToolUse`-minus-`PostToolUse` surplus was at least the number of FinishUP calls the
service rejected, and the one attempt without rejections was the one attempt without the gap.

Decision:

- Each ending is recorded locally with only closed tokens: the reason (`ttl`, `session_end`,
  `generation`, or `rejected_by_yoetz`), the call's structural tool name, its source generation,
  the moment, and an opaque 16-hex digest of its pairing key; a count per reason and the newest
  16 endings. `observe status` reports them as `pending_attempt_endings` (local-only, outside the
  frozen control-result schema, like `summary_refusals`). The first three reasons still record
  `pending_attempt_expired`.
- The FinishUP MCP bridge records each error result it returns for a FinishUP tool whose arguments carry
  a valid `request_id`: only a commitment to the call and the moment, in a bounded owner-only file
  beside the observation state (`observation/yoetz-rejected-calls.json`, 256 newest), and only
  where observation was already set up. A call is its operation scope, not its `request_id`
  alone (replay identity is task, writer and request): the commitment is
  `sha256(domain, tool basename, FinishUP session_id, writer_id, request_id)`, an absent or invalid
  session or writer committing as a fixed placeholder. A `publish_work` with no `request_id` key
  (the default shape since ADR-050; the bridge mints its id after the host's pre-event) commits
  instead to `sha256(body domain, tool basename, session_id, writer_id, canonical arguments)` under
  a separate domain (amendment of PR #1088 round 3); identical id-less bodies share it, and each
  rejection still closes only the oldest matching attempt received before it. A hook pre-event of
  a FinishUP tool keeps the same commitment on its pending attempt; every host adapter computes it
  from the payload the host sent (Codex directly; Claude Code and Cursor before their structural normalization drops
  `tool_input`, passing only the commitment on), so it works on every paired profile. An
  oversized hook body whose skim kept no `tool_input` commits to nothing and keeps the ordinary
  expiry.
- A pending attempt whose commitment matches a rejection recorded at or after its receipt closes
  as `rejected_by_yoetz` without the gap. A rejection younger than 5 s waits (so a host that does
  send a post for an error still pairs it), except for an attempt that is about to expire for any
  reason (deadline, session end, newer generation): a known rejection wins over every expiry,
  since no post can pair with that attempt any more. Each rejection is claimed installation-wide,
  under the record's lock, by the one attempt it closes (an opaque digest of the attempt's pairing
  key and receipt), so it never closes attempts in two workspaces; the claim is idempotent for its
  attempt, so a store transaction rerun under the lock or retried after a rollback keeps it. The
  record is best-effort: a missed or unreadable rejection leaves the ordinary expiry, which stays
  disclosed.
- Any other missing post keeps expiring with the gap. The deadline is not lengthened and
  expirations are not cleared wholesale.

### Local retention is not content loss

The envelope ring (`_MAX_ENVELOPES = 256`), the state-size bound, and the dedup fence keep local
copies of accepted inputs as pairing context and replay protection. Every tb4n5 attempt observed
376-2,262 inputs, so every attempt crossed the ring and recorded `truncated_payload`, whose public
meaning is a payload cut to a bounded prefix. Shedding those copies now records only its own local
reasons (`_local_envelope_retention`, `_local_dedup_evicted`), reported by `observe status` as
`local_retention` with first and last sightings and never as a gap. A pairing the ring can no
longer prove keeps `unpaired_event`, and `envelopes_truncated` still blocks retiring an old orphan.
Real clipping keeps `truncated_payload` where it was reported before: on the hook row whose
captured content was cut to its cap, and in the reconcile result for an oversize or unreadable
rollout line. An active `truncated_payload` flag a store
recorded for retention before this change is no longer pinned by the retention reason and clears
once the state bound has headroom, as #310 decided for the bound itself.

### The pre-check observation wait covers held rollout rows

The #1012 wait snapshotted hook outbox rows only. A rollout tool item that no hook post joins is
held for pairing (#910) and released only by a later post, the turn's end, eight idle reconciles
or the soft bound, and every new session activity resets its idle count. In tb4n5 biped S such a
row (occurred 19:43:07) was accepted 12m55s later, 3 s after check 530 reported `complete`, and
made that check stale. The service has no on-demand stream reconcile, so the wait cannot settle a
held row from the rollout; it can only release it or report it.

Decision (contract change to the #1012 amendment above): when `await_observations` is set, the
snapshot also covers this task's held rollout rows (host sessions whose lifecycle mapping names the
check's FinishUP session). Each one read at least 10 s before the wait is released by the wait itself,
exactly as the idle bound releases it: delivered once with `unpaired_event`, stamped with the
session's committed stream frontier, so it lands before the case freezes while its attribution
stays unproven and no outcome is decided for it. A younger row stays held and counts as pending.
A held row keeps one wait identity while held and once released into the outbox, so
`observations_awaited.pending_count` counts the snapshot's hook rows and held rows still
undelivered, and `bounded_timeout` is the disclosure of a held remainder the wait could not settle
(it is never reported `complete`). No schema changes: the member's shape is unchanged and its
count now includes held rows. A row that is genuinely a copy of a late post is delivered as a
second, disclosed record rather than lost, as the idle bound already does. `observe status`
reports the held account as `held_rollout_items` (`count`, `oldest_read_at`). The Stop gate's
count is unchanged.

### Drain counter and delivery lag

Owner decision, recorded with the drain budget it qualifies (ADR-022 amendment of 2026-10-13): the
0.2 s per-hook budget stays, `drain_budget_exhausted` is renamed `drain_pass_delivered_nothing`
(one pass delivered no row within the budget; the rows stay queued), and the exported delivery
measure is the outbox delivery lag, enqueue to acceptance, in `observe status` as `delivery_lag`.

### Per host

Yielded and tool-less cells, `clocksleep` and held rollout rows are Codex-only: Claude Code and
Cursor have no code-mode cell, no rollout stream and no `clock.sleep`; each host runbook records
the decision. The rejected-call record, attempt endings, local retention, the drain counter and
delivery lag are host-agnostic and apply wherever a paired profile keeps pending attempts or a
hook drains the shared outbox, on macOS, Linux and Windows through WSL 2 alike. Native-host
benchmark evidence for these changes is pending on the next tb4 run.
