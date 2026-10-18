# ADR-022 — Harness observation writer identity and observation-tolerant optimistic concurrency

**Status:** Accepted (2026-08-13), recorded for issues #214–#223 and acknowledged in issue #225.
**Amended:** 2026-09-05 for issue #494 / ADR-027 (observation writer stays per task/session;
only inventory-designated shared-mutable workspace routing or verification-job scheduling authority
may become project-scoped once multiple live tasks share a repository); 2026-09-04 for issue #577 (pending observation rows follow a superseded session
binding after ended-session recovery attach); 2026-09-04 for issue #560 (task-scoped operation identity across workflow
reattach, decision 18); 2026-09-03 for issues #539 (content-bearing committed replay) and #540
(terminal ingest rejection and retry ceiling); 2026-08-30 for issue #302 (captured observation ledger
evidence) and issue #331
(frontier-motion recovery across rewinds and restarts, decision 11); 2026-08-29 for
issue #445 (standing-grant parks are not an observation barrier); 2026-08-27 for issue #418 rollout
replay repairs; 2026-08-18 for the
maintainer-directed issue #346 incident repairs #350, #351, and
#352 (decisions 12–14); 2026-08-18 for maintainer-authored issues #320 and #326 and issue #322
(delivered frontier-motion high-water); 2026-08-16 for maintainer-approved issue #224; 2026-08-14
for moderator-approved issue #244 and the reopened issue #216 recurrence; 2026-09-05 for issue #605
(workspace recovery revalidation and durable lifecycle repair, decision 20); 2026-09-05 for issue
#607 (host/profile pairing contracts, scoped orphan diagnostics, and identity fencing, decision 21).
**Amended (continued):** 2026-09-06 for issue #616 (bounded host-hook maintenance: lightweight
ordinary-profile ingress and bounded native-content draining, with cancellation limits kept
explicit); 2026-09-06 for the native capture handoff and FIFO/check barrier contract; 2026-09-07
for the source-qualified, profileless Codex hook capture handoff and its independent AI-powered review
selection fence; 2026-09-25 for issue #836 (a handoff its own structural row can no longer consume
is retired at delivery, by the READY sweep, or at the CHECK preflight, and drains send a content
profile only with their own host's rows); 2026-09-26 for the reopened issue #689 (shared-store
contention: observable lock ownership, lock-free committed reads, host-window lock budgets,
change-proportional critical sections, and non-overlapping sweep settlement, decision 23);
2026-09-30 for issue #915 (no hook delivers a notice for observation-authored frontier motion,
decision 11); 2026-09-30 for issue #911 (observation-authored, non-actionable findings are
disclosed limitations, not response work; see the section at the end).
**Implemented by:** `src/finishup/application/observation_materialize.py`,
`src/finishup/application/observation_coordinator.py`, `src/finishup/cli/observe_hooks.py`,
`src/finishup/adapters/memory/ledger.py`,
`src/finishup/application/publish_work.py`, `src/finishup/application/receipt.py`,
`src/finishup/kernel/policies/observation_advice.py`, `src/finishup/service/ready_composition.py`, and
`src/finishup/adapters/integrations/observation_local.py`.
**Relates to:** ADR-009, ADR-010, ADR-020, and
issues #214, #216, #217, #223, #224, #225, #226, #227, #244, #302, #320, #322, #326, #331,
#445, #494, #539, #540, #560, #577, and #607.

**Proposed amendment for issue #231:** `provider_not_ready` remains bounded local advice, but the
observation coordinator does not materialize it as an agent-facing finding. Provider readiness is a
machine condition rather than a repair to the recorded work. A requested check still records the
exact AI-powered review status and coverage limitation, and receipts retain that limitation; the
amendment does not make the affected receipt clean. This is the narrow option that preserves
proof-based finding resolution and does not change `ResponseDisposition` or finding-kind traits.

## Context

Live observation and cooperative MCP publication share one task-global ledger frontier. Observation
originally reused the cooperative writer, so each delivered hook moved the frontier held by the
agent and made state-sensitive `publish_work` race continuously. Splitting the writer alone is not
enough because the optimistic guard is task-scoped. `check` has the same problem after freezing a
case: an intervening observation makes its exact-frontier commit fail terminally.

Observation also converted lifecycle prose into claims the agent did not make and derived advice
finding identity from the entire changing envelope snapshot. That made delivery capable of creating
unsupported claims and unbounded duplicate findings.

## Decisions

1. Each task session has a deterministic observation writer:
   `observation_writer_id(task_id, session_id)` calls `stable_observation_id` with
   `kind=IdKind.WRITER`, `source_identity=session_id`, mapping version `obs-writer/1.0.0`, and role
   `observation`. `_admitted_writers_for_session` unions that derived id with the writers admitted by
   completed starts; derivation does not grant durable authority. Existing observation operations
   are looked up under both this writer and the legacy cooperative writer during an upgrade.

   A second `start` is not an admission mechanism: attach semantics mint a fresh session on every
   start path. A synthetic `start_operations` row would assert a start that never happened in the
   table whose history establishes that fact. A separate catalog table would require a migration
   and a resume lifecycle for an identity that is already a pure function of task and session ids.

2. A record is observation-authored only when all four facts hold: actor id is
   `yoetz:observation-coordinator`, actor type is `harness`, authorship assurance is
   `harness_observed`, and publication channel is `hook_observed` or `engine_derived`. Actor id and
   type are caller-supplied, so they are insufficient alone. Assurance and channel are service
   derived; ordinary requests cannot select either admitted observation channel.

3. A stale `expected_frontier` is tolerated only when it is behind the real head and every
   intervening accepted record satisfies that four-fact predicate. The new batch appends at the real
   task head and reports that head as its subject frontier. Any cooperative, importer, or otherwise
   authored intervening record still conflicts. Dry-run applies the identical rule. Append
   computation and commit share one critical section so no concurrent append can invalidate ledger
   digests or assigned sequences between them.

4. Check acquisition may accept a caller frontier behind the live head only across an
   observation-authored suffix. It freezes the case at the live head, under a transient in-memory
   reservation that defers observation appends until the durable frozen-case barrier is installed.
   The reservation is never persisted and expires after 60 seconds if acquisition stalls.
   Observation-authored append attempts while either barrier is active receive retryable
   `OPERATION_PENDING`; the durable outbox retries after the check commits. A check parked on a
   standing-repository-grant suspension (`suspension_kind=repository_grant`) is not an active
   barrier: no provider job exists, the lease is expired, and the ceremony may never complete.
   Observation appends proceed; same-request replay re-installs the barrier when it reclaims the
   lease. The same holds for any pending check whose lease is no longer live under the current
   owner generation: its invocation went away (or a previous service generation died holding it),
   nothing renews it, and it may never be replayed. A frozen case is therefore an active barrier
   only while its lease is live. Before issue #838 an abandoned check deferred the structural
   delivery of its task's capture handoffs forever, and decision 22's barrier then refused every
   new check on the task: two retryable waits that could only ever release each other. Commit keeps the frozen subject frontier — the verdict is never retargeted to a frontier
   it did not inspect — and tolerates an observation-authored suffix after that frontier the same
   way acquisition and `append_batch` do, appending check events at the live head. Cooperative or
   importer motion still conflicts.

5. Receipt acquisition may keep its caller-supplied subject frontier across an
   observation-authored suffix only when the supplied projection is the exact genesis-prefix replay
   at that frontier and the suffix contains no `finding_recorded` event. The receipt document stays
   pinned to that subject frontier. Its locator append repeats the finding-free suffix check so a
   finding drained between availability inspection and append still conflicts. Material motion,
   spoofed observation authorship, a mismatched prefix projection, or a finding-bearing suffix
   returns the shared retryable `FRONTIER_CONFLICT` shape with repair facts.

6. Hook envelopes are observation evidence, not agent claims. Completion-like lifecycle signals
   materialize as metadata-only `evidence_recorded` events. A narrow claim path exists only when the
   structural payload explicitly carries an admitted `claim_kind`. Mapping version
   `obs-ledger/1.3.0` separates these identities from historical observation-derived claims and
   gives paired hook/stream results source-independent action/result IDs. Before staging a new
   `1.3.0` append, upgrade replay checks both the session observation writer and the legacy
   cooperative writer for committed `1.3.0` and `1.2.0` operations. A `1.2.0` hit carries that
   mapping version through logical-identity claim repair, preserving the original operation and
   claim identities for a committed-but-unacknowledged outbox row instead of duplicating them. A
   replayed `1.2.0` operation cannot be assumed to carry a host-stated result: it may be a
   pre-upgrade hook operation whose committed result is `UNKNOWN`. Its `1.2.0` record identities
   cannot be re-derived under `1.3.0`, so the correction path consults the committed result through
   the replayed operation's accepted event ids, skips the correction only when the committed result
   already states the same explicit fact, and otherwise binds the correction (with `dedup_conflict`
   coverage on a contradictory explicit fact) to the exact committed legacy action and its committed
   action event as causal parent.

7. Local advice finding IDs are condition-scoped over policy, kind, rule code, and detail
   token. Evidence refs prove the condition but never identify it: several rules intentionally cite
   a rolling or accumulating envelope window. Candidate subject refs map only their source envelopes
   to ledger event ids; a standing condition with no envelope anchors to the session lifecycle
   event. Once a readable finding for that condition exists, later evidence-window or frontier
   changes do not append another `finding_recorded` event. The current observation snapshot and
   coverage/gap state retain the changing evidence context without growing the durable finding set.
   A rule whose cause is one host tool call keys its detail token on the logical call, never on the
   observed phase or event position: the `PreToolUse` and `PostToolUse` phases of one edit are one
   condition. The key is fenced by source, session commitment, source generation, and the admitted
   `correlation_id`/`tool_call_id`, falling back to the envelope's source identity so a post-only
   profile still reports its one observed phase without a fabricated pre-event. Two tool calls
   remain two conditions, a call id reused across a source, session, or generation boundary never
   coalesces, and both phases stay in the evidence refs (issue #680).

8. `provenance_disputed` is the fourth `ResponseDisposition`. It records that the responder
   contests the finding's authorship or provenance premise, requires a non-empty reason, and may
   carry evidence, but is not scored as an evidence-free rejection by either local policy
   pack. It never resolves or erases the finding. Public compact/readiness projections expose two
   distinct counters: `unanswered_finding_count` decreases after any readable response, including a
   provenance dispute, while `receipt_blocking_finding_count` continues to count current actionable
   findings whose receipt state remains `resolved=false` for every disposition.

9. Standing provider-readiness advice is not converted into a `material_limitation_omitted`
   finding. That finding kind remains actionable for an omission in the work account. Provider
   configuration and availability remain visible through observation advice before a check and
   through the check coverage vector and receipt limitations after one.

10. [ADR-029](ADR-029-smart-observation-selection.md) moves routine-read selection before optional
    capture and queue admission. The adapter classifies only a closed set of read tools and
    conservatively parsed shell commands as routine candidates. A pre-event remains an attempt
    until an explicit successful post-event arrives. Proven successes may become a bounded
    source summary; failures, missing outcomes, ambiguous commands and protected evidence remain
    individual. The materializer accepts an explicit summary account and does not silently
    coalesce an individual delivery again. Detailed mode retains individual routine records
    within the same content and disclosure authority.
    Routine reads are never promoted to checks, and deterministic observation advice moves its
    verification baseline only on typed check evidence: a current `passed` approved-check fact, or
    an explicit success reported by a dedicated verification tool whose tool identity names the
    check (`test`, `pytest`, `cargo_test`, `npm_test`, `uv_run_pytest`). A successful generic host
    shell (`shell`, `Bash`, `bash`) proves that the tool returned, not that anything was verified,
    so it neither establishes a baseline, nor carries one past a later edit, nor supports a
    completion claim or a live-wire claim. Check identity is never inferred from command text or
    from a host-supplied `action` label, and a non-current, failed, stale or unknown check fact
    establishes no baseline. Consequently `edit_after_successful_check` reports staleness only
    against a real check: a session that never ran one is covered by
    `completion_without_verification` and by the check coverage vector instead (issue #681). The
    failed and unresolved-command rules still read every command-bearing tool, including generic
    shells: narrowing what proves a check does not narrow what reports an outcome.

11. Every newly accepted observation-authored append records one bounded pending frontier-motion
    notice for the originating Codex session. A retry of a completed append whose local notice
    write did not land reconstructs that notice from the committed append's frontier metadata.
    After the notice's bytes reach the hook consumer, the store retains that session's delivered
    high-water frontier (`to_sequence` plus `head_digest`), scoped to the announced task ledger,
    so a later replay of the same append is not re-announced. The coordinator also supplies the
    routed ledger's actual current frontier: a historical completed-operation replay may carry an
    older result frontier while the current lineage is still at or beyond the delivered mark, so
    the older result digest alone never proves a rewind. When the actual current sequence is below
    the mark, or is at the same sequence with a different digest, the stored mark and stale pending
    notice are discarded and announcement restarts from the rewound lineage. A known limitation: a
    rewind that re-appends past the mark's sequence before the store next observes the lineage is
    indistinguishable from continued append under this predicate, so the replaced range at or
    behind the mark is not re-announced. Otherwise candidates
    at or behind the mark are dropped and overlapping candidates are clamped to the undelivered
    remainder so `from` and record count describe only motion not yet announced. A mark recorded
    for a different task likewise neither drops nor clamps: when a session's mapping moves to
    another task, the stale mark and any pending notice for the old task are discarded so the new
    ledger's motion is announced from its start. Contiguous undelivered appends coalesce their
    from/to sequences and record count. The per-workspace notice and delivered-mark maps persist
    per-entry recency ordinals, evict ended sessions first, then evict the least-recently-used entry
    at the cap even after restart. A legacy delivered mark without frontier-digest and recency
    identity is ignored, failing open to a duplicate rather than suppressing unknown lineage.
    Amended for issue #915: no hook delivers this notice any more. Every recorded notice
    describes observation-authored motion, and such motion leaves a held cooperative publish
    frontier admissible, so the notice carried nothing an agent could act on; its text asked for
    `status` between routine tool calls, against the workflow cadence, and agents did not follow
    it (DeepSWE v2: 3,442 deliveries, next-cell `status` 6.9% after a notice against an 18.9%
    baseline). Motion by any other writer past a held frontier still reaches the agent on its next
    state-sensitive operation as `frontier_conflict` (`reason_code` `frontier_changed`) carrying
    the current sequence and head digest as repair facts. The bounded pending-notice and
    delivered-mark bookkeeping described in this decision is unchanged and is no longer consumed
    by a hook; retiring it is follow-up work. Until #915 the notice worked as follows:
    a later advice-safe `PostToolUse` hook surfaced that the motion was hook-observed, explained
    that held cooperative publish frontiers remain admissible only across observation-authored
    motion, and directed callers to use repair facts when an operation still conflicts. The
    pending notice was removed only after its bytes reached the hook consumer. When a contiguous merge races that
    peek/commit window, identity mismatches; commit still advances the delivered high-water to
    the peeked frontier (sequence and digest) and clamps the merged remainder rather than
    re-announcing the emitted range. When the queued same-task notice instead sits below the
    emitted frontier — or at its sequence with a different digest — it proves the emitted lineage
    was rewound away after the peek, so commit records no mark and leaves the rewind notice
    queued so the new lineage's prefix is still announced. It grants no authority, changes no
    optimistic-concurrency predicate, and adds no MCP operation.

12. Paired `PostToolUse` materialization consumes every host-stated outcome fact: `exit_status`
    remains authoritative; without it, explicit `denied`, boolean `success`, and a closed
    `result_status` spelling table map to `SUCCESS`/`FAILURE`/`PARTIAL`. The Claude ordinary
    `claude-code-hooks-ordinary-v2` mapping additionally treats the host's `PostToolUse` event as an
    explicit tool-level success fact, because Claude emits that event only after a tool call succeeds;
    it never turns that fact into a fabricated `exit_status: 0`. Its `PostToolUseFailure` event and
    explicit denial, interruption, error, invalid/unknown status, partial status, or conflicting fact
    remain failure/partial/unknown according to the closed parser. A background Bash launch is only
    partial without completion evidence. Other mappings retain the generic rule: only a payload with
    no outcome fact at all records `UNKNOWN` — a missing outcome is never upgraded to success. Such a
    record keeps its durable per-call action/result identity but carries the
    `host_outcome_unavailable` known gap on its entry coverage. Because check coverage and receipts
    fold per-record known gaps into one deduplicated code set, any number of outcome-less observed
    calls surface as one bounded task/session coverage condition. The research-evidence policy
    excludes exactly these records — result outcome `UNKNOWN`, no exit status, and source coverage
    carrying the service-derived `hook_observed` channel that decision 2 keeps unselectable by
    cooperative requests — from per-result `material_limitation_omitted` candidates. Explicit
    observed `FAILURE`/`PARTIAL` results and cooperative `UNKNOWN` results remain individually
    limiting, an outcome-less result still cannot support a completion claim, and the receipt
    retains the limitation through the coverage gap even when no actionable finding is emitted.
    Historical rows are not rewritten; mapping identity is unchanged so in-flight outbox replays of
    committed appends still deduplicate (issues #346/#350).

13. The retryable `OPERATION_PENDING` that decision 4 applies to observation appends during check
    acquisition or a frozen-case barrier — and the adjacent transient `BUNDLE_BUSY` and
    `FRONTIER_CONFLICT` coordination shapes — is designed back-pressure, not failure. The
    coordinator rejects such an ingest with the retryable `operation_pending` reason without an
    unexpected-exception diagnostic; drain paths keep the row pending without recording a coverage
    gap or a failure-shaped hook diagnostic, and the reason never projects into observation
    status, advice, coverage, or receipt inputs. Losing the nonblocking drain lease records
    nothing: the holder is a live hook or the service sweeper, and flock releases with a dead
    process. Hook drain-budget expiry records `drain_pass_delivered_nothing` (named
    `drain_budget_exhausted` before 2026-10-13) only when the pass moved no
    backlog; a bounded slice that delivered or quarantined rows and then yielded to the sweeper is
    working as designed. Genuine `SERVICE_UNAVAILABLE`, vault, storage, and preflight failures
    keep their existing visibility (issues #346/#351).

14. A mapped session's advice snapshot is constructed from that session's own retained envelopes
    and session-scoped lifecycle/gap health, resolved from the ingest envelope's session
    commitment or the durable workspace session route. The workspace-wide aggregate remains the
    operator surface and the source of deliberately standing machine conditions (composition
    facts), but is never a silent input to a mapped task snapshot — completing at the construction
    layer the delivery-selection boundary #250 established (issues #346/#352).

15. A hook `PostToolUse` with no outcome fact may commit `UNKNOWN` before the session stream later
    supplies an authoritative exit outcome for the same call when its selected mapping does not make
    the event itself authoritative. The Claude ordinary v2 mapping is the explicit host-event
    exception described in decision 12; its event-level success still does not invent an exit status.
    The original row is never rewritten.
    A replayed canonical operation consults the current projection and appends an idempotent
    `result_correction` linked to the same canonical action when it enriches `UNKNOWN` or exposes a
    contradictory explicit fact. Explicit outcomes are
    never downgraded or overwritten. Correction operation/claim identities bind the exact outcome
    and exit status: exact retries replay, while contradictory explicit facts append separately with
    `dedup_conflict` coverage so neither fact is silently discarded. Correction is part of ingest
    acceptance: if the candidate-findings projection is missing, lagging, rebuilding, or lacks a
    readable core result, the coordinator returns retryable `SERVICE_UNAVAILABLE` and the durable
    outbox row remains pending. It does not acknowledge the already-committed core append alone,
    because doing so could permanently lose the authoritative correction; a repaired or rebuilt
    projection lets the same row replay and finish idempotently.
    Amendment (issue #1019, tb4n2): a Codex hook advances its session generation at every
    `SessionStart`, including the `compact` start after a context compaction, while the session
    stream's generation follows the rollout file, which compaction does not rotate. The call
    identity includes the generation, so a completed stream command first looks for its hook
    call in the other recent generations of the same host session and task (at most 16). It
    materializes under that generation only when exactly one such hook action exists in the task
    ledger, it carries the same keyed command identity, and it holds no explicit outcome except
    one this completion itself recorded; otherwise the stream keeps its own generation. The
    reverse order (a stream completion delivered before a post-compaction hook call) still
    records two actions.
    Amendment (issue #1027, tb4n3 N3-7): the binding is resolved before the completion's
    captured-content manifests are looked up, because those manifests (and the role set they
    reconstruct) are keyed by the call's generation-qualified identity. Resolved after the lookup,
    a hook post that carried captured output committed a captured-evidence role the contentless
    completion could not reconstruct, so the completion was appended as a new operation reusing the
    hook post's result event id; the ledger refused it (`EVENT_INVALID`), the drain quarantined it
    as `ledger_rejected`, and every later command of the compacted session kept its hook
    `UNKNOWN` (183 outcomes in 7 of 7 compacted tb4n3 attempts). One shared predicate
    (`application/observation_committed.py`) now answers "is this observation already in the task
    ledger" for the alignment, the paired-call link and the replay lookup: when no committed
    operation is found under any reconstructable role set but every event of a call-keyed batch
    (event ids derived from the host call, never from a source identity alone) is already recorded,
    the delivery is a duplicate. Nothing is appended and the stream's explicit outcome still
    reaches the recorded action through the same append-only correction; an append the ledger
    refuses as `EVENT_INVALID` is re-read the same way before it can quarantine. Amendment
    (PR #1080, #1078 class): a call-keyed partial overlap is reconciled against the
    current readable projection. The call must already have an agreeing committed action core;
    an evidence-only intersection cannot authorize a new core. Every reused evidence row must
    retain its original causal action and result association with this call, even when a different
    call has its own committed pre-action. Matching core facts are replayed; only missing
    evidence/events are appended under their own role-set operation. Existing events remain immutable. Different
    delivery times, rendering and evidence-reference sets do not change the core. A conflicting
    action/command or existing evidence payload still rejects; stream outcome differences keep
    their append-only conflict correction. A committed result that stated no outcome agrees with a
    later copy that states one (a Codex stream `function_call_output` recorded first, then the
    content-bearing hook post), so that copy's captured evidence and workspace fact are recorded
    instead of the delivery being quarantined; a hook copy whose explicit outcome contradicts a
    committed explicit outcome still rejects (round 7). A smaller committed operation cannot discard new
    captured evidence. One immediate reconciliation also handles an overlap that races append;
    further agreeing races remain retryable rather than quarantined.
    A collision on source-identity-keyed ids (#560) remains a content refusal. This changes no
    capture consent, content authentication, byte budget or provider eligibility rule.
    Late evidence uses the existing optional `evidence_recorded.reference` to name its original action
    event after core and causal-parent validation. Selection follows that link only for service-stamped
    observation-captured provenance and retains the original execution frontier. F1 authenticated
    command/output binding remains required. A captured object already represented by agreeing evidence
    is reused, so another delivery does not make its object-to-evidence association ambiguous. New
    image source identities remain distinct; enrichment operation/claim roles bind the appended event
    IDs. Existing schemas and frozen vectors retain their bytes.
    Amendment (issue #1019, tb4n2 N-4): a retired native content handoff is disclosed on its own
    task. Each retirement appends one marker, keyed by the ticket identity, to the ticket's task
    ledger with the standing gap `capture_handoff_retired`; it never reaches another task and
    names no path or content. Local proof and clean deterministic conclusions tolerate it, and
    AI-powered findings treat it as a capture baseline. The marker is appended before the ticket is
    tombstoned; a retryable or unexpected failure leaves the ticket pending for the next
    reconciliation pass, so an interrupted publication is retried, not lost. Only a ledger that
    terminally refuses the marker (or a route without a writer) lets the retirement proceed
    without it, recorded in service diagnostics, so capture pressure is never held forever. The workspace-level
    `content_capture_unavailable` flag in observation status stays a lifetime workspace flag:
    the local store records it without a task (`note_coverage_gap` takes only the workspace, and
    the status query names no task), so scoping it would need a task-keyed gap store and a
    status query that resolves the current host session's task. The per-task marker is the
    task-scoped signal instead.

16. `obs-ledger/1.4.0` carries trusted observation-content manifests into ledger materialization.
    A manifest binds the encrypted object envelope plus the SHA-256 digest and byte count of its
    secret-scanned inner content. Only tool output, selected changed-file bytes, and workspace diff
    are eligible; the resulting `evidence_recorded/1.2.0` event uses `observation_captured`,
    `immutable_snapshot`, `bounded_excerpt`, and mirrors the object in `artifact_refs`. A linked
    result cites the new evidence; a routine read with eligible retained content is no longer
    coalesced away. Durable inspection facts and bounded excerpts use a separate idempotent
    snapshot operation and separate evidence records, so their provenance is not borrowed from a
    tool envelope. Missing, deleted, or legacy-unbound content weakens to
    `content_capture_unavailable`; policy-excluded retained kinds use `content_unselected`;
    redaction remains visible as `content_redacted`; and bounded inspection prefixes retain
    `truncated_payload`. Replays check current 1.4 identities and the 1.3/1.2 legacy operation
    identities before staging, preserving append-only upgrade behavior.

17. Captured-content chunks remain ephemeral at the hook boundary, but their encrypted manifests
    are durable and indexed by a phase identity derived from the canonical host call plus normalized
    phase. Equivalent hook/stream copies share that identity; Pre/Post/unpaired siblings do not.
    Before materialization, ingest queries both that current identity and the legacy canonical
    identity. The matching legacy source group may supply usable content; every legacy source group
    remains a separate lookup-only candidate so a post-upgrade stream copy can find a hook commit
    without combining sibling phases. It authenticates the object kind, media type, canonical
    envelope, inner bytes, and multipart completeness. Only a complete, readable, digest-bound set
    may strengthen a new materialization. Incomplete, unbound, orphaned, contradictory, or
    unreadable stored metadata is replay-only: it may reconstruct old role tuples for completed-
    operation lookup, but it never grants captured coverage or enters a new append. Once a phase
    has durable manifests, an equivalent-source retry cannot expand the stable role set. The
    content-independent core role tuple is also a replay candidate: if core-only materialization
    committed before content arrived, the later content-bearing copy reuses that operation and
    records `content_capture_unavailable` rather than reminting core event IDs or retroactively
    upgrading coverage. Thus the role-scoped `obs-ledger/1.4.0` lookup safely handles either arrival
    order. Missing, incomplete, contradictory, or unreadable objects remain
    the explicit `content_capture_unavailable` gap; they are never inferred. A non-retryable public
    error from ingest is terminal `ledger_rejected`, quarantines only that envelope, and never projects service
    availability failure. Retryable reasons retain their existing scope, but 128 consecutive
    rejections with the same reason terminally quarantine the row; designed `operation_pending`
    back-pressure and workspace-global pause/vault/disabled gates remain pending under their
    existing recovery contracts. Quarantine stays visible and lets the next FIFO row proceed. This ceiling
    is a defensive bound for future catch-all classification defects, not evidence that a retryable
    failure became successful (issues #539 and #540).

18. FinishUP observing its own MCP workflow is delivered in proportion to distinct evidence (issue
    #564). Every host hook (Codex, Claude Code, Cursor) and the Codex session stream record FinishUP's
    own `start`, `publish_work`, `check`, `respond`, `status`, `receipt`, and `read_guidance` calls
    exactly like any other tool, and the hook process that records them is the same process that
    drains the outbox, so the prescribed workflow's own status/respond/check traffic produced two
    outbox rows plus a content capture per call and starved its own delivery. The service already
    holds the authoritative record of every FinishUP-owned call it served, so the hook adapter and the
    stream reconciler ingest such envelopes into the bounded local observation store
    unconditionally but enqueue them for delivery only when they carry evidence the service cannot
    know from serving the call: an explicit host failure or denial (any phase, any FinishUP tool), or
    the post-event of a mutation (`start`, `publish_work`, `check`, `respond`). The pre-event of
    every FinishUP-owned call and the post-event of a FinishUP-owned read (`status`, `receipt`,
    `read_guidance`) without a stated failure stay local; pairing bookkeeping is unaffected, so a
    delivered post-event still materializes its action. FinishUP-owned tool arguments and results are
    never captured as tool input/output content: they are already durable in the ledger the call
    read or wrote. Tool identity derives from the one registry tuple rendered into every host
    spelling; a name that merely resembles a FinishUP tool is ordinary. Like decision 10 this is a
    delivery-volume policy, not a coverage limitation, so it records no gap. On the consumer side,
    the service sweeper yields with its partial summary on a budget under the daemon's sweep
    deadline, so progress made under a backlog is never discarded as a timeout. Its maintenance
    gate covers one coordinator ingest at a time rather than the complete pass, so ordinary
    workflow control remains responsive while the per-workspace lease and routed task fence retain
    recovery and bundle-rotation exclusion for each row. Legacy hook-spool normalization has one
    generation-owned worker, advances a durable byte cursor in bounded batches, and retains its
    claim future across cancellation before another pass may start; generation close stops between
    batches. Route inspection and fence checks use short-lived read-only snapshots outside the
    service event loop. The manual
    `observe drain` repeats bounded passes while a pass resolves rows and reports a terminal
    condition (`drained`, `retry_pending`, `service_unavailable`, `pass_limit`) instead of stopping
    at the first retryable lane head. `observe status` reports the receipt time of the oldest
    pending row beside the last successful drain so convergence is readable from one call.
18. `obs-ledger/1.5.0` keys the observation operation digest on the task, the canonical logical
    identity, the exact draft-role tuple, and the mapping version only. The stable event ids an
    operation commits are derived from the task and the source identity, never from the routed
    FinishUP session or writer, so the operation that owns them must be findable from every later
    session of the same task. A workflow reattach in one host session (a second `start`) rotates
    the mapped FinishUP session and therefore the derived observation writer; under the
    session-bound `1.4.0`, `1.3.0`, and `1.2.0` digests the repeated envelope missed its committed
    operation, re-minted the same event ids, and was quarantined as `ledger_rejected` (#560).
    Before staging, the coordinator resolves the current identity task-wide through
    `lookup_task_operation`, so an idempotent repeat after a lost acknowledgement, a service
    restart, or any number of reattachments reuses the committed operation without a new append
    or a quarantine row; the same task-wide resolution applies to the task-scoped advice-finding
    operation. A task-wide hit whose stored request digest differs from the candidate digest is a
    conflicting reuse of the operation identity and fails closed as non-retryable
    `IDEMPOTENCY_CONFLICT` (`ledger_rejected`); a repeat that reuses committed event ids under a
    different logical identity still fails closed as `EVENT_INVALID`. Legacy versions keep their
    session-bound digests as replay-only upgrade candidates. During route retirement, the lifecycle
    adapter retains a bounded suffix of predecessor `(session, writer)` bindings in a private,
    same-task sidecar before replacing the one-slot mapping. A fresh process can therefore probe
    the retained predecessor routes after restart; a missing sidecar means there are no retained
    predecessors, a malformed sidecar fails closed, and entries older than the bound are outside
    the replay guarantee. Clearing a host mapping clears its route history as well. Hook ordinals,
    session generations, and host session commitments are keyed on the host session, not the
    mapping, so they stay monotonic across a reattach.
19. An ended-host-session recovery attach that rotates the task route does not retire still-pending
    observation rows of the predecessor (issue #577). `SESSION_NOT_FOUND` with
    `reason_code: session_superseded` already carries the current task binding; ingest follows that
    binding, routes with the observation writer derived for the successor session, and persists the
    updated lifecycle mapping on each hop under its lifecycle lock only if the stored mapping still
    equals the predecessor. Busy locks, changed or cleared mappings, and persistence failures skip
    the cache update without blocking successor delivery. The shared hook recovery path also rewrites every ended
same-host predecessor mapping for that task in the same pass it stores the successor mapping. The
shared hook recovery path takes a nonblocking workspace reservation and ordered locks for every
eligible ended same-host session through full candidate revalidation, the service RPC, authorized
rewrites, and pruning; contention or changed state returns the closed `auto_attach_recovery_busy`
boundary rather than issuing ordinary new admission while the selector is unstable. A
    row refused only because its route was retired is never `ledger_rejected`; a superseded payload
    that cannot be followed (missing or mismatched task/session/writer ids, a hop cycle, or a
    rotation after the route already opened) quarantines that row as `session_superseded`. That
    reason is not `mapping_missing`, so ended-unmapped drain terminalization and the status rule
    that hides `mapping_missing` while a mapping file exists cannot mislabel a mapped retirement.
    `ledger_rejected` remains the terminal class for content and identity refusals.

20. Selected native Codex captured evidence is resolved before semantic case construction
    (issue #509). The application reads through the mapped task's observation and authenticated
    object ports; the pure packet builder receives only immutable, frontier-bound resolution
    values. A captured-object description is structural provenance, never a substitute for the
    captured bytes. Without successful resolution the packet contains an explicit omission.

    Resolution requires active local workspace observation consent, a capture timestamp within
    that grant, a native `codex_hook` envelope, the exact task-derived evidence identity, matching
    source commitment and correlation, complete multipart manifests, and authenticated content
    whose task, kind, media type, digest, byte count and part metadata match. Every member of a
    selected multipart group must authenticate. Current evidence redaction/unavailability wins
    over retained object bytes. SQLite reconstructs descriptors for current referenced native
    captures from the matching task-owned manifest and present object inventory before freezing
    availability. That reconstruction does not assert physical availability: the ledger still
    authenticates the object, and absent or deleted bytes remain unavailable. It repairs the
    composed failure where recovery restored event payload descriptors but omitted independently
    inventoried native captures.

    Revocation, pause or a changed consent record while resolving
    withholds the result. No new consent, profile or source authority is inferred from selection.

    Input, locator, session-stream and message content are excluded before object reads. This
    compatible 0.3 repair supports native Codex source/diff/tool-output objects; Claude and Cursor
    captured objects remain explicitly unselected. It introduces no capture ticket or two-phase
    transport protocol. Capture and outbound disclosure remain independent: the existing selected
    review profile and privacy coordinator still authorize the exact provider case after local
    resolution, and source consent is rechecked around resolution.

    Reads are bounded to 64 candidate/object identities and 256 recent task-owned envelopes.
    Each decoded part must fit both the review selection's byte limit and the resolver's 4096-byte native excerpt limit (below the shared semantic item ceiling); authenticated wrappers have a 10240-byte ceiling. The packet also enforces the
    configured excerpt count and aggregate byte limits. Old, oversized, unavailable or excluded
    items retain their own omissions and coverage gaps without vetoing valid neighbors. A missing
    member cannot be reconstructed from another source or a later successful drain.

    The state bound is the frozen captured snapshot identity and its present availability. It does
    not establish that a source read still matches the current working file; native excerpts keep
    `subject_state_relation=unknown` unless an independently recorded stronger relation exists.
    Packet omissions propagate into the final check and receipt. Local fixture execution, native
    hook execution, retained content, selected provider input, semantic result and follow-through
    remain separate acceptance facts.

## Amendment — multi-task workspace observation home (2026-09-05, issue #494 / ADR-027)

Decision 1 is unchanged: the observation writer remains a pure function of task and session.
Decision 14 is unchanged: a mapped session's advice snapshot is constructed from that session's
own retained envelopes and is never silently fed a workspace-wide aggregate.

ADR-027's bounded reversal of the #250/#352 no-cross-task-state posture does not create a shared
writable ledger and does not let workspace-wide observation become a silent input to another
task's advice snapshot. The #498 ownership inventory must classify each table before #496 moves
anything. Only inventory-designated shared-mutable workspace routing may move to a catalog or
project home; task-owned provenance remains in its task bundle. In the expected `0004` inventory,
`observation_workspace_session_routes` is one expected shared-mutable candidate. The
`observation_verification_jobs` per-workspace running-job uniqueness in `0003` is a separate
expected scheduling-authority candidate. Job results, `observation_inspection_snapshots`, and
`observation_session_advice` remain task-owned unless the inventory proves otherwise. In the dated
Increment-A design, `workspace_task_exists` kept the store single-task-safe until the #497 decision
table was ready. The current 0.3 candidate implements that replacement on automatic
`create_or_attach`: validated ended-session bindings may recover a task, while explicit
`mode=create` still reports the conflict for an identical identity pair. Recovery and migration
compatibility follow ADR-003 and the storage/recovery runbooks; native host capability evidence and
limits remain in the host integration runbooks.

20. Workspace recovery and host lifecycle mutation share a nonblocking workspace reservation and
    ordered per-session locks. The recovery snapshot is revalidated against every eligible
    candidate, including cross-workspace ownership, before the service RPC and again before any
    rewrite or prune. If a hook cannot acquire that reservation, it captures the envelope and
    persists an explicit bounded lifecycle intent; READY and hook drains reconcile those intents
    before delivery. Observation-local schema `/10` carries the intents. Upgrading it is a
    quiesced operation: stop older FinishUP services and host hooks, install the new runtime, then
    restart all services and integrations before writing `/10`; mixed `/9` and `/10` writers are
    unsupported because the `/9` reader ignores the new field and can erase it on save. The
    retention bound protects pending and quarantined evidence, so protected rows may keep the
    total above the clean-binding cap without being deleted.
21. Host hook pairing is selected by the closed source/profile contract, never by an arbitrary
    payload marker. The installed Claude Code and Cursor hook profiles are post-only: Claude's
    `tool_use_id` may identify a result when present, while Cursor's `generation_id` is metadata
    only and can never become a tool identity. Codex remains paired, including when a raw payload
    supplies a conflicting marker; a future paired Claude/Cursor profile must be an exact table
    entry with a real tool-call identity. Local admission performs deduplication, pairing-state
    lookup, envelope append, and pre/post consumption under one store lock. A duplicate therefore
    cannot consume a pre-event, and a concurrent second post records a source/session/generation/
    identity-scoped `unpaired_event` without resolving an unrelated orphan. Historical false
    post-only diagnostics may clear their active projection only when retained envelope history is
    complete; the immutable gap-history record remains. The local state extension is schema `/11`.
    Materialization mapping `obs-ledger/1.6.0` includes source lane, host session commitment, and
    source generation in canonical/action/result identities; legacy 1.5/1.4/1.3/1.2 identities
    remain replayable under their historical semantics.

22. Native Claude Code and Cursor ordinary profiles, and the source-qualified profileless Codex
    hook arm, use a two-phase encrypted-content handoff. The capture-only request runs in a
    separate bounded lane while a heavy structural append may be active. After the local service
    authenticates the request, it secret-scans and encrypts the eligible chunks, durably publishes
    their objects and manifests, and records a metadata-only capture ticket before the structural
    FIFO cursor advances. The ticket binds the encrypted object IDs to the exact
    workspace/task/FinishUP session, host session and source cursor, content profile when applicable,
    original source generation, content-authority generation, and expected content groups/parts.
    For Codex, the source-qualified profileless arm additionally fences the exact active consent
    authority/generation, workspace commitment, `codex_hook` source identity and commitment,
    tool-call correlation, expected multipart groups/parts, object kinds, and object/content
    digests. It contains no plaintext and cannot be borrowed by another event.

    A structural retry consumes a ticket only after revalidating the original source and
    authority generations and proving the complete expected group/part set. A partial, conflicting,
    unreadable, or orphaned set remains `content_capture_unavailable`; no manifest is upgraded by
    inference. Once the complete set is accepted, the structural envelope references the durable
    manifests and the ledger append and ticket cleanup are idempotent. The handoff result
    `content_capture_pending` means the encrypted staging boundary is durable while the FIFO
    ledger append is still pending; it is distinct from `operation_pending`, which is generic
    observation back-pressure and carries no content-retention claim.

    A successor may consume a predecessor ticket only through the existing bounded, validated
    route history for that mapped task and host session. The ticket's original FinishUP session stays
    immutable; sharing a task alone does not authorize borrowing another session's content. New
    checks inspect outstanding tickets across the task, since their frozen projection includes
    predecessor work. Completed same-request replay remains independent of newer handoffs.
    When a new CHECK encounters the barrier, READY performs that inspection as a bounded,
    exact-task preflight before one freeze retry, so a ticket left by a direct capture-only request
    is reconciled even when no structural outbox row remains. A ticket stays pending only while
    current local authority holds it and a pending structural outbox row can still consume it.
    Inactive, revoked, runtime-disabled, profile-unselected, or stale-generation tickets are
    tombstoned; when the capture lock is free, so is a ticket at least 30 seconds old with no
    pending outbox row or selected input left to consume it (#836). An unreadable local state or
    unknown clock keeps the ticket. Tombstoning never changes encrypted objects or retained observation history. A
    completed same-request replay returns before inspecting newer tickets.

    Current authority alone does not keep a handoff consumable (#836). Only the structural row a
    ticket was staged for can consume it, and the drain acknowledges or quarantines that row only
    after the coordinator returns. So the row's own delivery retires a ticket it leaves behind:
    after committing without consuming its matched ticket, or after a terminal refusal, it
    re-reads the durable ticket under the capture lock and tombstones it when the exact
    task/session/source/cursor binding matches. That includes a ticket staged by a capture-only
    request after the row passed its capture fence. A capture-only request whose structural
    envelope the task store already accepted, and which no queued row can deliver again, stages
    nothing (`content_capture_unavailable`). A ticket still stranded some other way (a retry
    ceiling, a session-wide quarantine, a lost release) is retired, independent of native
    admission, by the READY maintenance sweep and by the CHECK preflight when the capture lock is
    free, once it is 30 seconds old and no outbox row or selected input carries its native
    identity. The pending-age limit is unchanged: a ticket with current authority and a queued row
    still counts toward it. A hook drain delivers every lane in the shared workspace but sends its
    content profile only with rows of its own host; another host's row carries no profile and its
    ticket supplies it, so a Codex row drained by a Claude Code or Cursor hook is no longer refused
    as a terminal profile mismatch. Each such retirement records `content_capture_unavailable` and
    a bounded, payload-free local entry naming its ticket identity, stage, reason, ticket state, and
    age. That account commits before tombstoning the ticket or releasing its reservation; a failed
    or cancelled account leaves the handoff retryable, and a replay of the same ticket identity is
    idempotent. Active reservations pin their accounted identities within the outstanding-ticket
    bound, so repeated retirement failures cannot evict a replay key.

    The refusal names its stage: `reason_code: check_admission_capture_pending` with
    `retry_after_ms` and the `check_admission_same_identity` continuation (ADR-030), and `status
    view=operation` reports the stage on the still-`absent` page. The refused check held both
    dispatch gates, which is exactly what kept the handoff's structural delivery from running, so
    the daemon wakes the observation sweep as the refusal leaves; the delivery then runs before the
    caller's bounded replay instead of an idle sweep interval later (issue #838).

    At most 512 `staging` or `pending` tickets are outstanding per workspace. Revoked tickets are
    excluded from that quota but retained as metadata-only tombstones to prevent reuse after an
    authority pause, disable, revoke, or re-enable ABA cycle. A new check/frozen-case acquisition
    observes an outstanding ticket under the same bundle transaction and installs the retryable
    `OPERATION_PENDING` barrier atomically; the same request can retry after the ticket is consumed
    without reminting content or ledger identities. A host kill or service failure before
    authenticated staging completes may leave an honest content gap. There is no plaintext local
    spool or offline acceptance guarantee. The Codex arm admits only explicitly linked hook tool
    output, selected changed-file/code bytes, and workspace-diff bytes for captured-content evidence
    and AI-powered review selection. Its session-stream records remain outside this native ticket
    lane and are excluded from AI-powered review selection. Generic tool input and path/locator content are
    excluded from AI-powered review selection. Recognized visible edit arguments are projected
    separately as diff/changed-file content from the post-tool event, with workspace-relative locators (ADR-006). Captured-content staging does not authorize egress: AI-powered review
    case selection still requires effective repository privacy authority and an independently
    authorized provider/attempt route. Codex's historical session-stream path otherwise remains
    unchanged, while the shared generation, operation-replay, and teardown repairs apply to all
    hosts.

    Acceptance of the Codex arm requires a blocked-FIFO capture with bounded acknowledgement,
    guarded-store materialization through the AI-powered review packet, and negative coverage for
    source, correlation, task/session, authority-generation, multipart, cancellation, restart, and
    retry fences. Metadata-only objects, a successful structural receipt, or a typed MCP result
    alone do not prove that native Codex bytes became eligible provider input.

23. The owner-private local observation store stays one atomically replaced JSON document per
    workspace behind one process-local lock and one cross-process flock, and concurrent native
    hosts, their delegates and the service share it without the lock becoming the bottleneck
    (issue #689). Reads take no lock: an atomic replace makes every read observe exactly one
    committed version, never another writer's open transaction, and a read-mostly operation that
    reaches a write reruns under the lock. Writers keep one transaction per hook capture and one per
    answered sweep row (attempt, coverage gap, lane reason and acknowledgement or quarantine
    together, after the service answered), and both parse the committed document before queueing for
    the cross-process flock (under the process-local lock, so in-process arrival order is kept).
    Immutable envelopes, outbox rows and quarantine entries are encoded once per process and
    spliced as canonical fragments, and a re-read after another writer's commit neither
    re-validates nor re-decodes an envelope whose equal JSON the process already validated, so a
    critical section is proportional to what changed; persisted bytes are identical to inline
    encoding, and a re-read accepts exactly the documents whole-document validation accepts. Each acquisition keeps its two-second
    cap, and a caller may shorten it with one deadline for its whole scope: a hook pass is bounded by
    its rendered host window rather than by two seconds per call, and a sweep by its pass budget. The
    depth-one flock holder stamps a closed role, a code-identifier phase and its monotonic start into
    the lock file; a timed-out waiter reports them in `ObservationStoreLockTimeout`, and hooks and
    the service record timeouts and holds of a second or more as payload-free diagnostics. A
    contended hook capture fails open with `store_lock_timeout` and does not retain that input; a
    contended sweep stops with `observation_store_busy`, and an answered row whose settlement lost
    the race stays pending and replays as a duplicate; a contended pre-admission loss reconciliation
    refuses the CHECK retryably as `acquisition_contended` instead of failing it internally. A
    cancelled sweep cannot stop a worker already inside the store, so the next pass waits for such a
    worker and otherwise yields rather than overlapping it. This decision does not change the
    document format, retention priority, protected pending rows, loss commitments, pairing,
    ordering, or commit-before-acknowledge; an append-oriented representation remains the
    alternative if a measured workload still saturates the serialized write.

## Security and privacy consequences

The observation writer id is derivable from public task/session identifiers, but derivation grants
no publication authority. `publish_work` derives its channel from the closed integration kind; a
caller cannot request `hook_observed` or `engine_derived`, and a spoofed harness actor therefore does
not pass the observation predicate.

The Codex native hook arm is source-qualified and profileless. Active local observation consent
authorizes local encrypted capture for the exact `codex_hook` source; it does not authorize a
Claude/Cursor content profile, AI-powered review selection, or provider disclosure. Only linked
output, changed-file/code, and workspace-diff roles can enter an AI-powered review case after the
repository privacy authority and the individual provider attempt authorize that case.
Session-stream, input, and locator content remain excluded from AI-powered review selection.
Consented input/locator chunks may still be locally staged by the current hook path until the
staging filter follow-up lands.

ADR-009 includes `other_writer` disclosure provenance. When this ADR was written the production
privacy enforcer shipped without a provenance resolver, and it recorded that this harness writer
should then classify as `engine_derived_from_self_authored`: a hook observation is an observation of
the agent's own action, not unrelated third-party authorship. The resolver that shipped for issue
#914 does not implement that forward classification: rows this writer authors stay `other_writer`,
so host-captured prose is never widened into the default `agent_context` ceiling (see ADR-009's
2026-09-29 revision). Adopting the forward classification would be a separate, explicit decision.

## Consequences

Cooperative work can retain a frontier across observation-only delivery, while real cooperative
concurrency still conflicts. Check cases make progress by temporarily applying back-pressure to the
outbox rather than weakening verdict binding. Observation can contribute evidence and bounded
advice without impersonating the agent or minting the same standing finding indefinitely. Routine
reads retain their local observation evidence without producing an unbounded task-ledger trail,
FinishUP's own tool calls are observed without recursively feeding the outbox they are drained
from, and
cooperative writers learn about frontier motion that actually invalidates a held frontier from the
`frontier_conflict` response of their next state-sensitive operation; observation-authored motion,
which never does, is no longer announced on the hook channel (issue #915). Captured objects
contribute immutable byte identity without being upgraded to validation, reproduction, or
disclosure authority. Observation-advice policy `0.1.3`
applies the condition-scoped identity to new materialization (`0.1.1` first introduced it;
`0.1.2` rebased the standing `provider_not_ready` condition onto per-build structural machine facts
for issue #265; `0.1.3` keeps the full evidence basis while bounding advice projection and requires
an explicit authored completion claim). Historical duplicate findings remain append-only evidence;
this change does not erase or rewrite an existing task ledger.

## Attempt-derived provider attention (issue #819)

Observation-advice policy `0.1.5` adds two standing machine rules beside `provider_not_ready`:
`semantic_sign_in_required` (next action `renew_provider_sign_in`) and
`semantic_provider_attention` (`repair_semantic_provider`, or `update_yoetz` when pinned runtime
evidence expired). Their fact is a closed attention token (`sign_in_required`,
`credential_rejected`, `access_denied`, `quota_exhausted`, `model_unavailable`,
`runtime_update_required`) that the service derives from the last terminal attempt's closed failure
class and runtime failure stage per configured binding. A provider answer clears it; transient,
policy, and recovery outcomes leave it unchanged. The token is in-memory per READY generation, so
recomposition after setup, sign-in, or restart starts clean, and it adds no durable field, schema,
or egress. The rules fire only while the path is configured and structurally ready, are delivered
at the #241 SessionStart/Stop cadence with #249 scoping, are never materialized as ledger findings
(ADR-022 #231 amendment), and model-derived advice may not name their next actions. Hook text keeps
the token and adds a plain instruction to tell the user and offer a subagent fix, leaving sign-in,
credentials, and approvals to the user.


### Captured-envelope retention within the bounded ring (2026-09-28, #883)

Captured object manifests and ledger evidence can outlive the observation ring. A semantic
resolver still needs the original, source-qualified envelope to authenticate those bytes; an
exact-object lookup cannot recover an envelope that FIFO retention already deleted. SQLite now
protects the newest 64 content-bearing envelopes per workspace inside the existing 256-event
ring. The remaining slots retain the newest other events. No queue, disk, capture, or disclosure
ceiling is increased, and no plaintext is added to structural storage. The protected subset is
bounded and rotates when new captures arrive; this is not permanent retention or reconstruction
of historical state. At least 192 slots remain available for recent structural events.

The exact-reference lookup remains workspace/session fenced and the resolver still authenticates
consent, manifests, objects, and ledger provenance. Evicted, redacted, revoked, or unavailable
captures remain coverage gaps. Already-pruned envelopes cannot be repaired by upgrading. This
shared SQLite behavior applies to Codex, Claude Code and Cursor on macOS, Linux and WSL 2.

### Failed-command supersession and the keyed command identity (2026-09-30, #909)

A rerun is a new host tool call, so keying "resolved" on the call id left every red -> green cycle
unresolved. Observation-advice policy `0.1.6` makes `failed_command_unresolved` read the same kernel
predicate the local packs and the ADR-025 claim invariant read (`kernel/observed_failures.py`): a
failed command envelope is still reported only while no later post-event of the same *command
identity* followed it (only the latest limiting run of a command is judged), and the same host call
did not later succeed. A later failure or partial run of the same identity is a new condition; an
unknown outcome does not certify repair and never revives an earlier one. An edit post-event never
retires the failed verification.
Cursor's ordinary shell tool `Shell` is a command tool for this rule.

An observed edit changes the workspace state but does not establish that a failed verification was
covered. A failed run therefore remains live until a later run of the same keyed command succeeds,
or reruns with another limiting outcome, or the claim explicitly acknowledges it. An unknown
outcome does not certify repair, and an edit never retires the failure. The receipt keeps the
failed run as a limitation until one of those bounded resolutions occurs.

This section computes the commitment on hook paths, the legacy spool, and the session stream. A
Codex `CommandExecution` carries the same installation-keyed commitment when the local key is
available, so a later keyed run can supersede it; a row without a commitment keeps
`omitted:structural` and remains live until explicit acknowledgement. Same-command supersession
is active wherever the keyed commitment is available.

The command identity is a new structural envelope field, `command_commitment`: an installation-keyed
`hmac-sha256:` value (domain `yoetz/observation-command-commitment/v1`, the local observation
store's key material) over the host command argument (`tool_input.cmd`, `command`, or `argv`) of a
shell/exec tool after light, semantics-preserving normalization: unquoted runs of spaces and tabs
collapse to one space, and a host shell wrapper (`/bin/bash -lc`, `bash -lc` including the WSL 2
form, `sh -c`) is stripped when its argument is exact (an argv wrapper, or the canonical
single-quoted string form). Quoting, expansions, escapes and line breaks are never rewritten, so
commands with different shell meaning never share an identity. The hook process computes it and
discards the text; the text is never persisted, displayed, or sent, with or without content consent.
Edit tools (for example `apply_patch`, whose `command` argument is a patch) never carry one. The
value crosses the unreleased control-request `2.9.0` wire, materializes as the command action's
`omitted:<commitment>`, and the hook spool carries it for legacy replays. A plain `sha256` of a
short command is dictionary-guessable and is never an identity. Legacy envelopes without the field
still clear through the edit rule. The same predicate names only service-stamped observations, so a
cooperative publication of a copied commitment proves nothing.

## Observation-authored limitation findings (2026-09-30, issue #911)

**Context.** The observation advisory "Observation coverage is incomplete or stale" (rule
`observation_gap_or_stale`, kind `ledger_stale_or_incomplete`, priority 3, not actionable) was
materialized as the same condition-scoped finding in every Codex session of the 2026-09 DeepSWE run
(decision 7 gives it one stable id per condition). No check returns such a finding and no agent
action in the task can repair a standing host-profile gap, yet it counted in
`unanswered_finding_count`, set `findings_unanswered`, and a response to it after a check superseded
that check (a response to a finding the check did not return was always material), forcing an
identical recheck.

**Decision.** A finding is an *observation limitation* when its readable projection row was
recorded by a service-stamped observation-authored `finding_recorded` (decision 2's four-fact
authorship test) and its kind is deliberately classified as a limitation: it is in the explicit
allowlist `kernel/projections.OBSERVATION_LIMITATION_KINDS` (only `ledger_stale_or_incomplete`) and
its closed `actionable` trait is false (`kernel/projections.is_observation_limitation`). The
decision is structural; no finding id is special-cased, and an unreadable row is conservatively not
a limitation. The allowlist, not the generic trait, is the authority: a finding kind added or
reclassified as non-actionable later stays response work, and keeps superseding a check when
answered, until a change adds it to the allowlist with its own rationale.

1. An observation limitation is never response work. `unanswered_finding_count`, the compact
   `unanswered_findings` preview, `closure_readiness.findings_unanswered`, and the durable SQLite
   mirror share one rule (`kernel/projections.unanswered_finding_ids`).
2. An `acknowledged` or `provenance_disputed` response to an observation limitation does not
   supersede a recorded check: neither disposition is scored by a local policy pack, so a recheck
   cannot change the result. A `rejected` or `waived` response to it, and any response to another
   finding the check did not return, remain material (issue #911 open question 1): the
   work-integrity and research-evidence packs score those dispositions, so the recheck is
   productive (an unsupported rejection of the advisory returns `questionable_finding_rejection`).
   The reducer
   applies this through `ReplayIndex.observation_finding_event_ids`; receipts, receipt capacity, and
   compact status coverage apply the same predicate over the accepted records, so status and
   receipts cannot disagree. The attributable suffix still carries
   `check_current_as_of_earlier_frontier`, and the receipt names the acknowledgement.
3. Nothing about proof changes. The row stays in `view=findings`, keeps its resolution requirements
   and `resolved` state (it does not become resolvable), contributes its coverage gaps, and stays on
   the receipt as a coverage-limitation finding with any recorded acknowledgement. Its detail adds a
   bounded explanation naming it a disclosed limitation. The finding kind table, the finding and
   response schemas, and `ResponseDisposition` are unchanged.
4. Existing ledgers need no migration: replay applies the rule to their accepted history, so an
   advisory row written by an earlier build renders as disclosed history rather than as unanswered
   work after upgrade.
5. The hook `refresh_observation` clause asks the agent to wait only while `finishup observe status`
   reports lag or a drain backlog, and says that a remaining gap is a standing limitation needing
   no response or recheck. Which observation conditions raise the advisory, and how the sticky
   `unpaired_event` surfaces, are decided in issue #917.

**Consequences.** Acknowledging the advisory once is optional and final; a service restart or
session reattach does not reopen it because its condition-scoped id is not re-recorded. A later
distinct condition is a different finding. This applies to every host (Codex, Claude Code and
Cursor) on macOS, Linux and WSL 2, because the rule is service-side.

### Codex tool outcomes read where Codex states them (2026-09-30, #910)

Decision 12 consumes host-stated outcome facts, but on Codex the only reader was the
`apply_patch` `Exit code: N` prefix. Codex 0.157.x sends no top-level outcome: a shell, exec or MCP
result states it nested in `tool_response`. Every Codex shell result was therefore `unknown`, and
every Codex session carried `host_outcome_unavailable`. The Codex hook mapping now reads the
closed facts of each tool family on every `PostToolUse`. Shell and exec tools contribute the exec
result's `exit_code` (an object, or JSON text that carries a Codex exec-result key) and the
`Exit code: N` / `Process exited with code N` line of the function-output header, which ends at
`Output:`. `apply_patch` contributes that header. MCP tools contribute only the protocol-level
`isError`. The facts pass through the shared native reducer, so `exit_status` stays in `-1..255`,
conflicting facts resolve failure-first, and a result with no fact stays `UNKNOWN` with the
`host_outcome_unavailable` gap on that record only. Output text is never read. Selection
classifies the same facts, so a failed read cannot be summarized as a proven routine success.

The session stream now names a rollout `event_msg`/`item_completed` command, MCP or patch item as
the completed tool call it is (event kind `item_completed`). Its `status` and `exit_code` become a
result instead of an opaque row, and `exit_code: null` states no outcome. Where the hook call id
equals the rollout item id, decision 15's correction path applies unchanged. The item's id
(`exec-<uuid>`) normally does not join the hook's call, so it follows #917's code-mode wrapper gate:
once Codex tool hooks have admitted input for the session, the item stays in the local store with
the wrapper's accounting unless it is the only carrier of a hooked call's outcome. Items pair with
hook posts per call, in arrival order: an item whose id is an outcome-less hook call (a process
still running when its hook fired) is delivered and decision 15 corrects the hook's `unknown` row;
a command item whose exit matches an unpaired stated post of the same command commitment is that
post's copy; otherwise, while an outcome-less call of that commitment is unpaired, the item is
delivered as that call's exit, a second action for that run which #909 judges as the later run.
Counting per call means one call's stated outcome never withholds another call's only exit. An
item read before any hook post it pairs with is pending, not a copy. A later post with its call
id decides it directly, and a stated post of its command commitment takes it as the copy when
the exits match. An outcome-less post of that commitment takes its pending items only once no
other call of the same command is open, so parallel same-command runs never trade outcomes by
arrival order. Surplus items are all delivered (a second record over a lost failure). A call whose
`PreToolUse` left the envelope ring stays open until its post is seen or evicted or the turn
ends. `Stop`/`SessionEnd` close the turn: owed calls take their command's pending items, and any
other pending command item stays local only when a stored stated post proves it a copy (same
call id, or same commitment and exit); MCP and patch items, which have no commitment, stay local
as copies. A carrier is delivered once on the next stream reconcile, committed together with its
settlement and stamped with the committed stream frontier at release time, since the task's
per-source cursor refuses an older position. The pending account keeps each item's structural
record. An item with no proof at the turn's end, one the ring evicts before pairing, the oldest
past the account's bound, and one idle for 8 workspace reconciles while its session stores
nothing are delivered with `unpaired_event` as unpaired evidence, so the receipt discloses them;
only the account's hard bound drops an item, with a local gap. A session without tool hooks
delivers every item, with its outcome, as the only record of the call. An `McpToolCall` item that names an `error` or a result `isError: true` fails whatever its
`status`, and a `FileChange` item belongs to the edit family. The Codex outcome reader reads only
Codex's own shell tools (`Bash`, `shell`, `exec_command`, `local_shell`), never a code-mode `exec`
cell, and JSON text only when it carries an exec-result key and a string `output`. Mapping versions
are intentionally unchanged: already-stored envelopes keep the facts they recorded, so
historical `unknown` rows and their gap are not re-materialized. Recording
failures makes the failed-work rules reachable on Codex, so this change is sequenced after the
failure-supersession change of #909. A stream `CommandExecution` item carries the same
installation-keyed `command_commitment` as its hook copy, computed from its `command` argv with
#909's normalization, so supersession spans both paths. Observation-advice policy `0.1.7` adds the
Codex shell spellings `exec_command` and `local_shell` to the commands the unresolved-command rule
reads, beside `Bash` and `shell`. A delivered stream `command_execution` row stays out of the
advice, so the advice never names one run twice. The shapes are
pinned by the OUT-001 fixture, which is derived from recorded 0.157.1 rollouts; a raw hook stdin
capture is still owed on #910.

Amendment (2026-10-18, n7 RC2, issue #1106). Both Codex copies of one call mint the same action
and result ids, so whichever commits first defines the action. Codex writes every `function_call`
row of a turn before it runs them, and the first call's hook reconciles the rollout, so with
parallel calls the other calls' stream rows commit before their own hooks fire; about a fifth of
n7's shell calls were recorded that way, with no command identity or runner class, and planned
verifications that ran were `planned_verification_not_observed`. A rollout `function_call` row of
one of Codex's own shell tools (`exec_command` and the legacy `shell`, `shell_command`,
`local_shell`, `bash`; never the code-mode `exec` cell, `write_stdin` or an MCP tool) now commits
to the command its arguments name (`cmd`, `command`, `argv`, the hook's order) with the hook's
normalization and key, and carries the same segment commitments, runner class and relative write
scope (Codex 0.159 `exec_command.rs` sends the hook `tool_input: {"command": args.cmd}`, and the
hook's `tool_use_id` is the row's `call_id`). Only the post copy carries the compound-outcome gap.
Facts only the hook can know stay hook-only (absolute-path write scope, `effective_user`,
`install_target`; `workspace_effect` is already reconciled). A command containing a secret the
importer redacts commits to the redacted text: a missed match, never a false one. A missing hook
fact never stands for its opposite: `verification_only_as_root` is decided over the verification
runs that state a user, so a stream-first run with no `effective_user` neither raises nor clears
it (#1106 r1). A rollout `CommandExecution` item records an argv (`["/bin/bash", "-lc", CMD]`):
its heredoc patch writes are read through that one host-shell layer.

A Codex 0.159 `Bash` post states no exit, so for a direct `exec_command` call the rollout is the
only place the exit is stated. The reader takes it from the header Codex itself writes before
the output of `function_call_output` (`context.rs` `ExecCommandToolOutput::response_header`:
`Chunk ID`, `Wall time`, `Process exited with code N` once the process exited, `Process running
with session ID N` while it runs, `Original token count`, then `Output:`; or the classic `Exit
code: N` header), matched only as that anchored, closed grammar and never searched for in the
output, and keeps it only when pairing names a Codex shell call (the output row names no tool);
`-1..255` only. A running process states no exit.

When the stream copy committed first without an outcome, the hook copy stating one was refused
as a disagreement and the outcome was lost (#1092 item 1). A Codex hook `PostToolUse` (or
`PostToolUseFailure`) now takes decision 15's correction path like a stream completion: the
committed `UNKNOWN` gets one correction result linked to the same action, and the duplicate check
counts a ledger whose only outcome for the call is `UNKNOWN` as agreeing. A hook copy never records
a disagreement: one that contradicts a stated outcome keeps the ledger's refusal and quarantine
(fail closed, #560), a fact a prior correction already states is not stated twice, and a hook copy
that just recorded its own result reads no projection. A replay may resolve to the stream copy's
operation, so while the projection lags or awaits a rebuild it is refused as retryable
(`service_unavailable`), like a stream copy, and the outcome is recorded on the retry. A replay
into a routed session that opens no projection yet (a workflow reattach rotated it and it has
recorded nothing, #560) is acknowledged without a correction: the stream copy's `UNKNOWN` then
stays, which is a missed outcome, never a hidden one. Mapping
versions are unchanged; calls already recorded identity-less stay so. The shapes are pinned by
OUT-005 (`observations/codex-shell-call-identity-0.159.0.case.json`), derived from the Codex
0.159.0 source; a raw hook stdin capture is pending.

## Amendment (2026-10-07, issue #994): the drain clock, content under a contended lease, and the Stop drain

tb4n1 measured `drain_budget_exhausted` on 94% of Codex hooks, `content_capture_unavailable` in
every attempt, and a Stop gate that almost always read "observations were still draining". The
owner decided: start the clock after connecting, spool durably, and finish the drain at Stop.

1. **The delivery clock starts after the connection opens.** The connect keeps its own
   preflight bound (one second, cold handshake included). Loading the local snapshot and the
   handshake no longer spend the delivery budget, which now covers content staging, lifecycle
   reconciliation, the ingest RPCs and the local commit after each. An optional absolute pass
   deadline clamps both stages. The ordinary per-hook slice is 0.20 s and at most eight rows; a
   content-bearing pass keeps 1.0 s and sixteen rows. Decision 13's rule is unchanged:
   `drain_budget_exhausted` (renamed `drain_pass_delivered_nothing` on 2026-10-13, see below) is
   recorded only when a pass moved nothing.
2. **Transient content is staged even when another owner holds the drain lease.** A hook that
   loses the nonblocking lease still opens its own connection and sends its content chunks as
   `capture_only`. The service commits the encrypted manifests and the retry ticket before it
   answers the capture-pending reason, so the bytes are durable in the vault; the owner or the
   sweeper that later delivers the structural row consumes the ticket. `capture_only` never
   advances the ingest cursor or the ledger, so it needs no lease, and a row the owner already
   delivered is refused as before (#836). This service-side encrypted handoff is the durable
   spool: plaintext is never written to the local outbox. Content that still could not be
   staged keeps the explicit `content_capture_unavailable` gap.
3. **Stop finishes the drain.** Stop is a turn boundary: it flushes buffered routine admission
   accounts, then drains toward the current frontier with a larger slice (2.5 s, 64 rows),
   clamped so the closure gate keeps its five-second status-read reserve inside the ten-second
   Stop window on every host (the drain's deadline sits 0.75 s above that reserve for the local
   commit after the last ingest). While another owner holds the lease the Stop pass waits for that
   owner's progress, and gives up once this task's pending count has not moved for 0.75 s; when it
   holds the lease itself and a retryable refusal delivers nothing,
   it stops at once and leaves the rows to the sweeper. Only rows that can still change this
   task's facts count: the host session's own rows and those of other host sessions mapped to
   the same FinishUP session. Rows of other tasks in the workspace, and of unmapped sessions, do
   not hold the decision. The outcome is a bounded diagnostic, `stop_drain_complete` or
   `stop_drain_incomplete`, and the closure gate receives `observation_pending` only when this
   task's rows remain (ADR-033 decision 5). Claude Code and Cursor ordinary profiles drain at
   Stop too; they no longer defer a contentless Stop pass. SessionEnd keeps its 0.15 s teardown
   slice under the three-second host clamp.

4. **Drain and pass failures name their stage (tb4n2 N-3, issue #1019).** A drain preflight
   records `drain_connect_timeout`, `drain_connect_failed` or `native_content_stage_failed`
   instead of one `drain_preflight_failed` for both the connect and the content handoff; an
   unexpected pass exception records `observe_<exception class>` from the service's reviewed
   closed vocabulary instead of the bare `observe`. The old tokens stay admitted for older rows.

Not changed: `check` does not wait for hook rows (a mid-session check can still be current as
of an earlier frontier); local content cannot be spooled when the service is unreachable,
because the hook holds no vault key.

## Amendment (2026-10-13, tb4n5): keep the drain budget, rename its counter, measure delivery lag

tb4n5 recounted the per-hook drain diagnostic on the same nine tasks: no regression once attempts
and hook volume are normalized (the S arm fell from 17.3 to 12.4 per attempt; an earlier 26.7
compared seven old tasks with nine new ones), and rows still landed within about 1-2 s. The one
row that landed 13 minutes late was a rollout item held for pairing, not drain latency (ADR-029
tb4n5 amendment). The owner decided:

1. **The 0.20 s ordinary per-hook delivery slice stays** (content-bearing passes keep 1.0 s).
2. **The counter is renamed to say what it counts.** `drain_budget_exhausted` is now
   `drain_pass_delivered_nothing`: one hook drain pass that delivered no row within its budget
   (or whose connect preflight left none). The rows stay queued for the next pass or the
   sweeper; it is not lost delivery and not lateness. The hook diagnostics reader reports rows
   written under the old name under the new one, so one cause keeps one tally across an upgrade.
   The reason is local-only (`hook-diagnostics.jsonl`, `observe status` `hook_diagnostics`), in
   no schema or fixture.
3. **Delivery lag is the measure.** Every outbox row records when it was enqueued
   (`enqueued_at`, local wall clock; kept across retry attempts, not part of the row identity);
   its acknowledgement after the service accepted it adds one enqueue-to-acceptance sample to a
   per-workspace histogram (fixed bounds 100 ms to 900 s plus an overflow bucket, with count, sum,
   maximum, last sample and the moment measurement began). `observe status` reports it as
   `delivery_lag` with `p50_ms_at_most`/`p95_ms_at_most` bucket bounds. Rows enqueued before the
   field existed are not measured. A rollout row held for pairing is enqueued when it is released,
   so its hold time shows as `held_rollout_items`, not as delivery lag.
