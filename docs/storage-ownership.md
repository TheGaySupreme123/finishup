# Storage ownership inventory for #496 and #498

**Status:** durable ownership and retention contract for the 0.3 lineage and project series

**Verified:** 2026-09-06

**Owners:** storage and runtime foundation

This page is the durable storage ownership inventory required by issues [#496](https://github.com/TheGaySupreme123/yoetz/issues/496)
and [#498](https://github.com/TheGaySupreme123/yoetz/issues/498). It records the durable owner of each
workspace-keyed store, what may be shared, how an object remains rooted, and which concurrency
and migration rule applies. A workspace reference is an input to routing; it is not authority to
open another task bundle.

## Catalog migration source and generated mirror

The catalog DDL source and generated mirror are part of the durable schema contract:

* `migrations/catalog/0004.sql` and `migrations/catalog/0005.sql` are the hand-authored sources for
  the catalog 0004 and 0005 schemas. Catalog 0005 adds the project-operation request journal; it
  does not relocate project text or task evidence.
* `src/yoetz/resources/migrations/catalog/0004.sql` and `0005.sql` are byte mirrors produced by the
  resource ripple. They are never edited independently.
* The bundle migrations `0003`, `0004`, `0008`, `0009`, `0010`, `0011`, and `0012` remain separate
  sources. Catalog 0004 and 0005 do not move or recreate bundle tables.
* Project, project-operation, lineage, host-annotation, and coordination tables are migration-owned. Adapters only
  validate their presence and issue reads or writes; they do not execute runtime `CREATE TABLE`
  or `ALTER TABLE` statements.

The fixed-point command for a later resource refresh is:

```text
uv run python scripts/sync_resource_ripple.py --write
uv run python scripts/sync_resource_ripple.py --check
```

The source tree and its generated mirror must be compared at the same revision before a release.

## Durable disposition vocabulary

* **stay** means the current owner is durable: task-owned provenance remains in the task bundle,
  and owner-only hook state remains workspace-local.
* **catalog** means the installation catalog is the durable owner of shared mutable authority,
  with its own migration and generation fence.
* **relocate** means an object or projection is intentionally kept with its task owner while a
  structural pointer or liveness fact is kept in the catalog; the pointer never takes ownership
  of encrypted bytes.
* **tested** means the named focused test in the executable dispositions section pins the row's
  ownership, retention, and concurrency behavior.

## Bundle migration inventory

Every table created or rebuilt, and every ownership-bearing column added, by bundle migrations
0003, 0004, 0008, 0009, 0010, 0011, and 0012 is listed below. Indexes follow the table owner and
are included in the table's concurrency and retention rule. Migration 0008 adds content bindings,
0009 rebuilds two tables, 0010 adds the ordinary-content consent profile column, 0011 adds the
capture handoff table, and 0012 adds the asynchronous semantic-advice attempt table; none creates
a shared catalog ownership domain.

| Bundle table or migration surface | Owner and key | Object owner and retention root | Concurrency and migration rule | Disposition |
|---|---|---|---|---|
| `observation_workspace_bindings` (0003) | The task bundle; `workspace_commitment` | Encrypted workspace-locator object in the same bundle; the row and referenced object are rooted by the task's current route | Bundle writer transaction; 0003 is append-compatible and revocation is an explicit state transition | stay; tested for concurrent task-specific reads |
| `observation_content_manifests` (0003) | Task-owned observation provenance; `(workspace_commitment, logical_identity, content_kind, correlation_identity, source_commitment, part_index)` | `object_id` points to an encrypted bundle object; the manifest row and object reference are GC roots until redaction/retention policy permits collection | Insert is idempotent on the declared identity; 0008 adds nullable digest/byte bindings without upgrading historical rows | stay; tested for independent sibling lanes |
| `observation_logical_identity` (0003) | Task bundle materialization index; `(workspace_commitment, logical_identity)` | No plaintext object; referenced content manifests carry the roots | Single bundle writer and unique operation identity; 0003 schema remains readable | stay |
| `observation_trusted_check_policies` (0003) | Task/workspace policy authority; `(workspace_commitment, policy_digest)` | `trust_object_id` is an encrypted policy object rooted by the task's privacy root set | One trusted policy per workspace is enforced by a partial unique index; policy changes are generation-fenced | stay; tested for task-local policy isolation |
| `observation_verification_jobs` (0003) | Task-owned verification scheduler; `job_id`, with workspace query index | Results and any captured output are rooted by the job/result rows and task route | Lease owner and lease generation are checked in bundle transactions; the workspace unique key is task-local because each task has its own bundle | stay; tested for per-task scheduling and unrelated-task fault isolation |
| `observation_verification_results` (0003) | Task bundle; `(job_id, check_id)` | `output_object_id` and result commitments remain rooted by the result row and task retention policy | Result replacement is generation-aware; historical rows remain readable | stay |
| `observation_advice_history` (0003) | Task/workspace advice history; `(workspace_commitment, suppression_identity, evidence_basis_digest)` | `snapshot_json` is structural and rooted by the history row; it contains no unencrypted user prose | Idempotent history insert and ordered frontier index; no cross-task latest-row lookup | stay; tested for session/task scoping |
| `observation_advice_delivery` (0003) | Task/workspace delivery audit; `(advice_id, channel, attempt)` | No separate object; advice history is the parent root | Append-only attempts; retry outcome is a new attempt | stay |
| `observation_inspection_snapshots` (0004) | Task/workspace inspection projection; `(workspace_commitment, yoetz_session_id, subject_state_digest)` | `facts_object_id` and `excerpt_object_id` are encrypted task objects rooted by the snapshot row; 0008 nullable bindings preserve weaker historical coverage | Current-row selection is indexed and updates occur in the bundle writer transaction; 0008 only adds nullable digest/size/redaction flags | stay; tested for concurrent session isolation |
| `observation_workspace_session_routes` (0004) | Task-local projection of workspace to Yoetz session; `(workspace_commitment, yoetz_session_id)` with unique `yoetz_session_id` | No plaintext object; route points at the task/session identity in the same bundle | Active/unbound is a state transition; the catalog's `task_sessions` table is the installation-level liveness authority for the 0.3 foundation | stay as provenance projection; catalog liveness is the shared-mutable surface |
| `observation_session_advice` (0004) | Task/workspace session advice; `(workspace_commitment, yoetz_session_id)` | Structural snapshot only; encrypted detail remains in task-owned objects | Current advice replaces only the same session row; no workspace-wide fallback for task-scoped delivery | stay; tested for multiple live session lanes |
| `observation_content_manifests.content_digest` and `.content_bytes` (0008) | Same manifest owner and key as 0003 | Digest/size bind the manifest to the encrypted object; the object remains the root | Nullable checks preserve pre-0008 rows and their weaker coverage | stay |
| `observation_inspection_snapshots.facts_content_digest`, `.facts_content_bytes`, `.excerpt_content_digest`, `.excerpt_content_bytes`, `.excerpt_redacted`, and `.excerpt_truncated` (0008) | Same snapshot owner and key as 0004 | Nullable digest/size and redaction facts never own plaintext; object references remain the roots | Nullable, bounded checks preserve older snapshots and prevent inferred capture strength | stay |
| `observation_cursors` (0009 rebuild) | Task/workspace source cursor; `(workspace_commitment, source, session_commitment)` | Cursor is structural replay state; its owning task bundle is the retention root | 0009 rebuilds the closed source check to admit `claude_hook` and `cursor_hook` while preserving every row and id | stay; tested for N session lanes |
| `observation_events` (0009 rebuild) | Task/workspace observation envelope; integer `id` plus workspace/session/source identity | Structural envelope and content references are rooted by the task ledger and referenced object manifests | 0009 rebuilds only the source check and receipt index; accepted rows are never rewritten or reinterpreted | stay; tested for sibling isolation |
| `observation_consent.content_capture_profiles_json` (0010) | Task-bundle observation consent row; workspace commitment | No content root; the consent row carries the bounded, versioned ordinary-profile selection and the task bundle retains its observation authority | `NOT NULL DEFAULT '[]'` backfills existing consent rows without granting legacy content capture; consent/runtime fences serialize profile changes; profile selection remains separate from profileless Codex structural observation | stay; tested for legacy/default and profile transitions |
| `observation_capture_tickets` (0011) | Task-owned native-capture handoff; `ticket_id`, with unique `(workspace_commitment, logical_identity)` | `expected_parts_json` and `object_ids_json` contain bounded structural identities; captured bytes remain in task-owned encrypted objects and `observation_content_manifests`. A staging/pending ticket is temporary coordination state, while a revoked ticket is a cleanup tombstone; ticket deletion after a committed envelope does not delete historical content. A ticket its own structural row can no longer consume is tombstoned by that row's delivery, the READY sweep, or the CHECK preflight (#836) | A ticket binds task/session/source identity, source and authority generations, mapping/profile, expected parts, and object identities. Staging, pending, and revocation transitions are idempotent and consent-fenced; a retry must present the same binding and complete expected parts before the ledger cursor advances | stay; tested for exact retry, independent ticket budget, consent cleanup, and stranded-handoff retirement |
| `observation_advice_semantic_attempts` (0012) | Task-owned asynchronous semantic-advice attempt; `attempt_id`, unique `(workspace_commitment, yoetz_session_id, basis_digest)` | The minimized packet, scoped coverage gaps, terminal summaries/details, finding identities, provider identity, attempt receipt, and evidence digest remain bounded task-bundle rows. The row records semantic-attempt evidence; it is not a new observation/content root and does not become catalog authority | `state_token` orders attempts and leases are fenced by `service_generation`, owner, and expiry. Identical workspace/session/basis requests coalesce; a newer basis supersedes only unattempted pending rows; only validated `succeeded` output may add semantic advice, and interrupted/unavailable/failed/cancelled rows retain honest coverage gaps | stay; tested for per-task queue bounds, lease recovery, and session-lane isolation |

The bundle's task ledger, object directory, projection rows, maintenance pins, and privacy root
sets remain one retention graph. A catalog pointer to a bundle object carries the owning task and
route generation; it is never copied into a shared project row as plaintext.

The 0010–0012 observation additions preserve three independent task-local lanes. Consent selects
an allowed ordinary-content profile; a capture ticket stages one authenticated handoff to the
existing content-manifest/object graph; and a semantic-advice attempt records a bounded,
frontier-bound asynchronous review. `projection_state`, `p1_projection_state`, and the query
snapshot frontiers remain task-ledger projections, while `basis_digest`, `subject_digest`, and
`state_token` on an advice attempt are replay/staleness fences rather than shared frontier
authority. None of these rows is copied into the catalog, and no catalog project or operation row
can advance a task bundle frontier.

## Catalog migration inventory

Catalog 0004 and 0005 are the durable owners of shared installation state. The rows below name
every table they alter or create, including the delegation, host-lineage, coordination, and
project-operation surfaces. The existing 0001 `maintenance_operations` row is included because it
is also the restart marker for the automatic bundle-upgrade phase. Catalog rows contain structural
identifiers, commitments, bounded state, and encrypted-object pointers; the encrypted bytes remain
rooted by the owning task bundle.

| Catalog table or migration surface | Owner and key | Encrypted owner and GC root | Concurrency and migration rule | Disposition |
|---|---|---|---|---|
| `task_routes` (0004 alters) | Catalog route authority; `task_id` | `bundle_relpath` identifies the task bundle and its current or retained route generation | One catalog writer; route generation and the root attach pair are fenced; 0004 backfills lineage columns and keeps delegated children out of root-pair uniqueness | catalog; tested |
| `start_operations` (0004 rebuild) | Catalog start lifecycle; `(installation_id, operation_id)` | Terminal result bytes and response object reference remain tied to the task route and its bundle retention | Lease/CAS phase transitions; 0004 widens the mode set and copies rows failure-atomically | catalog; tested |
| `maintenance_operations` (0001, migration extension) | Catalog-shared backup/restore/migration journal; `(installation_id, operation_id)` and task route | Backup manifest and migration result are structural digests; the task bundle and retained route own the encrypted objects and frontier snapshot | `BundleUpgradeCoordinator` reserves `kind='migration'` with `requested_target_version='13'`, a request digest, plan digest, route/frontier/privacy bindings, and a lease; `SqliteBundleUpgradeJournal` advances `reserved → backup_ready → schema_applied → replay_verified → terminal`, then records `complete` or `quarantined`. It is the automatic-upgrade marker; no second marker table or lazy writer upgrade is permitted | catalog |
| `task_sessions` (0004) | Catalog session liveness; `session_id` and `task_id` | None; the route and task bundle own task evidence | Health transitions are serialized and lease-fenced; 0004 creates the shared liveness projection | catalog; tested |
| `projects` (0004) | Catalog grouping authority; `project_id` | Title/description pointers remain rooted by their owner task and route generation | Membership generation and dissolution are catalog transactions; 0004 creates the grouping row | catalog; relocate; tested |
| `repository_grouping_preferences` (0004) | Catalog repository opt-out; `repository_commitment` | None; only the structural bit and timestamp are stored | Upsert is serialized; pre-birth preference does not create a project row | catalog; tested |
| `project_memberships` (0004) | Catalog membership graph; `(project_id, membership_generation, member_kind, member_commitment_or_id)` | None; task members point to task routes | Append-only membership rows and one-active-member index; generation changes are catalog writes | catalog; tested |
| `project_operations` (0005) | Catalog-shared project mutation journal; `(installation_id, request_id)` with request digest and operation name | `reserved_*_object_id` and canonical title/description refs point to encrypted text owned by the source task and route generation; `result_canonical` is the bounded structural response replay, not a plaintext content root | `BEGIN IMMEDIATE` reserves one request, rejects request-id/digest or operation conflicts, advances only through `reserved → text_ready → effect_pending → completed`, and stores one exact canonical result. Replaying the same request/digest returns the stored record/result; generation/CAS in the project tables remains the effect fence | catalog |
| `coordination_grants` (0004) | Catalog generation-bound grant; `(project_id, membership_generation)` | None; audit id is structural | Grant activation and revocation are monotonic and generation-fenced | catalog; tested |
| `lineage_task_meta` (0004) | Catalog lineage lifecycle; `task_id` | Task route and task bundle retain lineage evidence | Revision and abandonment fields are updated with the route authority; migration requires the route FK | catalog; tested |
| `lineage_operations` (0004) | Catalog delegation phases; `(installation_id, operation_id)` and handle digest, with optional `(project_id, membership_generation)` admission pair | Opaque handle material is private catalog state; child bundle is rooted by its task route and the original project grant remains structural | Lease owner/generation and phase CAS make reservation retryable; cross-repository admission is immutable across replay; 0004 creates the durable operation table | catalog; tested |
| `lineage_attach_handles` (0004) | Catalog single-use capability; `handle_digest` | Private handle value is catalog-owned until expiry/revocation; child bundle remains task-owned | Consume/revoke is a single writer transition; 0004 creates the capability table | catalog; tested |
| `lineage_manifests` (0004) | Catalog frozen parent-child snapshot; `(parent_task_id, child_task_id)` | Canonical manifest is structural; referenced child facts remain rooted by the child bundle | One immutable manifest per edge and authority revision; receipt/check reads reuse it | catalog; tested |
| `host_lineage_annotations` (0004) | Catalog provisional host correlation; `(installation_id, correlation_id)` | None; host and conversation values are keyed commitments only | Alias binding is serialized and ambiguity remains durable; migration creates commitment-only rows | catalog; tested |
| `host_lineage_annotation_aliases` (0004) | Catalog alias index; composite alias key plus correlation | None; aliases contain no raw host text | Insert-only lookup aliases retain many-to-one ambiguity; FK ties each alias to its annotation | catalog; tested |
| `coordination_detections` (0004) | Catalog structural detection; `detection_id` and project generation | `detail_ref_json` points to encrypted detail owned by the source task | Detection state is generation-bound; migration creates bounded JSON and disposition checks | catalog; relocate; tested |
| `coordination_participants` (0004) | Catalog source snapshot; `(detection_id, task_id)` | None; source route and task ledger remain the evidence roots | Participant facts are inserted with the detection and route generation; no live re-read substitutes for them | catalog; tested |
| `coordination_deliveries` (0004) | Catalog delivery retry state; `(detection_id, target_task_id)` | Advice JSON is bounded structural state; detail remains under the detection's object pointer | One terminal delivery outcome per target with idempotent retry/refusal checks | catalog; tested |
| `coordination_coverage` (0004) | Catalog per-task observability coverage; `(project_id, task_id, membership_generation)` and `coverage_id` | None; only bounded coverage and gap vocabulary is stored | Idempotent insert by coverage identity plus generation-scoped lookup; 0004 creates the durable table | catalog; tested |
| `coordination_obligations` (0004) | Catalog obligation disposition; `(detection_id, task_id)` | Obligation event identity remains rooted in the task ledger | Declared/addressed/resolved transitions are checked; nullable `obligation_id` preserves empty legacy rows | catalog; tested |

New coordination detection identities bind the project generation, resource commitments, and
both task route snapshots. Task identifiers and their route generations/identity digests are
canonicalized together, so reversing the pair preserves the identity. A route replacement produces
a successor detection; it cannot overwrite the previous immutable participant rows. A retained
legacy detection can be retried under its original identity only while its recorded participant
snapshots still match. Delivery and projection revalidate those snapshots against current source
authority before exposing advice or encrypted detail.

Coordination declarations remain historical ledger facts after their obligations close. Only
declarations for currently open obligations participate in later detection sweeps; a closed
declaration cannot prevent unrelated overlaps from being considered.

## Hook-side local observation store

`LocalObservationStore` is an owner-only, workspace-keyed fallback and capture spool under
`observation/workspaces/<commitment>.json`. Its `_WorkspaceState` is a local structural evidence
container, not a second ledger and not shared project authority.

| State family | Key and owner | Retention and object root | Concurrency and migration rule | Disposition |
|---|---|---|---|---|
| Consent and routing (`consent`, `session_workspaces`, `codex_session_bindings`, `pending_lifecycles`) | Workspace commitment; session commitments and raw host-session IDs are lane keys | Owner-only state file; no transcript content; pending lifecycle intents retain the event until the session lock converges | Interprocess state lock plus workspace recovery lock and per-session lifecycle lock; JSON schemas 1–10 remain readable, and schema 11 adds pairing/retention provenance | stay; tested for N lanes |
| Replay state (`cursors`, `dedup`, `dedup_order`, `dedup_lanes`, `envelopes`) | Workspace commitment and session/source lane | Envelopes are bounded structural observations; dedup and cursor fences remain for deterministic replay; no plaintext transcript; any envelope eviction persists `envelopes_truncated` and records the local-retention reason, never `truncated_payload` (tb4n5) | One state-file transaction under the interprocess lock; bounded deterministic eviction marks the affected lane and blocks claims based on incomplete history | stay; tested for replay bounds |
| Hook pairing (`open_pre`, `unpaired_scopes`, `pairing_state_unknown`) | Workspace plus source/session/generation/correlation scope; host call IDs never cross lanes | Codex paired calls retain scoped open-pre and orphan identities; Claude/Cursor post-only calls retain no synthetic missing-pre gap; the bounded orphan set remains structural; unknown legacy aggregate provenance stays unresolved | Pairing admission stages envelope and pairing mutation in one rollback-on-exception transaction; duplicate/reordered delivery cannot erase a real orphan; `pairing_state_unknown` remains true when scoped provenance is absent or incomplete; a legacy `/11` `pairing_history_complete` marker is accepted only as a read-compatibility migration signal | stay; tested for pairing/replay faults |
| Attempt endings (`pending_attempt_endings`, `pending_attempt_ending_counts`) and the bridge's `observation/yoetz-rejected-calls.json` | Workspace commitment; the rejection file is installation-wide | Closed tokens only: ending reason, structural tool name, source generation, time, a 16-hex pairing-key digest (16 newest plus counts per reason); the rejection file holds `sha256(domain, tool basename, Yoetz session, writer, request_id)`, a millisecond time and the opaque claimant digest of the attempt that consumed it, 256 newest; never a call id, request id or argument (tb4n5) | Endings are recorded with the pairing mutation under the state lock; the bridge appends and the store claims under the record's own file lock (taken after the store lock, never before it) with an atomic replace; a claim is installation-wide, so a rejection closes at most one attempt in any workspace, and idempotent for its claimant across a rerun or retried transaction; an unreadable file closes nothing | stay; tested for expiry identity, lifecycle boundaries, host routes and cross-workspace reconciliation |
| Code-mode cells (`code_mode_cells` with `runtime_cell`, `waits`, `held_output`; `code_mode_item_sessions`) | Workspace plus Codex session and cell call id | A yielded cell's held output is one structural envelope kept until its terminal `wait` or turn end decides the cell; sessions whose rollout wrote a tool item are remembered; both maps hold 256 entries and the cell map forgets a holding cell last (tb4n5) | Decided with the stream cursor under the state lock; a held output stays until its delivery commits, so a replayed pass redelivers it idempotently | stay; tested for yield, poll, overlap, reload and turn end |
| Gap and unsupported-event state (`gaps`, `session_gaps`, `unsupported_events`) | Workspace commitment, with scoped gap sets by session | Gap history is structural and bounded; it is evidence of loss, never a content root; incomplete retention keeps `unpaired_event` active | Gap activation/resolution is serialized with state writes; unknown codes are not copied into structural errors; legacy post-only false gaps are retired only with complete retained history | stay; tested for scoped gaps |
| Advice (`advice_snapshot`, `session_advice`, `last_advice_suppression`, `session_advice_suppression`) | Workspace plus task/session delivery scope | Snapshot is structural; user-controlled detail is absent or encrypted elsewhere | Delivery selection is read-only; commit happens after output; session scope prevents one lane suppressing another | stay; tested for session isolation |
| Stream replay (`stream_cursors`, `stream_partials`, `stream_call_tools`, `stream_source_identities`, `stream_profiles`, `stream_partial_dropped_sessions`) | Workspace and Codex session commitment | Partial tails are bounded read-cache data; dropped tails produce a source-lag gap and are reread from the cursor | Cursor/profile/source generation updates are atomic under the state lock; maps and partial bytes are bounded | stay; tested for stream bounds |
| Hook ordinals and frontier notices (`hook_sequences`, `hook_sequence_clock`, `frontier_motion_notices`, `frontier_motion_delivered`) | Workspace and host-session lane | High-water marks and notices are structural replay fences; the workspace clock survives bounded map eviction | Hook sequence allocation is serialized and active sessions are protected; a workspace high-water mark prevents counter reset | stay; tested for high-water marks |
| Delivery and quarantine (`pending_outbox`, `quarantine`, `storage_corrupt_sessions`, `delivery_lag`) | Workspace and raw host-session lane | Pending rows remain until acknowledged; each new row records `enqueued_at`, and its acknowledgement adds one enqueue-to-acceptance sample to the fixed-bucket `delivery_lag` histogram (counts and milliseconds only, tb4n5); quarantined detail remains visible until age/byte cap or explicit reclaim, with eviction evidence | FIFO is preserved within a lane; a quarantined sibling cannot block unrelated lanes; all drops carry gap evidence | stay; tested for lane isolation |
| Capture accounting (`capture_backlogs`, `capture_reservations`, `capture_reservation_bootstrap`, `capture_handoff_retirements`, `capture_handoff_retired_count`, pending retirement bindings) | Workspace commitment; task route and capture-ticket identities | Metadata only: counts, bytes, timestamps, and opaque ticket/task identities; the retirement account keeps the last 16 payload-free entries (ticket identity, stage, reason, ticket state, source, task, age, closed quarantine reason) plus a total count; at most 512 ticket-to-task bindings remain pending until retirement confirmation | Reservations and inventory proofs change under the interprocess lock and the coordinator's capture lock; retirement accounting commits by ticket identity before tombstoning/releasing, then confirms after both succeed; a full pending binding set fails closed, and restart reconciliation drops only bindings absent from a complete, schema-available active-ticket listing below the 512-row cap; an aged reservation or pending binding is READY maintenance demand, and unknown or legacy entries are read conservatively or dropped (#695, #836) | stay; tested for bootstrap, reconciliation, and stranded-handoff retirement |

The local store has explicit aggregate ceilings for state bytes, envelopes, dedup keys, open
pairing entries, pending lifecycle intents, outbox rows, quarantine rows, stream partial bytes,
stream call tools, hook sequences, frontier notices, and parsed state-cache entries. Session replay
tombstones and cursor/stream maps are independently capped so ended-session churn cannot grow a
state file after its envelope window is empty. Live, pending, quarantined, and storage-corrupt
lanes are protected from pruning.

## Lifecycle mappings and runtime boundaries

| Surface | Owner and key | Retention/concurrency rule | Migration and disposition |
|---|---|---|---|
| `codex-lifecycle/<codex_session_id>.json` | Host integration adapter; one validated raw Codex session ID | Owner-only 0600 mapping; it contains only task/session/writer IDs and an optional frontier; per-session lock serializes rewrites | Mapping version is validated before use; ended mappings are bounded by the recovery scan and remain while undrained rows may name them | stay; tested for concurrent recovery |
| `codex-lifecycle/.<codex_session_id>.pending.json` | Lifecycle adapter; one raw host session | One replaceable pending operation is applied only by the session-lock owner; applying files survive a crash for replay | Versioned pending operation is additive and fail-closed; no runtime SQL | stay; tested for replay |
| `codex-lifecycle/.<codex_session_id>.lock` | Lifecycle lock authority; raw host session | Nonblocking per-session lock with stale-token fence; no pattern-based process termination | Lock format is private and versioned by the adapter; no migration table | stay |
| `codex-lifecycle/workspace-recovery-locks/<workspace>.lock` | Recovery coordinator; workspace commitment | Nonblocking workspace reservation is acquired before session locks; sorted session acquisition prevents cycles | Private lock path is commitment-derived and symlink-safe | stay; tested for lock ordering |
| `RuntimeCachePolicy` and runtime task cache | Service runtime; task ID and route generation | Per-task cache/opening ceilings evict idle tasks and refuse unsafe opening pressure; one task bundle writer remains authoritative | In-memory policy has no SQL migration; every sweep iterates task routes instead of assuming one task per repository | stay; tested for task-local cache bounds |
| Recovery, idle relock, and sweeps | Service/catalog owner; task route and session lease | Recovery selects only a persisted binding or explicit selector; repository/workspace membership never selects a task; expired leases derive `contact_lost` without a write | Catalog `task_sessions` and route generations carry durable liveness/recovery facts; no runtime DDL | catalog; shared liveness and multi-lane recovery are tested |
| GC roots and maintenance recovery | Task bundle plus catalog route/retained-route pointers | Current and retained route generations root bundle objects; catalog project/detection text references are checked and rebased only for their owning task route | Backup/restore validates object, route, privacy-root, and project-pointer evidence before the catalog CAS; failed validation rolls back | relocate; object ownership stays task-local and catalog pointers are tested |
| Verification scheduler | Task bundle `observation_verification_jobs`; task ID is the writer boundary | A running job lease is task-local; a quarantined or unavailable sibling must not stop another task's worker | Existing bundle tables remain readable; cross-task scheduling requires a new catalog migration and design gate | stay; no shared mutable requirement is established and task isolation is tested |

The catalog extension introduced by 0004 owns lineage, project, session-health, host-annotation,
and coordination authority. It is the only place for those shared structural tables; project
coordination adapters fail with `MIGRATION_REQUIRED` when those tables are absent rather than
creating them at runtime.

### Catalog upgrade recovery boundary

The catalog 0004/0005 startup upgrade applies all pending DDL and catalog version metadata in one
SQLite transaction, then verifies schema identity and foreign keys before reopening the ordinary
guarded writer. An exception during either migration rolls the transaction back; retry applies the
same append-only migrations. Legacy session rows start as `contact_lost`, because an old active
route is not proof of a current lease. Normal session attachment and lease reconciliation establish
new activity; the migration does not infer it.

This path does **not** create the machine-bound pre-migration backup or phase journal used for
task-bundle upgrades. Transaction rollback protects an uncommitted migration, not a committed
logical migration error, later storage loss, or binary downgrade. Backup parity is a remaining
catalog recovery limitation tracked under #496; the bundle upgrade's backup guarantees must not be
claimed for the catalog. Startup owns migration before READY and closes its DDL connection before
runtime work. The transactional regression tests do not establish competing-service or power-loss
acceptance.

The `repository_grouping_preferences` table is catalog-owned repository authority keyed by the
privacy commitment. It stores only the auto-grouping bit and update timestamp, so a pre-birth
opt-out remains durable without materializing an implicit `projects` row; project birth consumes
the preference and keeps the project row as the later mutable generation authority.

`project_operations` is catalog-shared retry authority for project lifecycle commands, not a
replacement for task-owned project text or observation evidence. Its request digest authenticates
the complete operation identity before any text/object side effect; only object IDs and canonical
references cross into the journal. A completed row is the durable response for that request, so a
lost response can be replayed without applying the project effect twice. A request-id reuse with a
different digest, an invalid phase transition, a stale membership/route generation, or a missing
source authorization remains a conflict/refusal; the journal cannot grant egress, observation,
consent, or disclosure authority.

## Catalog pointer and recovery rules

* A pointer to encrypted project text or coordination detail stores the object ID, content digest,
  plaintext byte count, owner task, route generation, and envelope digest. The object remains in
  the owner's bundle.
* Restore validates every pointer, accepts only an object whose owner task and retained/current
  route generation are present, and rebases only pointers owned by the replaced route. A pointer
  to another task or retained generation is preserved and validated.
* The current route and retained route are switched in one catalog transaction after the restored
  bundle's replay, object set, privacy roots, and route identity have been verified. No live bundle
  is opened read/write by an inspection-only path.
* A catalog table references a bundle object only through a structural pointer. The catalog never
  becomes the encrypted object's owner and never becomes a plaintext store.

## Executable dispositions

The storage tests pin the executable side of this matrix:

* `tests/integration/storage/test_migration_0001.py` pins the ordered bundle and catalog migration
  registries and replay behavior.
* `tests/integration/storage/test_catalog_v4_extensions.py` pins the catalog 0004 extension and its
  historical `user_version = 4` fixture; catalog 0005 is the current project-operation extension
  described in the inventory above.
* `tests/integration/storage/test_migration_0010_observation.py`,
  `tests/integration/storage/test_migration_0011_observation.py`,
  `tests/integration/storage/test_codex_capture_ticket_sqlite.py`,
  `tests/integration/storage/test_capture_ticket_consent_cleanup.py`, and
  `tests/unit/application/test_observation_advice_semantic.py` pin the 0010 consent default,
  0011 capture-ticket shape/cleanup, and 0012 semantic-attempt scheduling/lease behavior.
* `tests/integration/storage/test_start_catalog_state_machine.py`,
  `tests/unit/application/test_lineage_coordinator.py`,
  `tests/unit/adapters/test_sqlite_host_lineage.py`, and
  `tests/unit/application/test_project_coordination.py` pin the route/start/session, delegation,
  host-annotation, and coordination table dispositions listed above.
* `tests/integration/storage/test_backup_restore.py` pins object/manifest validation, route CAS,
  project pointer validation/rebasing, and privacy-root preservation.
* `tests/integration/service/test_project_text_roots.py` pins catalog pointers as GC roots only
  for their owning task.
* `tests/integration/storage/test_start_catalog_state_machine.py` pins durable pre-birth
  auto-grouping opt-out and the no-project-row birth boundary.
* `tests/unit/adapters/test_observation_state_bounds.py`,
  `tests/unit/adapters/test_observation_local_multiplicity.py`, and
  `tests/unit/test_adversarial_multiplicity.py` pin local-store bounds, per-session routing,
  quarantine isolation, lifecycle lock lanes, replay-map pruning, and hook high-water marks.
* `tests/unit/adapters/test_host_lineage.py` and
  `tests/unit/adapters/test_sqlite_host_lineage.py` pin host-annotation identity and catalog
  migration refusal.

These tests are focused evidence for the dispositions above. Packaging, full-suite, and installed
artifact claims remain separate release gates.
