# ADR-050 — Server-filled publish boilerplate and brief status

**Status:** Accepted for [issue #1084](https://github.com/TheGaySupreme123/finishup/issues/1084).
Design gate: protocol. Maintainer acknowledgement: "Maintainer approved 2026-10-16: server-filled
publish boilerplate and slimmer status responses", recorded on #1084.
**Amended 2026-10-17** (round-1 review of PR #1088, maintainer-approved fix loop): decision 2 no
longer derives `request_id` from the body (the host owns the identity), decision 5 guards an
omitted frontier with the admission-time frontier, decision 3 seeds minting with the whole
operation scope, decision 7 canonicalizes only an explicit field allowlist, decision 8 returns the
committed operation's provenance on replay and labels a filled time in history and review inputs,
and decision 10 keeps the closure instructions in the brief text.
**Amended 2026-10-17, round 2** of the same review: decision 2 drops the durable body-keyed
binding and its automatic resumption. The bridge cannot verify that a result reached the caller,
and the record's own failure modes duplicated or suppressed publications. Each id-less call now
gets a fresh, named id: retry means sending it, and an in-memory guard refuses an identical
id-less resend instead of guessing. The `replay_notice` field is retired. Golden vectors are added
(CAN-022).

This ADR widens unreleased 0.3 schema versions in place:

- `publish-work-request` 1.2.0;
- `event-draft` 1.2.0;
- `publish-work-result` 1.1.0;
- `status-request` 1.2.0;
- `status-result` 1.4.0.

It adds no released-family version and no SQLite migration. The publish operation's stored result
gains one optional structural key. The ADR grants no runtime, credential, disclosure, egress or
destructive-action authority.

**Implemented by:**

- `src/finishup/protocol/publish_boilerplate.py`: minting (`DraftMintScope`), the set-field
  allowlist (`PAYLOAD_SET_FIELDS`), canonicalization and the `ServerFilled` record.
- `src/finishup/mcp/publish_identity.py`: the in-memory repeat guard for id-less calls
  (`PublishRepeatGuard`).
- `src/finishup/protocol/models.py`:
  - `PublishWorkRequestModel`, including the omitted-frontier marker;
  - the `server_filled` result models;
  - `StatusRequestModel`: `detail`, the default `limit`, and the results filter;
  - `StatusBriefSuccessModel`.
- `src/finishup/application/publish_work.py`: completion, identity markers, the admission frontier
  guard and provenance (stored provenance on replay, reduced success included).
- `src/finishup/adapters/memory/ledger.py` and `src/finishup/kernel/deterministic_checks.py`: the
  `occurred_at_source` label on history rows and frozen history; `src/finishup/application/
  semantic_case.py` carries it into review packets.
- `src/finishup/ports/ledger.py` and `src/finishup/adapters/memory/ledger.py`: `server_filled` on
  `AppendCommand`, the stored result, and `ResultsProjectionFilter`.
- `src/finishup/application/status.py`: `brief_status_body`, the results filter, and the operation
  page.
- `src/finishup/mcp/server.py`: minting an id-less call's request id, naming it, the repeat
  refusal and the brief default. `src/finishup/cli/app.py` mints and names it for
  `finishup publish-work`.
- `scripts/generate_publish_server_filled_fixture.py`: the CAN-022 golden vectors.
- `src/finishup/mcp/descriptors.py`, `src/finishup/mcp/summaries.py` and
  `src/finishup/mcp/status_streak.py`.
- `src/finishup/cli/startup_gate.py` and `src/finishup/adapters/integrations/startup_gate.py`.
- `scripts/generate_schemas.py`.
- Guidance: `guidance/agent-instructions.md`, `guidance/publication.md`,
  `guidance/publication-policy.md`, `guidance/request-templates.md` and `guidance/workflow.md`.

**Relates to:**

- ADR-002 (canonical protocol);
- ADR-020 (evidence digest provenance);
- ADR-022 (observation-tolerant concurrency);
- ADR-030 (typed recovery directives);
- ADR-043 (bounded agent-facing text);
- ADR-047 (inspection check and operating card).

It takes up the direction recorded on #919 for event ids and envelope mirrors, and keeps #919's
guardrail that `request_id` stays a caller- or host-owned operation identity (decision 2).

## Context

The N6 D-lane trials ran the PR #1080 wheel on 62 Terminal-Bench 4 tasks. FinishUP workflow cost
42.6% of solver output.

- **Publishing:** 1.0M output tokens in 480 calls, 0.8M of them tool-call arguments.
- **Status navigation:** 0.43M output tokens in 796 calls, and about 36% of the extra uncached
  input.
- **Field proxies** inside those arguments:
  - request and session ids: about 124k tokens;
  - `expected_frontier`: about 65k;
  - draft event ids: about 64k;
  - mirrored envelope `evidence_refs`: about 59k;
  - `occurred_at`: about 46k.
- **Contract:** the reviewed contract required current timestamps, sorted refs, and matching
  envelope and payload refs.
- **Audit friction:** the audit's friction list named mirror mismatches, unsorted sets, `status`
  filters rejected beside `view=results`, and `date -u` run only to timestamp payloads. The `date`
  calls also fed false "closing review is stale" Stop prompts.
- **Status bodies:** every status body repeated four equal frontiers, projection metadata, the
  import status and the full closure readiness. That envelope was about half of each page.

None of this clerical work is the ceremony the product wants. The ceremony is deciding to publish
a material transition, not typing UUIDs, timestamps and mirrors.

## Decision

1. **Only `schema` and `payload` are required in a draft.** A `publish_work` request may omit
   `expected_frontier`, and each draft's `event_id`, `occurred_at`, `causal_parents`,
   `artifact_refs` and `evidence_refs`. An agent may also omit `request_id`; the host fills it
   (decision 2) and the service keeps requiring it. A value the caller sends is used unchanged. A
   request that sends every value keeps its earlier validation, request digest, recorded events and
   result bytes.
2. **The request id is caller- or host-owned. It is never derived from the body, and never resumed
   by content.**
   - **Why (round-1 review, R1):** a content hash is a deduplication key, not an operation
     identity. The round-1 design derived `request_id` from the body, so a deliberate identical
     repeat (`ai_powered` -> `local` -> `ai_powered`, a repeated blocker confirmation after new
     evidence) replayed the first operation. The third switch was never recorded.
   - **Why not a durable binding (round-2 review, N1-N6):** the round-1 fix minted an id per call,
     bound it to a body commitment in a state file, and resumed it for the next identical body
     until an outcome was "delivered". A host cannot verify delivery: settlement happened before
     the result reached the caller. The record could also fail in ways that cost identity:
     - a failed cleanup, a short write, a corrupt or full record;
     - a wall-clock step;
     - a same-id call by another writer or a dry run.

     Each failure duplicated or suppressed a publication.
   - **Decision:** when an agent omits `request_id`, the MCP bridge (and `finishup publish-work`)
     mints a fresh `req_` UUIDv4 for that one call. The bridge's own transport retries reuse it
     (reconnect, and the timeout probe with its replay). Every result and error names it: the
     structured `request_id`, plus a fixed text line on an id-less error. The CLI prints it on
     stderr before sending. **Retrying an unknown outcome means sending that id.** A deliberate
     identical repeat is always a new publication.
   - **Guard, not guess:** the bridge keeps, in memory, each writer's previous id-less publish
     that could have committed. An id-less body identical to it is refused before anything is
     sent (`INVALID_REQUEST`, `publish_repeat_unconfirmed`, continuation
     `publish_identity_choice`, `replay_request_id` naming the earlier id). The refusal says a
     call the caller saw succeed is recorded: to publish again on purpose it changes the body or
     sends a fresh `request_id` (`req_` plus a new lowercase UUIDv4); to retry a call whose result
     it did not see, it sends that id. A `finishup-blocker` confirmation is therefore asked to
     name its re-check in the rationale (round 3 of the PR #1088 review): the confirmation rule
     keys on the line and the obligation, so the changed body confirms, and the guard still
     refuses a lost-reply resend that would otherwise confirm a blocker unasked (#985).
     - The record is replaced by the writer's next id-less publish.
     - It is dropped by the writer's explicit-id publish that could have committed, by a certain
       pre-append rejection of that call, and after one hour of monotonic time.
     - Dry runs and other writers never touch it.
     - Being in memory, it has no file to corrupt, short-write or leave stale, and no wall clock.
   - **Stated limits (no guard):**
     - after a bridge restart;
     - after the writer's next publish;
     - after the hour;
     - beyond 4,096 writers per bridge;
     - for the CLI.

     An identical id-less body is then a new publication. Agents that need a retry to survive
     those cases send their own `request_id`. An agent holding no id reads `status view=history`
     before republishing.
   - **Rejected alternatives:**
     - random service minting after receipt, clock- or frontier-derived identity, and a timestamp
       in the body: each loses safe recovery after a lost reply;
     - a durable body-keyed binding with automatic resumption: it needs a delivery acknowledgement
       no host provides;
     - binding a host tool-call id: no host's MCP tool-call identity is verified in this
       repository.
3. **Event ids are minted from the whole operation scope.** An omitted draft `event_id` is minted
   from `(task_id, writer_id, request_id, draft position, preview or commit)`. The operation key is
   `(task, writer, request_id)`, so two writers reusing one explicit `request_id` never mint the
   same id (round-1 review, R4); the session is left out because a task-scoped replay must
   recompute the same ids. A replay recomputes the same ids, also across a service restart, and a
   non-evidential preview never mints the ids its commit records.
4. **An omitted `occurred_at` is the service clock.** The clock is read once per operation. The
   request identity carries `null` in place of that time, so a same-id retry is the same request.
5. **An omitted `expected_frontier` is guarded at admission.** The service reads the current
   frontier when it admits the batch, before preparing or staging it, and passes that sequence to
   the append (`AppendCommand.expected_frontier`), which enforces it with ADR-022's observation-only
   tolerance. A cooperative write that lands while the batch is in flight is `FRONTIER_CONFLICT`
   (`frontier_changed`); nothing is written (round-1 review, R3: an older local switch, or a
   resolution resting on a success that a newer failure superseded, was otherwise accepted on top
   of the newer state). The identity carries `"admission"`.
   - An explicit `null` keeps its earlier meaning: `expected_frontier_required` on a
     state-sensitive family, no guard otherwise.
   - A supplied frontier keeps its guard. It is still the way to refuse a change made *before*
     the request arrived, which an admission read cannot see: guidance tells agents to send it when
     a claim, resolution or decision rests on an earlier read and another writer shares the task.
   - There is no omission-selected unconditional mode. An explicit opt-in was not added: no
     measured workload needs one, and the explicit `null` already covers families that do not
     depend on state.
6. **Envelope mirrors are copied from the payload when omitted:**
   - `result_recorded`, `response_recorded` and `coordination_disposition_recorded` copy
     `evidence_refs`;
   - `evidence_recorded` copies `artifact_refs` from `captured_object_id`;
   - `causal_parents` defaults to an empty set.

   A sent mirror that disagrees is still `ref_mirror_mismatch`.
7. **Only contract-defined reference sets are canonicalized.**
   - **Scope:** the request model sorts (ASCII bytes) and de-duplicates every draft's envelope
     sets and the payload fields an explicit `(family, version, field)` allowlist names
     (`PAYLOAD_SET_FIELDS`): the fields the domain decodes as unique, sorted typed ids. Nothing is
     inferred from a value's contents: a text tuple whose members look like ids (`alternatives`,
     `attempted_items`, `scope_exclusions`) keeps its order and repeats (round-1 review, R2), and a
     family or version absent from the allowlist keeps its exact bytes and refusal. Lineage and
     coordination payload sets keep their refusal.
   - **Why this is safe:** a set has no order or multiplicity, so this changes no assertion.
8. **Provenance is recorded, not inferred.**
   - **What is recorded:** whenever anything was filled, every success, reduced success and
     dry-run result carries `server_filled`. It lists `expected_frontier` when omitted and, for
     each draft by batch index, the envelope fields.
   - **Where it is stored:** the publish operation's stored result keeps the same record. It holds
     field names only, never caller content. A replay and `status view=operation` return the
     committed operation's stored record, never one recomputed from the retry body (round-1
     review, R6).
   - **Where a reader sees it:** `status view=history` rows, the frozen check history and the
     review packet carry `occurred_at_source: "service_clock"` for an event whose publish omitted
     `occurred_at`, derived from the appending operation's stored record (round-1 review, R7).
     Absence means caller-asserted.
   - **Why not the event record:** the record keeps its exact nineteen fields. A per-event coverage
     gap would have propagated into every check and receipt.
9. **Payload ids and evidence `observed_at` stay caller-authored.** Their payload schemas are
   released, and in-batch cross-references need them; #919's label proposal remains the route for
   that.
10. **Status has a `brief` detail level.**
    - **Protocol:** `status` accepts `detail: brief | full`. `full`, or an absent `detail`, is the
      earlier body. A `brief` body is a strict subset of it:
      - a frontier equal to `result_frontier` is omitted;
      - projection metadata at its current defaults, an empty import status and an enforced
        credential filter are omitted;
      - the compact view keeps `coverage` and `closure_readiness`;
      - every other view carries `closure_state`: the state, blocking conditions and
        agent-actionable tokens.
    - **Privacy:** it is built before the disclosure boundary, so the privacy projection and its
      commitment cover exactly what is sent.
    - **Who gets which detail:** the MCP `status` tool asks for `brief` unless the agent names a
      `detail`. The CLI, hooks and the bridge's own recovery reads keep the full body.
    - **Text surface:** the MCP text of a brief non-compact body names `Closure: <state>`, the
      agent-actionable tokens and the count-free directive (at `ready_with_limitations`, "Nothing
      further to do. Request the receipt.") from `closure_state`, and omits the counts a brief
      body does not carry rather than printing them as unavailable (round-1 review, R5).
    - **Paging and filters:** `limit` defaults to `"20"`. `view=results` admits `filter`
      `after_sequence`, `actor_id` or `author: "mine"`, each read from the source event's
      accepted envelope.
11. **Fewer reasons to call `status`.** The accepted-publish text says the next `publish_work` may
    omit its frontier (and that `check`, `respond` and `receipt` take the returned one). It also
    names the filled values and up to eight minted event ids, for hosts that read text only. The
    minted ids are always in the structured `accepted_events`.
12. **The startup surface stays within 8,192 bytes as served.** The budget counts the initialize
    block exactly as `server_instructions` serves it, mandatory route line included, for both
    routes on every host (round-1 review, R8); the optional AI-powered-review destination
    disclosure keeps its separate allowance.

## Consequences

- **Agent effort.** An ordinary batch is written as session, writer, actor, client and drafts of
  `schema` plus `payload`. Agents stop minting request and event ids, running `date -u`, mirroring
  refs and sorting sets.
- **Required startup gate.** In the opt-in required startup mode (Claude Code and Cursor native
  plugins), the gate hook cannot see a host-minted id before the call, so an id-less
  `publish_work` is admitted with no pre-call ticket. Its ticket opens only at a post-call event
  that carries the structured result naming the minted `request_id`; minted event ids are matched
  by position. Claude Code delivers MCP error results to hooks as text only (or as
  `PostToolUseFailure` with no `tool_response`), so there an id-less publish that errors or loses
  its reply holds no ticket and substantive tools are not held for it, and a concurrent delegate's
  tool can pass while one is in flight; each tool is still live-probed against the current accepted
  plan. The agent retries by the minted id the error names, which takes a ticket again. The design
  is kept; owners who need fail-closed tracking have agents send their own `request_id`.
- **Host state.** None. The repeat guard lives in the bridge process's memory.
- **Retry cost.** A lost reply now costs one explicit retry by id. A blind identical resend right
  after it is refused once and names the id, instead of being replayed automatically.
- **Residual identity limit.** When the caller never saw the minted id, an identical id-less resend
  is a new publication rather than a retry. That happens when the bridge restarted, the host lost
  the whole tool result, or it is a CLI re-run whose stderr was lost. Agents that need a retry to
  survive those cases send their own `request_id`. The ready-to-file follow-ups are listed in the
  PR #1088 round-2 fix report.
- **Version skew.** An older service refuses a sparse body as `INVALID_REQUEST` before any append.
  A schema-manifest change supersedes an older holder through the existing handshake.
- **Downgrade.** An older 0.3 build that replays a sparse operation would refuse its stored
  result's extra key. Downgrade below this unreleased contract is not supported.
- **Concurrency.** An omitted frontier refuses a cooperative write that lands while the batch is in
  flight, but cannot see one made between the caller's read and the request; a caller whose batch
  rests on that read sends its frontier. A conflicting omitted-frontier batch costs one resend.
- **Measured estimate, not a treatment effect.** The recorded N6 calls were re-serialized in the
  new shape and counted with the o200k_base vocabulary. The details are on #1084.
  - **Publish arguments:** the 480 publish argument bodies fall from 791,377 to 598,032 tokens
    (−193,345, −24.4%). That is model output.
  - **Status responses:** the 796 status responses fall from 2,167,374 to 1,584,139 tokens
    (−583,235, −26.9%). That is fresh model input.
  - **Publish responses:** `server_filled` adds 23,650 tokens to the publish responses. Re-estimated
    for the amended design with the same method: 26,238 tokens. `server_filled` no longer lists
    `request_id` (22,438 tokens), and the 76 recorded publish errors would each carry the 50-token
    minted-id line (3,800 tokens). Publish arguments, status responses and arguments, and the
    removed `date` commands are unchanged, because the agent omits the same fields. Not counted:
    the extra round trip of a refused blind resend after an unknown outcome.
  - **Not modelled:** reasoning tokens, fewer status calls, fewer rejected batches, and resends
    after an admission-guard `FRONTIER_CONFLICT` (zero frontier conflicts were seen in 3,698
    DeepSWE single-writer calls, #919).
  - **Still needed:** a confirmation run to measure the real effect.
