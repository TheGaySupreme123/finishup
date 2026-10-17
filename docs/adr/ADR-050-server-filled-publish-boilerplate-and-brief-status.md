# ADR-050 — Server-filled publish boilerplate and brief status

**Status:** Accepted for [issue #1084](https://github.com/TheGaySupreme123/yoetz/issues/1084).
Design gate: protocol. Maintainer acknowledgement: "Maintainer approved 2026-10-16: server-filled
publish boilerplate and slimmer status responses", recorded on #1084.
**Amended 2026-10-17** (round-1 review of PR #1088, maintainer-approved fix loop): decision 2 no
longer derives `request_id` from the body (the host owns the identity), decision 5 guards an
omitted frontier with the admission-time frontier, decision 3 seeds minting with the whole
operation scope, decision 7 canonicalizes only an explicit field allowlist, decision 8 returns the
committed operation's provenance on replay and labels a filled time in history and review inputs,
and decision 10 keeps the closure instructions in the brief text.

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
- `src/finishup/adapters/integrations/publish_call_identity.py`: the host-owned request identity
  of an id-less call (`PublishCallIdentities`), shared by the MCP bridge and the CLI.
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
- `src/finishup/mcp/server.py`: minting and binding an id-less call's request id, the resumed-call
  notice and the brief default; `src/finishup/cli/app.py` does the same for `finishup publish-work`.
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
2. **The request id is caller- or host-owned, never derived from the body.**
   - **Why (round-1 review, R1):** a content hash is a deduplication key, not an operation
     identity. The round-1 design derived `request_id` from the body, so a deliberate identical
     repeat (`ai_powered` -> `local` -> `ai_powered`, a repeated blocker confirmation after new
     evidence) replayed the first operation: the third switch was never recorded and the
     conversation stayed `local`. The degraded reduced success did not even carry the notice.
   - **Decision:** when an agent omits `request_id`, the MCP bridge (and `finishup publish-work`)
     mints a fresh `req_` UUIDv4 for that call and records a binding before sending it:
     commitments over the FinishUP session and writer and over the canonical body, the minted id,
     an owner token and process id, in an owner-only state folder, written atomically and fsynced.
     Every retry the host makes for the call reuses the id (reconnect, the timeout probe and its
     replay). A delivered `ok: true` outcome closes the binding and every unresolved binding of
     that writer; any other end leaves it resumable. The next call from the same writer with the
     identical body resumes an unresolved binding, or one whose owner process died mid-call, for
     up to one hour, so a lost reply is retried safely and the service replays. A call still in
     flight in a live process is never shared, so concurrent identical calls stay two operations.
     A delivered call that sends a bound id itself closes the binding too.
   - **Disclosure:** a resumed call that the service replayed carries the closed `replay_notice`
     (`unresolved_call_resumed`, fixed text), also on the reduced `accepted_projection_unavailable`
     success; an id-less error names the minted id in its text. When the binding cannot be written
     the call is refused (`STORAGE_UNSAFE`) and nothing is sent.
   - **Rejected alternatives:** random service minting after receipt (a lost reply loses the id),
     clock-derived or frontier-dependent identity, and a timestamp in the retry body: each loses
     safe recovery after a lost reply or makes it depend on state the caller cannot reproduce.
     Binding a host tool-call id was preferred where available, but no host's MCP tool-call
     identity is verified in this repository, so the bridge-minted nonce is the mechanism.
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
  refs and sorting sets. The startup gate hook, which cannot see a host-minted id before the call,
  opens the write's ticket at the post-call event from the echoed `request_id`, and matches minted
  event ids by position.
- **Host state.** The bridge writes one small owner-only record under the user state directory.
  Only commitments and minted ids enter it; a record it cannot write stops the id-less call.
- **Residual identity limit.** If an outcome was delivered to the host but lost there (the host
  crashed after the bridge answered), the binding is already closed and an identical resend is a
  new publication. An agent that needs that guarantee sends its own `request_id`.
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
    for the amended design with the same method: 26,010 tokens. `server_filled` no longer lists
    `request_id` (22,438 tokens), and the 76 recorded publish errors would each carry the 47-token
    minted-id line (3,572 tokens). Publish arguments, status responses and arguments, and the
    removed `date` commands are unchanged, because the agent omits the same fields.
  - **Not modelled:** reasoning tokens, fewer status calls, fewer rejected batches, and resends
    after an admission-guard `FRONTIER_CONFLICT` (zero frontier conflicts were seen in 3,698
    DeepSWE single-writer calls, #919).
  - **Still needed:** a confirmation run to measure the real effect.
