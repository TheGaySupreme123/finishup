# ADR-050 — Server-filled publish boilerplate and brief status

**Status:** Accepted for [issue #1084](https://github.com/TheGaySupreme123/yoetz/issues/1084).
Design gate: protocol. Maintainer acknowledgement: "Maintainer approved 2026-10-16: server-filled
publish boilerplate and slimmer status responses", recorded on #1084.

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

- `src/finishup/protocol/publish_boilerplate.py`: derivation, minting, set canonicalization and the
  `ServerFilled` record.
- `src/finishup/protocol/models.py`:
  - `PublishWorkRequestModel`, including the derived `request_id` and the `latest` frontier;
  - the `server_filled` result models;
  - `StatusRequestModel`: `detail`, the default `limit`, and the results filter;
  - `StatusBriefSuccessModel`.
- `src/finishup/application/publish_work.py`: completion, identity markers, `latest` admission and
  provenance.
- `src/finishup/ports/ledger.py` and `src/finishup/adapters/memory/ledger.py`: `server_filled` on
  `AppendCommand`, the stored result, and `ResultsProjectionFilter`.
- `src/finishup/application/status.py`: `brief_status_body`, the results filter, and the operation
  page.
- `src/finishup/mcp/server.py`: the derived envelope id and the brief default.
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

It takes up the direction recorded on #919 for event ids and envelope mirrors. It deliberately
deviates on `request_id`; see decision 2.

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
   `request_id`, `expected_frontier`, and each draft's `event_id`, `occurred_at`,
   `causal_parents`, `artifact_refs` and `evidence_refs`. A value the caller sends is used
   unchanged. A request that sends every value keeps its earlier validation, request digest,
   recorded events and result bytes.
2. **The request id is derived from the body.** When the caller omits `request_id`, it is the
   SHA-256 of a domain tag plus the canonical request body without `request_id`, shaped as a `req_`
   UUIDv4. It is computed after the meaning-preserving normalizations below, and over the model's
   strict serialization, which equals the normalized wire body.
   - **Idempotency:** the retry after a lost response is resending the same body. It replays the
     stored outcome; `status view=operation` keys on the same id; a different body is a different
     request. A caller that wants to change a body under one identity sends its own `request_id`,
     and the existing `REQUEST_IDENTITY_CONFLICT` contract applies unchanged.
   - **Why this deviates from #919:** #919 kept `request_id` caller-minted because a service-minted
     id cannot be retried after a lost response. A body-derived id has no such gap, because the
     caller can always recompute it by resending.
   - **Trade-off:** two deliberately identical publications are one publication. That matters
     for an id-less fact repeated on purpose, such as a `finishup-blocker` confirmation or a
     review-mode switch back. Every derived-id replay therefore carries the closed `replay_notice`:
     nothing new was appended, so reword the body or send a fresh `request_id`. Replays never
     append twice.
3. **Event ids are minted from the request identity.** An omitted draft `event_id` is minted from
   `(request_id, draft position, dry_run)`. A replay recomputes the same ids, also across a service
   restart. The dry-run flag is part of the seed, so a non-evidential preview never mints the ids
   its commit records, even under one explicit `request_id`.
4. **An omitted `occurred_at` is the service clock.** The clock is read once per operation. The
   request identity carries `null` in place of that time, so a resend is the same request.
5. **An omitted `expected_frontier` is the `latest` mode.** The batch is admitted with no
   compare-and-set guard (`AppendCommand.expected_frontier = None`). The ledger still validates it
   against the frontier it lands on, atomically. The identity carries `"latest"`.
   - An explicit `null` keeps its earlier meaning: `expected_frontier_required` on a
     state-sensitive family.
   - A supplied frontier keeps its guard, including the ADR-022 observation tolerance.
   - The guidance tells agents to send a frontier when a concurrent writer could change what the
     batch depends on, such as a parent and its delegates.
6. **Envelope mirrors are copied from the payload when omitted:**
   - `result_recorded`, `response_recorded` and `coordination_disposition_recorded` copy
     `evidence_refs`;
   - `evidence_recorded` copies `artifact_refs` from `captured_object_id`;
   - `causal_parents` defaults to an empty set.

   A sent mirror that disagrees is still `ref_mirror_mismatch`.
7. **Reference sets are canonicalized, not refused.**
   - **Scope:** the request model sorts (ASCII bytes) and de-duplicates every draft's envelope sets,
     and the top-level arrays of typed ids in ordinary agent families, before the schema check.
     Free text is never reordered. Lineage and coordination payload sets keep their refusal.
   - **Why this is safe:** a set has no order or multiplicity, so this changes no assertion.
8. **Provenance is recorded, not inferred.**
   - **What is recorded:** whenever anything was filled, every success and dry-run result carries
     `server_filled`. It lists the request fields and, for each draft by batch index, the envelope
     fields.
   - **Where it is stored:** the publish operation's stored result keeps the same record. It holds
     field names only, never caller content. Replay and `status view=operation` return it.
   - **Effect:** a filled `occurred_at` is never read as a caller assertion.
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
    - **Paging and filters:** `limit` defaults to `"20"`. `view=results` admits `filter`
      `after_sequence`, `actor_id` or `author: "mine"`, each read from the source event's
      accepted envelope.
11. **Fewer reasons to call `status`.** The accepted-publish text says the next write may omit its
    frontier. It also names the filled values and up to eight minted event ids, for hosts that read
    text only. The minted ids are always in the structured `accepted_events`.

## Consequences

- **Agent effort.** An ordinary batch is written as session, writer, actor, client and drafts of
  `schema` plus `payload`. Agents stop minting event ids, running `date -u`, mirroring refs and
  sorting sets. The startup gate hook derives the same request id for a sparse write, and matches
  minted event ids by position.
- **Version skew.** An older service refuses a sparse body as `INVALID_REQUEST` before any append.
  A schema-manifest change supersedes an older holder through the existing handshake.
- **Downgrade.** An older 0.3 build that replays a sparse operation would refuse its stored
  result's extra key. Downgrade below this unreleased contract is not supported.
- **Concurrency in `latest` mode.** Under `latest`, a concurrent cooperative writer's events can
  land before the batch. Nothing guards against that unless the caller sends a frontier. Every
  state rule still runs at append time.
- **Measured estimate, not a treatment effect.** The recorded N6 calls were re-serialized in the
  new shape and counted with the o200k_base vocabulary. The details are on #1084.
  - **Publish arguments:** the 480 publish argument bodies fall from 791,377 to 598,032 tokens
    (−193,345, −24.4%). That is model output.
  - **Status responses:** the 796 status responses fall from 2,167,374 to 1,584,139 tokens
    (−583,235, −26.9%). That is fresh model input.
  - **Publish responses:** `server_filled` adds 23,650 tokens to the publish responses.
  - **Not modelled:** reasoning tokens, fewer status calls, and fewer rejected batches.
  - **Still needed:** a confirmation run to measure the real effect.
