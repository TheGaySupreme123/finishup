# FinishUP protocol v0.1

This document is the first stop for anyone implementing a FinishUP client, importer, or independent
reader of the ledger: what the protocol records, what it deliberately does not prove, the six
public workflow operations, the event/identity model, canonical encoding and idempotency, coverage
and findings, error handling, version discovery, and the minimum safe client workflow.

## Status and normative sources

FinishUP v0.1 is a public alpha protocol. This page is explanatory. Where it repeats a frozen value —
an enum member, a schema field, a canonical digest — the machine-readable source wins on conflict:
[`docs/adr/`](../adr/) for architecture decisions, [`docs/INTERFACES.md`](../INTERFACES.md)
for the shared vocabulary, and the JSON Schemas under [`schemas/`](../../schemas/) plus the golden
vectors under [`fixtures/`](../../fixtures/) for exact wire shape and byte identity. A conflict
between this prose and those sources is a documentation defect, not an alternate reading. Clients
validate against the schema set and `version --json` identities that ship with their installed
release, not against this page's examples.

A conditional compatibility claim on one axis (protocol, storage, an event schema, a provider
profile, a platform) is never read as unconditional compatibility on every axis. See
[`compatibility.md`](compatibility.md) for the full axis model.

## Trust model

FinishUP is a local-first, append-only work ledger and completion-integrity layer. It is **not**:

- an executor or orchestrator of the work it records;
- a transcript recorder of everything an agent did;
- an identity provider;
- proof that repository or world state matches a claim.

Cooperative publications (`publish_work`) are assertions carrying an explicit actor type and
authorship assurance and an explicit publication channel; they are not independently verified
facts. Imported records (the Codex JSONL importer) are bounded observations of a public transcript
format, not a complete internal trace of what the harness did.

Local checks evaluate the published record and a named, versioned policy at one frozen
`Frontier`. They are exact and reproducible from the same inputs. Optional AI-powered results are
advisory: they are provenance-labeled, freshness-fenced against the frontier they were computed at,
and can never take a check's local-check result away. Coverage is a vector, not a score — the
weakest material dependency and any explicit gap bound what a receipt or final wording may say. A
receipt records conclusions about captured work at a frontier; it is not a certificate and it is not
cryptographic proof of correctness or authorship.

**You may say:**

- "recorded", "published", "self-asserted" (or the exact stronger assurance the record carries);
- "digest observed to match" (with the digest);
- "captured bytes checked against policy X at coverage Y";
- "local policy found no issue at coverage X".

**Do not say** "verified", "proved", "authenticated", or "complete" unless the sentence also states
the exact sufficient coverage that justifies it.

## Six public workflow operations

FinishUP exposes exactly six mutating/reading workflow operations, as both MCP tools and CLI
commands (`start`, `publish-work`, `check`, `respond`, `status`, `receipt`). MCP also registers
read-only `read_guidance`, which returns one packaged guidance document as tool text and is not a
ledger operation:

| Operation | Mutating | Intent |
|---|---|---|
| `start` | yes | Open or resume a task/session and obtain a writer identity. |
| `publish_work` | yes | Append a bounded atomic batch of typed work events. |
| `check` | yes (allocates findings) | Freeze a dependency/frontier case and run local (and optionally AI-powered) policy. |
| `respond` | yes | Record a disposition (`acknowledged`, `provenance_disputed`, `rejected`, `waived`) against a finding. |
| `status` | no | Read bounded, paginated projection state at the current frontier. |
| `receipt` | yes (allocates the receipt) | Produce a durable, current-state receipt. |

Every mutating operation requires a stable `request_id` and returns the same result on retry with
the same canonical request; a different request body under the same ID is a conflict, never a silent
overwrite. `publish_work` accepts a bounded atomic batch of typed events — one invalid event rejects
the whole batch. `check` freezes a dependency/frontier case and may complete local-only or with an
additional AI-powered review status; the local-check result is never discarded because AI-powered
evaluation was unavailable. `respond` records disposition as history and never erases the finding it
responds to. `status` is bounded and paginated and discloses the projection frontier and any lag
behind the ledger. `receipt` is built from durable current state, excludes its own publication from
the subject frontier where the schema specifies that, and never strengthens coverage beyond what the
underlying record supports.

Import, review, backup, restore, migrate, version, and harness integration are **CLI support
surfaces**, not additional workflow operations — they are not exposed as MCP tools, and none of them
adds a seventh operation to the wire protocol.

## Events, identities and accepted envelopes

FinishUP records exactly sixteen event families, each independently schema-versioned starting at
`1.0.0`: `session_opened`, `session_resumed`, `plan_published`, `obligation_published`,
`assignment_recorded`, `decision_recorded`, `action_recorded`, `result_recorded`,
`evidence_recorded`, `claim_recorded`, `plan_revised`, `finding_recorded`, `response_recorded`,
`redaction_recorded`, `check_recorded`, `receipt_recorded`.

A caller submits an `EventDraft`; the server accepts it into an `AcceptedEvent` — the canonical
structural envelope — assigning ingestion/writer sequence, accepted time, and chain digests under
the current generation. A schema the server does not recognize at its exact `(family, version)`
pair is preserved opaque (`UnknownEvent`, `projection_status = "unknown_unprojected"`) rather than
guessed at.

One task has one bundle. Within it, sessions group work and distinct writer identities
(`wri_...`) attribute concurrent contributors. Every accepted event carries a caller-asserted
`ActorAssertionModel` (actor ID, actor type, optional display name) and belongs to a global ledger
chain and a per-writer chain, each with its own predecessor digest. `Frontier(sequence,
head_digest)` — not sequence alone — is the complete causal position: sequence zero is
`Frontier(0, "genesis")`. Concurrent publication ordering may differ across writers while causal
constraints (parent/reference rules) and deterministic reducers remain binding regardless of
ordering.

Identifiers are typed: `<prefix>_<lowercase canonical UUIDv4>` (for example `tsk_`, `ses_`, `wri_`,
`evt_`, `fnd_`, `rcp_`). IDs are opaque and never parsed for order or meaning; server-side
generation is a cryptographically random UUIDv4, never derived from a digest, sequence, timestamp,
or database row ID.

## Canonicalization, digests and idempotency

Every canonical byte sequence is RFC 8785 JCS restricted to the FinishUP value profile: UTF-8, strict
JSON parsing that rejects duplicate keys, floats, unsafe integers, and lone surrogates; sorted,
domain-separated digests rendered `sha256:<64 lowercase hex>` and keyed commitments rendered
`hmac-sha256:<64 lowercase hex>`. **Ordinary JSON serializer output — even
`json.dumps(sort_keys=True)` — is not necessarily canonical FinishUP bytes.** Only the FinishUP-owned
canonicalizer produces bytes suitable for digesting or comparing against a published fixture.

Every mutating request carries a stable operation identity (`request_id` plus, for
`publish_work`/`check`/`respond`/`receipt`, `(task_id, writer_id, request_id)`; `start` uses
`(installation_id, request_id)`). Submitting the same identity with the same canonical request
returns the original result; a different request digest under the same identity is a conflict
(`IDEMPOTENCY_CONFLICT`). If a response is lost to a timeout, cancellation, or connection drop, the
outcome is unknown — never treated as failure. The correct client action is retry with the *exact
same* request, or inspect `status`/the operation result; a client must never mint a new request ID
"to make retry work," because that manufactures a duplicate logical operation.

## Findings, coverage and receipts

Findings originate from one of two engines: `deterministic` (local policy evaluation) or
`semantic_model_derived` (AI-powered advisory review). Each carries `priority` 1–3, a bounded
`summary`/`detail`, `subject_refs`, the policy ID/version that produced it, the frozen
`subject_frontier` it was evaluated at, and a `Coverage` vector. `check` returns a sparse,
capped, ranked set (`MAX_FINDINGS_DEFAULT = 3`, up to `MAX_FINDINGS_LIMIT = 10`). A finding is
unanswered until `respond` records `acknowledged`, `provenance_disputed`, `rejected`, or `waived`.
No disposition resolves the finding: a provenance dispute contests its authorship/provenance
premise, while a waiver is scoped, has an expiry, and requires explicit interactive human
confirmation. Waiver is unavailable to an MCP caller, importer, or noninteractive client. A
response is history, never deletion: the original finding remains in the ledger. Any material
change requires a recheck before a receipt can rely on the updated disposition. A readable response
to a finding returned by the current check does not require one; a redacted or unreadable response
does.

`Coverage` has six dimensions: `publication_channels` (a set drawn from `cooperative_mcp`,
`local_cli`, `codex_jsonl_import`, `hook_observed`, `engine_derived`, `human_import`),
`authorship_assurance` (`self_asserted` < `harness_observed` < `locally_authenticated` <
`service_authenticated` < `cryptographically_attested`), `artifact_observation`
(`published_only` < `import_observed` < `hook_observed` < `content_captured` < `artifact_verified`
< `independently_reproduced`), `evidence_immutability` (`mutable_reference` < `metadata_only` <
`content_digest` < `immutable_snapshot` < `independently_reproduced`), `ledger_freshness`
(`unknown` < `redacted_gap` < `partial` < `stale_after_material_change` < `current`), and
`check_types` (a set drawn from `none`, `deterministic`, `semantic_model_derived`). Combination is
always conservative — the weakest material dependency governs the aggregate, never an average.
Subject-state binding, import gaps, and redaction all weaken freshness explicitly rather than being
silently treated as "unchanged."

A receipt is derived from canonical JSON and reflects durable current state; Markdown rendering is
a presentation of that same JSON, never an independent source of truth.

## Errors, retry and cancellation

Public error codes are grouped by family and each carries an explicit retryability signal and a
bounded correlation ID — never a payload, path, prompt, key, SQL fragment, or traceback:

| Family | Codes |
|---|---|
| Invalid / conflict | `INVALID_REQUEST`, `PROTOCOL_VERSION_UNSUPPORTED`, `SESSION_NOT_FOUND`, `SESSION_CONFLICT`, `IDEMPOTENCY_CONFLICT`, `FRONTIER_CONFLICT`, `EVENT_INVALID`, `LIMIT_EXCEEDED` |
| Pending / busy | `OPERATION_PENDING`, `BUNDLE_BUSY` |
| Storage / provider | `STORAGE_UNSAFE`, `STORAGE_CORRUPT`, `MIGRATION_REQUIRED`, `SERVICE_UNAVAILABLE`, `VAULT_LOCKED`, `PRIVACY_AUTHORITY_REQUIRED`, `PROVIDER_UNAVAILABLE`, `PROVIDER_REFUSED`, `PROVIDER_TIMEOUT`, `SEMANTIC_RESULT_INVALID` |
| Cancel / internal | `CANCELLED`, `INTERNAL_ERROR` |

A transport-level success/error is distinct from a check's *verdict* — findings never make a
protocol call itself fail. A client deadline never establishes the durable storage outcome; only
the durable operation row does. Cancellation requested before commit has no acknowledged effect on
storage; a shielded commit in flight resolves to a definite outcome regardless, and the client
learns it through a normal response or retry.

## Minimal cooperative client workflow

A minimal, honest client workflow:

1. `start` — attach to (or open) a task/session and obtain a writer identity.
2. Publish the plan and its obligations (`publish_work` with `plan_published` +
   `obligation_published`).
3. Publish material work as it happens (`action_recorded`, `result_recorded`,
   `evidence_recorded`) — batched, with stable event IDs so a retry does not duplicate work.
4. If multiple writers contribute (e.g. a subagent), each uses its own writer identity from its own
   `start` attach.
5. After a resume, call `status` to re-ground before publishing more work.
6. Publish the intended completion `claim_recorded` and current evidence.
7. Run `check` at the current frontier.
8. `respond` to any findings honestly (acknowledge, reject with evidence, or waive with an
   interactive human confirmation).
9. Recheck after any material change. A readable response to a finding returned by that check
   needs no recheck; a redacted or unreadable response does.
10. Call `receipt` for the frontier-bound final wording — and only assert what the receipt's
    coverage actually supports.

Each step uses a stable `request_id`; retries reuse it rather than minting a new one.

## Version and compatibility discovery

`finishup version --json` returns the full `VersionManifest`: package, protocol, storage, migration,
projection, policy, object format, resource, skill, and MCP identities, plus the exact
tested/supported/denied capability sets for external tools. See
[`compatibility.md`](compatibility.md) for what each axis means and how to diagnose a mismatch.
Unknown newer storage schemas block writes (`MIGRATION_REQUIRED`/`STORAGE_UNSAFE`); unknown event
schemas are retained and surfaced as an explicit coverage gap, never interpreted optimistically.

## Security/privacy constraints

Structural SQLite tables, catalog rows, and log fields contain only bounded IDs, enums, digests,
sizes, and timestamps. Payloads that carry user content are encrypted objects. No secret, key,
passphrase, or payload ever appears in an error, log, trace, or MCP text summary. The strict-local
default performs zero external provider egress; optional AI-powered evaluation is gated by an
explicit, human-authorized privacy policy that classifies, minimizes, redacts, and scans before any
disclosure. This threat model protects against casual/at-rest disclosure — a stolen disk, another
local user, accidental sharing — not a compromised active user account, root, or live process
memory. See [`local-service-security.md`](local-service-security.md) and
[`data-egress-and-privacy.md`](data-egress-and-privacy.md) for the enforceable detail, and the
[`docs/runbooks/`](../runbooks/) for operational procedures. Independent security review is a
release gate, not a completed claim — see `docs/public-claims.json` for exactly which statements
have current evidence.

The machine policy is an installation ceiling, not standing authority for every repository. External
LLM admission additionally requires an exact granted row for the installation-keyed commitment of
the trusted session's canonical Git common root (or resolved non-Git directory). Public
`workspace_ref` cannot select it; absence or mismatch blocks before provider construction or
credential-handle minting. Package upgrades preserve machine-policy bytes and may only perform the
bounded no-reapproval legacy narrowing defined by ADR-009.

## Schemas, fixtures and further reading

- [`schemas/`](../../schemas/) — the released JSON Schema set (requests, results, events, config,
  privacy, service, receipts, version).
- [`fixtures/canonical/`](../../fixtures/canonical/) — canonicalization, request-digest, and
  accepted-envelope/entry-digest golden vectors.
- [`fixtures/replay/`](../../fixtures/replay/) and [`fixtures/backward-read/`](../../fixtures/backward-read/)
  — replay and backward-compatibility fixtures.
- [`compatibility.md`](compatibility.md) — the full version-axis and support-matrix model.
- [`data-egress-and-privacy.md`](data-egress-and-privacy.md) and
  [`local-service-security.md`](local-service-security.md) — the enforceable privacy and local
  trust-boundary protocol.
- [`docs/adr/`](../adr/) — the architecture decisions this page summarizes.
