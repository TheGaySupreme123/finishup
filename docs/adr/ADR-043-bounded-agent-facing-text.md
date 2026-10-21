# ADR-043 — Bounded agent-facing text: one composer, and a committed operation never fails on its text

**Status:** Accepted for [issue #1025](https://github.com/TheGaySupreme123/finishup/issues/1025)
(tb4n3 core issue RC-2: N3-1 and family A). Maintainer acknowledgement (TheGaySupreme123,
2026-10-11, tb4n3 remediation owner decisions 1 and 3): raise the MCP text cap from 512 B to
4,096 B, add one never-failing composer, make a committed operation return its stored verdict plus
a typed diagnostic instead of `INTERNAL_ERROR`, and drop the "retry the same request_id" advice
that cannot work. It grants no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/finishup/domain/bounded_text.py`, `src/finishup/mcp/summaries.py`,
`src/finishup/mcp/server.py` (`_result_text`, `_dispatch`, `dispatch_closure_prepare`),
`src/finishup/cli/closure_gate.py` (`_fallback_parts`), `src/finishup/kernel/receipt_builder.py`
(`_keep_by_rank`, `_finish_section`), `src/finishup/domain/receipts.py` (`_bound_human_text`),
`src/finishup/cli/hook_io.py` (`_bounded_context`), `src/finishup/domain/closure.py`
(`scope_inventory_to_selection`), `src/finishup/protocol/recovery.py` (`REASON_REMEDIES`).
**Relates to:** ADR-030 (typed recovery directives and the text-channel budget priority), ADR-033
(the Stop-time closure gate), ADR-009 (the privacy projection of MCP summaries).

## Context

Every bounded text FinishUP hands an agent was built the same way: append the optional clauses with
no budget, budget only the late list-shaped ones, then enforce the bound afterwards by raising,
collapsing to a bare identity, or rejecting the artifact. In tb4n3 (28 real Codex runs) that shape
cost the most important call of a run:

- The check text was capped at 512 bytes. A data-only change (the strict route began recording
  `semantic_route_required: false`) filled one old unbudgeted clause, and the closing `check` of
  **10 of 13 deterministic runs** overflowed: `_bounded` raised, the bridge returned retryable
  `INTERNAL_ERROR response_projection_failed`, and the message said to retry the same `request_id`.
- A replay loads the stored result and re-runs the same deterministic builder, so it failed
  identically. Two agents obeyed the advice (sglang D twice, retro D once) and none of the three
  succeeded. The check had committed and resolved a finding on the service, but the agent never saw
  a verdict: two runs claimed completion ("FinishUP checked the full scope at frontier 1092") from
  status counters alone.
- The same pattern sat in the Stop-gate fallback (it kept `head[:2000]` and dropped every repair
  and close instruction, in 44 of 55 token sets with one blocker and one acknowledgement), the
  public-error text (everything collapsed to bare identity on overflow), the receipt (more than 64
  or 100 rows of a kind built no receipt at all), the receipt `human_text` (a head cut dropped the
  by-id disclosures) and the hook text (cut mid-word with nothing to say so).
- `closure_prepare` named no remedy for its own refusals and, at a long-run frontier, exceeded the
  MCP frame by echoing about 900 evidence rows the agent had already seen.

The owner's rule: an error must say what actually went wrong, and a committed operation must not
become an error because of how its text was rendered.

## Decision

### One composer

`finishup.domain.bounded_text` is the only way a bounded agent-facing text is assembled. Two forms:

- `compose_bounded(required, optional, limit, *, sep, tail, marker, ascii_only)`: `required` parts
  are kept, each `optional` item is a list of progressively shorter variants (the longest that fits
  wins, else the next, else the item is dropped), `tail` is required text that reads last.
- `compose_parts(parts, limit, ...)`: every `Part` renders at its reading-order position and room is
  granted by priority. A required part holds its shortest variant up front; a longer variant is
  granted only when room remains. An explicit priority may place a required part's longer variant
  behind a more important optional sentence.

Both never raise. Output is ASCII (typographic punctuation is folded, anything else becomes `?`).
Required text is shortened only when it alone exceeds the limit, by a documented last-resort cut:
the longest part loses its tail first and ends with a visible marker. `list_variants` renders a
token list as progressively shorter forms with an exact `+N more`.

### Bounds

| Surface | Bound | On overflow |
|---|---|---|
| MCP compact text summary (check, status, receipt, public error, awaiting, closure, other) | 4,096 bytes (`MAX_SUMMARY_BYTES`, was 512) | optional clauses shrink or drop by priority; required core cut only as a last resort |
| One id or token list in a summary | 1,024 characters | fewer values and an exact `+N more` |
| Stop-gate text | 2,000 characters | the ladder drops whole optional sentences; then the composed fallback keeps one instruction per present item family and the close instruction |
| Hook advice text (Codex, Claude Code, Cursor) | 2,000 characters | ends with a visible cut marker |
| Receipt document rows | 100 findings (at most 64 of them resolved history), obligations, responses, claim and evidence refs; 64 gaps; 64 findings per child | the rows that matter most are kept (unresolved actionable first; a self-verified child finding ranks below one that still needs work); the summary section says how many were left out |
| Receipt section | 64 items, 32,768 body characters | the item remainder is counted; a body cut is marked |
| Receipt `human_text` | 32,768 characters | shortened by section; every section keeps its heading; the marker names the shortened sections |

The 2,000-character figure is FinishUP's own conservative cap. No host document available to this
repository states a limit for Codex, Claude Code or Cursor hook text, so it is not claimed as one.

The 4,096-byte bound is on the compact summary, as the 512-byte bound was. The returned text
appends, each with its own bound, the check-totals line (fixed counters), the review-input manifest
line, the reviewer output (12 KiB), publish blocker notices and, only when something degraded, one
sentence naming it; those are not part of the summary and are not budgeted against it.

### Budget priority

The required core of each builder is reserved first and is never dropped to make room for optional
text; the first-granted optional clauses are the instructions and ids the next request needs.

- **check:** the verdict sentence (its shortest form still names the verdict and its coverage
  bound), the task continuation (`overall next`: action and status), the review status/reason, and
  the frontier with its head digest. Then, in order: the recovery directive, the at-budget cue,
  acknowledged-endpoint and disclosure sentences and target refs, finding ids, the redacted-values
  line, the to-do checklist, missing-for-assessment items, the route and await disclosures, the
  check-time-change sentence, withheld items, then children and advice counts.
- **status:** the view and frontier, the ledger freshness, the open-obligation count, the
  unanswered, receipt-blocking and gap counts, and the closure-readiness state with its directive.
- **receipt:** the conclusion, the frontier, the limitation count and the suppressed count.
- **public error:** the error identity and the rejected location first (ADR-030 order), then the
  continuation directive, the typed remedy, commands, guidance pointer and nudge.

### A committed operation never fails on its text

`mcp/server._result_text` does not raise for a result it was handed. By the time it runs the
operation is durable, so a clause or section that fails to render is omitted, named in the text
(`summary_render_failed:<builder>.<clause>`) and recorded as a service diagnostic (operation
`<builder>_summary_degraded`, phase `<builder>.<clause>`, exception class and `finishup` origin); a
builder whose required core fails falls back to the verdict or state token, the frontier, the
failing builder's name and "read status view=compact". The structured result is returned as the
call's result either way. Only a structural failure (the result cannot be serialized, or fails its
response schema) still returns `INTERNAL_ERROR`, as the typed stage `bridge_result_wire_failed` or
`bridge_result_validate_failed`; its remedy covers both cases the bridge cannot tell apart at that
point -- a write is recorded (read `status view=operation`, never resend it, replaying rebuilds the
same result and fails the same way) and a read or dry run changed nothing (repeat it) -- and renders
on the text channel as well as in the structured message.

### Errors say what went wrong

Every `INTERNAL_ERROR` the bridge or a service operation path produces carries a typed
`reason_code` and a fixed remedy that also reaches the text channel (`REASON_REMEDIES`):
`bridge_request_validation_failed`, `bridge_invoke_failed`, `bridge_error_mapping_failed`,
`bridge_result_wire_failed`, `bridge_result_validate_failed`, `closure_prepare_failed`,
`check_pipeline_failed`, `import_publication_failed`, `maintenance_state_unverified` and
`start_state_inconsistent`, and `service_start_failed` for a spawned service that exited during
startup (issue #1040; `phase` names the stage). Their messages claim only what the failing site knows: an invoke or
import failure says the write may or may not be recorded; a failed check says it may not have
produced a verdict, to replay its request_id once (a committed check returns its stored verdict) and
only then to run it again under a new request_id. Status faults were already
typed by stage (`phase`). The service's own `response_projection_failed` keeps its retryable replay
but says to replay once and, if that replay also fails, to stop and read `status view=operation`;
it and `read_projection_failed` now carry their remedy on the text channel too, which they never
did.

### closure_prepare

Each preparation refusal is its own protocol reason code (`closure_attempt_selection_required`,
`closure_obligation_unknown`, ...) with its fixed remedy in the text. A draft phase (`attempt`,
`respond`, `resolve`, `claim`, `receipt`) validates against the whole pinned inventory but echoes
only the rows its selection names, with the per-view totals under `inventory.scope`; the
`inventory` phase and the CLI keep the complete inventory, and an oversized inventory still
returns `LIMIT_EXCEEDED` (`closure_result_too_large`) naming the scoped phases as the alternative.

## Consequences

- A new optional clause costs a priority, not a headroom guess. A data-only change can no longer
  turn a closing check into an error; the property tests render every builder with every optional
  field at its maximum, every verdict, status, reason, readiness state, error code, reason code and
  continuation token, at 4,096 and at 512 bytes.
- Golden text changed only where the old bound forced a squeeze; with room, the reading order and
  wording of every existing clause are unchanged. Three deliberate differences: a public error with
  a rejected `field` but no `reason_code` now renders `Field: <pointer>.` (it rendered nothing);
  the Stop-gate ladder sheds the required limitation ids before the planned-verification hint;
  and the receipt `human_text` marker reads "shortened sections: ..." instead of "remaining
  canonical section content is omitted".
- Adding a protocol reason code now needs a directive, an exemption or (for the typed stages) a
  remedy sentence in `REASON_REMEDIES`.
- Not done: the receipt document has no schema field for omitted-row counts (they are stated in the
  summary section text); a larger change would need a receipt-document version.

## Amendment: Codex reads structured JSON, cut head and tail (2026-10-18, issue #1107)

**Context.** In the n7 trials every one of 195 review results reached the Codex model cut in the
middle. Codex 0.159 (`rust-v0.159.0`) shows a model the MCP `structuredContent`, never the text
channel, whenever structured content is present: `CallToolResult::as_function_call_output_payload`
(`codex-rs/protocol/src/models.rs:2302-2331`) returns `serde_json::to_string(structured_content)`.
`McpToolOutput::response_payload` (`codex-rs/core/src/tools/context.rs:185-212`) prefixes
`Wall time: N seconds\nOutput:\n` and truncates the body with `truncate_middle_chars`, a 50/50 head
and tail split (`codex-rs/utils/string/src/truncate.rs:38-69, 126-129`). For a model slug that is
not in the bundled `models.json`, `model_info.rs:127` falls back to `bytes(10_000)`; with the ×1.2
serialization allowance (`codex-rs/utils/output-truncation/src/lib.rs:16-18`) the model sees the
first 6,000 and the last 6,000 bytes. A bundled slug uses `tokens: 10000` (24,000 + 24,000 bytes).
Codex's `serde_json` is built with `indexmap` (`preserve_order`), so the model sees FinishUP's own
field order. The check result declared `findings`, provenance and the reviewer summary before
`missing_for_assessment` and `overall_next`, and the manifest, totals, fact lineage, coverage and
privacy projection after them, so the continuation sat exactly where the cut falls; and the
per-kind "publish exactly" instruction reached only the text channel, which Codex never shows.

**Decision.**

- Every committed check success result carries `agent_next` (check-result 1.5.0, extended in place
  while 0.3.0 is unreleased): one printable-ASCII line of 1 to 2,048 bytes, composed by the service
  (`domain/review_input_render.render_agent_next`) from closed tokens, fixed sentences and admitted
  subject ids only, never reviewer prose, task text, paths or command text. It states the overall
  next action and status; for `supply_missing_input`, each `agent_suppliable` item with its kind,
  targets and exactly how to supply it, then what counts as supplied (ADR-006 amendment of the same
  date) and the FinishUP-limit count; for every other action the one shared per-action instruction
  (`OVERALL_NEXT_INSTRUCTIONS`, which the CLI's `Overall next` line also reads) and its targets; and
  the predicted receipt conclusion when room remains. Under the bound, every item's kind and target
  count, one direction per requested kind (its shortest variant in the one shared per-kind table)
  and every limit count are reserved first; target lists then expand, every item to the same bound
  with an explicit `(+N more)`, and longer directions only after them, so a direction is never
  dropped for a target id (the ids also ride in `missing_for_assessment`, the direction only here).
  It is composed with the one composer under its own 2,048-byte bound; any failure omits the field,
  never the result (a committed check never fails on its text). It is derived at serialization,
  so older `check_recorded` rows project it too.
- **Field order is part of the contract on the MCP wire.** The check success model declares
  `agent_next`, `overall_next` and `missing_for_assessment` right after `verdict`; the continuation
  precedes every bulky field, and a new bulky field goes after `missing_for_assessment`. Schema
  documents and their digests are canonical (sorted keys) and do not change with this order. With
  the header and the identity prefix, `agent_next` ends below byte 2,700 of the compact JSON, inside
  the smallest head window, whatever the size of the rest of the result. The two structured fields
  are best effort; `agent_next` is the guarantee.
- `status view=operation` returns a finished check's `check_outcome` (status-result 1.4.0, extended
  in place): the verdict, `agent_next`, `overall_next`, `missing_for_assessment`, the AI-powered
  review status, reason and conclusion and the result frontier, rebuilt exactly as a same-id replay
  rebuilds them (`ledger.load_check_result`, then `check.replayed_check_view`). Like a replay's,
  `agent_next` and `overall_next` need the closure basis at the check's result frontier, read from
  a process-local memo (per reading session, eight frontiers) or re-read from a prefix the ledger
  stops re-reading once a later material record (such as an attach's `session_resumed`) exists.
  Without it, a stored `agent_suppliable` item still yields `supply_missing_input` and its lead
  from the stored rows alone (no predicted conclusion); any other continuation is omitted. So
  presence depends on that memo, and after an attach the original writer's resend and the
  successor's page can differ; persisting the continuation with the stored check is a storage
  follow-up (#1100). It is the recovery read for a lost or cut check result; a failure omits it with the bounded diagnostic
  `status_check_outcome_unavailable` and never fails recovery.
- A remedy that exists only on the text channel does not reach a Codex model; anything an agent
  must act on goes in the structured result.

**Consequences.** Codex, Claude Code, Cursor and generic MCP hosts all receive the same structured
field; Cursor's canonical text copy sorts `agent_next` first or second. Up to 2 KB more structured
output per check result. A newer service with an older bridge would reject the new optional field
(closed model); that skew is gated by the version-manifest and control-result digests, as for every
earlier optional field. Canonical vectors: `fixtures/canonical/check-agent-next-1.5.0.case.json`
(AGN-001) and `fixtures/canonical/status-check-outcome-1.4.0.case.json` (AGN-002, the status
page's `check_outcome`), both from `scripts/generate_review_result_delivery_fixture.py`.

### Result delivery amendment (issue #1139, 2026-10-21)

The owner requested the residual fix after #1152: retaining a caveat-first preview did not prevent
Codex from clipping the complete JSON, and a 180-byte field preview could lose the qualification
that changed its meaning. Complete review fields therefore replace the shortened preview.

The Codex 0.159 fallback documented by `test_codex_structured_head.py` is a 10,000-byte policy
with a 1.2 serialization allowance: a 12,000-byte window, retaining the head and tail. The TB-Science
pilot's native stored check results reached approximately 12,023 characters; that includes host
framing and is not a universal character limit. FinishUP budgets result delivery at **9,000 UTF-8
bytes**, measuring JSON escaping, both MCP channels, and a 128-character JSON-RPC request ID.
Claude Code and Cursor have no independently measured larger safe window in that evidence, so
both use the same conservative result budget.

After ordinary disclosure, oversized completed check, receipt, and status results become
`delivery_page` results. Findings' discrepancy, requested action (`detail` and
`challenge.requested_next_step`), alternative interpretation and uncertainty precede bulk excerpts
and provenance. Subject refs, policy/coverage bounds and finding closure facts also remain
action fields. Pages carry whole fields and explicit object/array initialization markers; an individually oversized scalar uses explicit fragments
with its path, Unicode scalar offsets (`unit=unicode_scalar`), total length and canonical-JSON digest. Consumers reconstruct and
verify the complete field before using it. There is no shortened actionable preview. A fixed
`required_next_step`, `truncated`, `complete`, `offset`, `total_items`, `source_digest` and
`next_cursor` distinguish emission, deferred content and consumer reconstruction.
`actionable_complete` marks the end of action fields; subsequent cursor pages contain optional bulk
provenance. `inventory_read` names the separate findings read needed for suppressed rows and receipt
text, or the next page of an existing status inventory. It must be followed before claiming that all
open findings were considered. `complete` does
not assert that the host delivered or the agent read the page.

Continue with `status`, `view=compact`, `delivery_cursor=next_cursor`, the same session/writer and
a fresh read request ID. These domain-separated authenticated cursors select a recorded complete
operation or a status query pinned to its original frontier. Reads reapply the ordinary disclosure
policy; they never dispatch review, append a check or create a receipt. A changed authorized
content digest, changed sink, invalid binding, or missing retained source refuses continuation.
The cursor freezes status head/lag watermarks, so an unrelated append does not invalidate the
original read. Like existing status cursors, a service restart expires it: recover with current
status/findings, without starting a new review. Fresh disclosure audit metadata is outside the
source content digest. There is no plaintext response cache, extra retention capacity, or new network authority.

MCP uses canonical JSON for delivery pages, including text-only hosts. Small checks carry complete
JSON alongside their coverage-bounded prose; when that prose would exceed the result budget, the
complete JSON is the text channel. Repeated required page reads never acquire a status write nudge.
CLI JSON and terminal text carry the same pages and explicit read instruction. Native TUI views retain their complete local
presentation; their finding renderer now includes every delivered finding and all challenge fields.
Authenticated owner exports retain their full local view, because their exact-request approval
does not authorize a generic status continuation. Hook payloads retain their structural bounded
instructions and point to status rather than embed reviewer excerpts. CLI structural status reads used by hooks retain typed snapshots; findings reads use pages.
MCP compact/operation results participate in the result budget. Existing receipt inventory and
redaction limits remain explicit: page completion is not proof that suppressed findings are absent.

Closure preparation reconstructs status pages before consuming its pinned inventory. It verifies
container types, fragment offsets/digests, contiguous page offsets and the content digest. Each
status result has a 128-page, 1 MiB aggregate serialized-page read bound; crossing it retains the
existing `closure_inventory_limit` refusal and never drafts from a partial inventory.

Page admission includes inventory selectors and both cursor values. It reduces the deterministic
fragment size when that overhead needs more room, measuring every atom against the worst page
envelope. Mapping traversal is canonical, so reloads with different insertion order keep the
same partition. The authenticated cursor index stays outside compression to make its maximum
serialized length exact.
