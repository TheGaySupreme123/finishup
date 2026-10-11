# ADR-043 — Bounded agent-facing text: one composer, and a committed operation never fails on its text

**Status:** Accepted for [issue #1025](https://github.com/TheGaySupreme123/yoetz/issues/1025)
(tb4n3 core issue RC-2: N3-1 and family A). Maintainer acknowledgement (TheGaySupreme123,
2026-10-11, tb4n3 remediation owner decisions 1 and 3): raise the MCP text cap from 512 B to
4,096 B, add one never-failing composer, make a committed operation return its stored verdict plus
a typed diagnostic instead of `INTERNAL_ERROR`, and drop the "retry the same request_id" advice
that cannot work. It grants no runtime, credential, disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/domain/bounded_text.py`, `src/yoetz/mcp/summaries.py`,
`src/yoetz/mcp/server.py` (`_result_text`, `_dispatch`, `dispatch_closure_prepare`),
`src/yoetz/cli/closure_gate.py` (`_fallback_parts`), `src/yoetz/kernel/receipt_builder.py`
(`_keep_by_rank`, `_finish_section`), `src/yoetz/domain/receipts.py` (`_bound_human_text`),
`src/yoetz/cli/hook_io.py` (`_bounded_context`), `src/yoetz/domain/closure.py`
(`scope_inventory_to_selection`), `src/yoetz/protocol/recovery.py` (`REASON_REMEDIES`).
**Relates to:** ADR-030 (typed recovery directives and the text-channel budget priority), ADR-033
(the Stop-time closure gate), ADR-009 (the privacy projection of MCP summaries).

## Context

Every bounded text Yoetz hands an agent was built the same way: append the optional clauses with
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
  a verdict: two runs claimed completion ("Yoetz checked the full scope at frontier 1092") from
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

`yoetz.domain.bounded_text` is the only way a bounded agent-facing text is assembled. Two forms:

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

The 2,000-character figure is Yoetz's own conservative cap. No host document available to this
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
`<builder>_summary_degraded`, phase `<builder>.<clause>`, exception class and `yoetz` origin); a
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
`start_state_inconsistent`. Their messages claim only what the failing site knows: an invoke or
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
