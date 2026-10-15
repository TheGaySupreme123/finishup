# Status render performance (issue #916)

The DeepSWE v2 run measured a cached 100-row `status view=evidence` cursor page at ~2.1 s
(~0.5 s fixed plus ~18 ms per returned row) and `closure-prepare` at 16-55 s on ledgers of
about 1,000 events. This runbook records the profile that attributed that cost, the change that
removed it, and how to replay the measurement.

## Harness

[`tests/integration/application/test_status_render_cost.py`](../../tests/integration/application/test_status_render_cost.py)
builds a deterministic Codex-shaped ledger
([`tests/builders/status_render_cost.py`](../../tests/builders/status_render_cost.py)): 998 events,
about 70% hook-observed action/result/evidence triples appended under the observation author,
agent-published actions, results and evidence, one open obligation, a completion claim and a local
check. It renders pages through the whole path one MCP `status` response takes: `status`, the
daemon's privacy projection with the local-disclosure receipt written to a SQLite privacy catalog,
the control envelope in the service and the client (modeled as separate processes), and the MCP
bridge rendering. It runs in the `sqlite-integration` CI job.

- `test_status_render_matches_pre_change_golden` pins every rendered page, MCP text, durable
  receipt, audit subject and the `closure-prepare` inventory to
  `tests/fixtures/status-render-cost/golden.json`, generated from the code before the change. Two
  rows carry a never-send credential shape (one hook-observed description, one agent-published
  reference), so the omission reasons mix `never_send_redacted` and
  `local_disclosure_not_authorized`. Regenerate only for an intended output change
  (`FINISHUP_STATUS_RENDER_GOLDEN=write`, see the module docstring).
- The cost tests never compare wall-clock time with a fixed threshold. They count deterministic
  work (stock JSON Schema validator constructions per valid page: 0; leaf-rule scans on a second
  page: 0) and compare CPU time only as a ratio to a baseline measured in the same run (ten
  canonical encodings of the same page), with a 3x margin.

Replay with `-s` to print the stage table. To measure the original code, extract a baseline
source tree and put it first on `PYTHONPATH`; the golden test runs unchanged there.

## Profile and result

Min CPU of five renders of one cached 100-row evidence cursor page, 998-event ledger, on a shared
4-core Linux container. The *before* column ran at load average ~20 and the *after* column at ~7,
so the absolute numbers are inflated and noisy; the ratios are the comparable figures.

| Stage | Before | After |
|---|---|---|
| `status` query and page model | 6 ms | 5 ms |
| Privacy projection, receipt, result model | 400 ms | 89 ms |
| Control envelope check and frame (service) | 499 ms | 36 ms |
| Control frame decode and parse (client) | 691 ms | 96 ms |
| MCP bridge rendering | 488 ms | 22 ms |
| Total | 2,084 ms (83 units) | 249 ms (12.5 units) |
| Stock validator constructions per page | 11 | 0 |
| `closure-prepare` inventory, 21 status calls | 31.7 s CPU, 129 s wall | 3.2 s CPU, 3.4 s wall |
| 100-row page at 410 / 1,508 events | 2,070 / 2,064 ms | 278 / 259 ms |
| 16-call compact burst / solo (CPU) | — | 644 / 37 ms |

A cProfile attribution of one page before the change put almost all of it in JSON Schema
validation: every page was validated against the full status-result or control-result schema
eleven times (result model twice, daemon envelope check and frame encode, client decode and
parse, bridge dump, revalidation and rendering), and the stock `anyOf`/`oneOf` keywords walk every
row of each failing branch to collect diagnostics. The leaf classification scanned all 1,170 leaf
rules per leaf. The never-send scan (~18 ms profiled) and the receipt reserve/complete write
(~43 ms profiled) were minor, so receipt granularity (issue item 3) does not need to change.

The fast path reads private `jsonschema`/`referencing` resolver state and falls back to the stock
validator when it cannot, which stays correct but silently loses the speedup.
`test_the_pinned_dependencies_take_the_fast_path_for_valid_results`
(`tests/unit/protocol/test_schema_validity_checker.py`) fails if, with the locked versions
(`jsonschema` 4.26.0, `referencing` 0.37.0 at the time of writing), any valid workflow result,
status page or control envelope needs the stock validator; a dependency upgrade that trips it must
adapt the checker or accept the fallback on purpose.

The change keeps every decision and every byte:

- Valid instances are decided by a first-error validity checker: the same keywords, except that
  `anyOf`/`oneOf` stop each failing branch at its first error and `$ref` resolves once per base URI.
  Anything it rejects is validated again by the stock validator, which builds the unchanged
  diagnostic. A bounded per-process memory of (schema, canonical bytes) pairs found valid answers
  repeated validations of identical content, including a control envelope's body already validated
  as a status result. A differential test holds it to the stock verdict on every result model,
  every status view and systematic mutations.
- Leaf classification is decided once per pointer shape (array indexes erased); no rule names an
  index, which the rule builder now enforces.
- The projection encodes the source once for the subject digest and the audit context.
- Every projection still classifies, scans and receipts every candidate leaf. The never-send scan
  still runs on blocked leaves because its result is the omission reason and the receipt's secret
  scan count.

## Host and OS coverage

The change is in the shared service, control protocol and MCP bridge path, so it applies equally
to Codex, Claude Code and Cursor. The numbers above come from the in-process harness on Linux
only. Per-host dogfood timings on macOS, Linux and Windows through WSL 2, and a 2 vCPU runner, are
not yet measured; issue #916 owns that follow-up. Likewise unmeasured: first-page and
cursor-page renders after an append, session reattach, projection rebuild, service restart or
schema-resource reload on an installed service, and `closure-prepare --output` against a reader
racing the replacement, a crash during the rename, or a filesystem that refuses a directory
flush (the unit tests only simulate a refused or failed directory flush).
