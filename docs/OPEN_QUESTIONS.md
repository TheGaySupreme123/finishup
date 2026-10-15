# FinishUP — decision ledger and release-gate dispositions

**ADRs:** ADR-001 through ADR-029 | **Related:** [`docs/INTERFACES.md`](INTERFACES.md),
[`docs/adr/`](adr/), release-evidence generation

## Purpose

The next product release candidate is **0.3.0** (release tracking: #785); **0.2.4** remains
the published line until the candidate's gates pass. The candidate carries Linux/WSL
compatibility fixes (**0.2.1**), install-path fixes (**0.2.2**), the integration and session
recovery repairs (**0.2.3**, #786) and the guided desktop installation (**0.2.4**, #767). The
dated v0.1 decisions below remain history; the 0.2 re-dispositions govern the current line. Real
WSL 2 and native Linux Claude/Cursor session acceptance remain untested and native Codex
multi-agent acceptance (#499, #507) remains open. The #767 first-run gate landed in 0.2.4 and is
carried here; its installation evidence is configuration evidence, not session acceptance.
The privacy-receipt CLI bugs #731 and #732 are fixed in this candidate (#783). This version
update does not close a gate or add a supported capability cell.

This file is the one canonical ledger of the decisions taken for v0.1 and the dated dispositions
of every release gate. As of the v0.1.0 public-alpha reconciliation (2026-08-20) it holds no open
questions: every founder item is resolved, every empirical gate carries a disposition, and the two
independent reviews are deferred with binding conditions. A public claim may strengthen only by
adding the evidence its gate names and updating this ledger in the same review.

## How to read an item

Every item has a stable ID, class (`founder`, `empirical`, `independent-review`, or `deferred`), a
working default, an owner, and a freeze condition. An item is removed only by recording the answer
in its owning ADR and moving a short result into the resolved-decisions section below.

## Behavior

Before implementation starts, all `founder` items must be accepted or deliberately amended. Before
the affected release claim ships, all `empirical` and `independent-review` items must have dated,
artifact-bound evidence. `deferred` items do not block v0.1 and may not leak into v0.1 help,
schemas, capability claims, or implicit adapter behavior. As of 2026-08-20 every item is either
resolved, dispositioned for the v0.1.0 public alpha, or deferred; none of the E-gate ledger entries
blocks the v0.1.0 tag under the dated maintainer decisions below.

## Errors and edge cases

- Silence is not acceptance: a working default remains visibly provisional until its freeze
  condition is met.
- A library/tool version is never settled by prose alone; the exact release lock and executable
  capability evidence are authoritative.
- An empirical threshold cannot quietly change protocol identity or honest wording. Such a change
  requires an ADR amendment.
- A deferred feature cannot be implemented opportunistically while adjacent code is being built.

## Invariants

1. Ignored architecture/strategy inputs are never required to interpret an item or its answer.
2. Founder questions describe product/legal choices, not measurements engineers can answer.
3. Release claims remain narrower than the evidence produced by the applicable gate.
4. Closing an item updates every affected ADR, code path, test, and fixture in the same review.

## Enforcement

`scripts/scan_public_boundary.py` rejects private drafting dependencies;
`tests/conformance/claims/` binds every public claim in `docs/public-claims.json` to real evidence
and holds each claim at its honest `release_status`; release-evidence generation refuses open
applicable empirical/review gates.

## Decision record

### Phase 0 implementation reconciliation — 2026-07-17

The pre-code consistency pass rechecked the private P0–P4 review catalogue against the current
public authorities and closed every still-live implementation ambiguity required by the next
materialization boundary. Later-wave byte-identity gates remain explicit below and must close
before their owning modules are coded:

| Review seam | Frozen resolution | Public authorities updated |
|---|---|---|
| P0-1 finding kind/origin and fixture ownership | `FindingKind` and `FindingOrigin` are independent; the exhaustive fourteen-kind trait table fixes priority/actionability, and the reviewed 48-file corpus covers every kind without inventing a `fixtures/policies/` family. | `INTERFACES.md`, finding/policy/fixture owner specs and conformance specs |
| P0-2 verdict versus receipt conclusion | Checks retain four `CheckVerdict` values; receipts retain three `ReceiptConclusion` values, with one exact projection-derived correspondence and conservative precedence. | `INTERFACES.md`, ranking, receipt, event, schema, fixture and reducer specs |
| P0-3 shared-registry drift | `INTERFACES.md` owns shared names and semantics. The pass reconciled ranking context/coverage, canonical depth, adapter-only frame caps, schema kind/role maps, control/privacy methods, operation recovery values, secret purposes and human-authority values. | `INTERFACES.md` and every affected owning spec |
| P0-4 unsupported non-LLM channel fork | A proposal to enable an unavailable v0.1 non-LLM channel is rejected immediately as `channel_unavailable`, creates no pending consent or I/O, and a crafted/imported enabled row remains fenced while producing a structural no-dispatch receipt. | ADR-009, privacy policy/domain/fixture and gateway specs |
| P1–P4 implementation gaps | Receipt reads, recorded coverage, memory/SQLite parity, catalog DDL ownership, keyed scope commitments, service-security ownership, idle-relock reachability, exact TLS wording, recovery contracts, CLI/error mappings and dangling names were reconciled. | Affected ADRs, owning specs, schemas, fixtures and test specs |
| E-001 implementation lock | The build lock is frozen to the exact 2026-07-17 versions in ADR-007 and repository owner specs; this does not manufacture platform/provider support evidence. | ADR-007, repository owner specs and E-001 below |
| Wave B implementation lock (2026-07-18) | B0 now has one closed 127-reason registry, implementable Pydantic 2.13 root/presence semantics, deeply immutable package-only schema loading, and a 52-route schema bundle whose gates resolve entirely from local resources. | `INTERFACES.md`, protocol/model/schema owner specs, coverage schema and manifests |
| Wave B replay/policy lock (2026-07-18) | Redaction-safe full replay uses one nonplaintext durable projection locator per accepted event; projection records/gaps and contradiction lifecycles are exact. Local-check bases have explicit status/outbound mappers, complete subject cardinality/order/templates, and fixture-aligned coverage/frontiers. | Event/projection/reducer/migration, local-check/policy/AI-powered review specs, REP/ADV fixtures and tests |
| Wave B port/status lock (2026-07-18) | Frozen checks always carry the current lease, replay has a distinct internal commit result, dependency staleness has one terminal conflict outcome, row queries own typed positions, and candidate status is the local-check whole-case exception. | Ledger/memory/SQLite/status/check specs, `INTERFACES.md`, conformance/property/integration tests |
| Wave B1 domain lock (2026-07-18) | Domain materialization uses exact canonical strings/timestamps/sequences, closed local coverage/frontier codecs, lossless receipt refs/sections, selected-attempt AI-powered review provenance, lossless lifecycle identity bounds, exact receipt-object mirrors, and an operation/channel event-family admission matrix. | Value/clock/coverage/model/event/finding/receipt/application owners, schema owners and closest tests |
| Wave B2 kernel lock (2026-07-19) | Deterministic ranking uses the frozen verdict/conclusion precedence and stable finding order; receipt construction uses the canonical policy-version tuple order, lossless refs/sections, and byte-exact digest preimages. Protocol replay/frontier/unknown-event behavior and the canonical fixture mirrors are executable and regression-covered. | Ranking/receipt owners, protocol identity/service-control owners, canonical receipt fixtures, package resource mirrors and focused unit/property/conformance tests |
| Wave B3 port lock (2026-07-19) | The application boundary is frozen as explicit inert port modules with closed records/enums, opaque key and secret capabilities, separate start/check leases, bounded importer/maintenance state, AI-powered review packet limits, and an ADR-009 privacy boundary that rejects unavailable channels before consent or I/O. Adapter/runtime construction remains outside the port package. | `INTERFACES.md`, domain privacy and all port owners, protocol bounds, and focused unit/property/conformance tests |
| Wave B4 adapter lock (2026-07-19) | Configuration, key/object stores, memory/SQLite ledgers, start catalog, importer persistence, maintenance, recovery, migrations, and local Unix transport are materialized with generation-fenced durability and memory/SQLite parity. SQLite reopen reconstructs canonical structural history and verified payloads; importer publication reservations are permanent; check/finding commits advance one canonical ledger; unavailable runtime evidence fails closed. | Config, adapter, migration and resource owners; ledger/importer/privacy port amendments; object/key vectors; cumulative unit/property/conformance/integration tests |
| Wave B5 service lock (2026-07-19) | The trusted local service boundary is materialized with strict ordinary/confidential framing, same-user fixed endpoints, typed clients, vault and unlock generations, durable throttling, one-use human authority, session-triggered relock, one shared ready runtime, structured privacy-safe logging, and bounded daemon drain/close behavior. Privacy receipt inspection is schema-exact and tagged; lifecycle stop has its own closed result. Production ready-application composition remains owned by Wave B6, where the application factory first exists. | Service, runtime/session, observability, control/privacy receipt amendments, focused subprocess security tests, and cumulative non-live gates |
| Wave B6 application/integration lock (2026-07-19) | Every workflow/import/review use case returns a sink-independent internal body; the daemon performs the sole ordinary-client projection from canonical admitted control bytes, catalog-verified route identity, and one durable objectless privacy-audit record. Agent-context provenance widening is limited to verified self-authored material, local-human projection remains a separate sink, and even an all-structural result completes a receipt. START and CHECK crash continuation use one current verified encrypted object pointer; CHECK reopens its lossless frozen case and pinned local findings without rerunning policy or reallocating IDs. Codex JSONL import is stderr-absent only, uses exact durable source digests for review, and never accepts caller-invented commitments. Codex integration remains explicitly unsupported with empty tested profiles until E-002 evidence exists. Maintenance is preview/digest/acceptance bound, machine-bound work never acquires a secret, portable recovery uses a one-shot generation-bound handle, diagnostics are path-free, and invalid/no-op migration targets are rejected. The production service graph starts locked, constructs the application only inside the successful unlock generation, binds authenticated local endpoints after singleton acquisition, and serializes activation/lock/session/stop cleanup. | Application, privacy, importer, integration, service/daemon, ledger/object/migration owners; `INTERFACES.md`; focused unit/property/conformance/integration/subprocess gates |
| Wave B7 client/resource lock (2026-07-19) | CLI and `python -m finishup` are exact service-only peers with bounded exit/render behavior; confidential commands acquire secrets only through foreground current-user controlling-TTY ceremonies and zero mutable buffers after one-shot use. MCP pre-gates unsupported protocol versions, exposes exactly six projected service tools and four verified static resources, uses frozen descriptor/set digests, emits bounded schema-valid errors/summaries, and keeps stdout transport-pure under partial I/O, EINTR, backpressure, cancellation, and signals. The installed resource manifest verifies 71 entries; its set identity has one explicit runtime-support self-exclusion while the concrete support bytes remain hashed. Artifact and post-build evidence are typed external/absent references, not self-digests; development Codex/MCP capability sets remain empty and unverified. Successor startup removes a stale local endpoint only after singleton acquisition and exact stale-inode proof, and a valid stop response is correlated before EOF closes unrelated pending calls. | CLI/MCP/resource/version/service-client/control owners; guidance/skill/support mirrors; schema/resource manifests; focused conformance/subprocess and cumulative non-live gates |
| Wave C migration lock / W-C-001 (2026-07-19) | Bundle migration `0001` is frozen as one standalone root SQL file with a byte-identical installed resource. Its importer schema owns four tables, including permanent `(publishing_writer_id, request_id)` and `(source_identity_digest, publication_ordinal)` reservations; ordinals `0..batch_count-1` identify batches and ordinal `batch_count` identifies the final report. The runner loads only registered resource bytes, and fresh-schema, constraint, identity, and foreign-key probes pass. | Root/resource migration owners, SQLite migration runner, importer/ledger owners and focused migration tests |
| Wave B8 privacy/egress lock (2026-07-20) | The scripted/local-model/OpenAI provider adapters and the policy-enforcing outbound gateway are materialized: a generation-fenced `ProviderRegistry` snapshot swap gated on policy/vault/human-authority validation, dispatch bound to one exact credential-free factory per attempt, and idempotent terminal transport closure. `ApprovedOutboundCase` carries only its real domain fields (payload bytes, included item IDs, digests); the outbound-case document's `review_packet`/`review_selection_digest` are wire-schema fields, not domain-value attributes. The honesty/operations/surfaces conformance suites close the remaining Wave B/E behavioral gates and, in doing so, found and fixed four real defects: status's future-frontier mapping to `FRONTIER_CONFLICT` instead of the spec's `INVALID_REQUEST`, a status pagination cursor encoding that could never round-trip against `CursorWire`'s pattern, a `candidate_findings` status view that always failed validation on a `JsonObject`-vs-`dict` mismatch, and a respond evidence serialization that sent an explicit null for a field the wire schema requires omitted. Two `FILE_MANIFEST.md` ordering defects and one missing `tests/unit.md` index entry (`test_catalog_audit.py`, `test_local_enforcer.py`) were reconciled; `verify_spec_manifest.py --check` now reports only its own necessarily self-referential prose examples. | Provider adapter, gateway, status, respond, service owners; `INTERFACES.md`; `FILE_MANIFEST.md`/`tests/unit.md`; focused unit/property/integration/conformance tests |

### Later-wave pre-code gate

None. W-C-001 is resolved by the frozen Wave C migration lock above.

No founder-class implementation question remains. Empirical and independent-review gates below
remain release blockers where stated; they do not block building the bounded v0.1 implementation.

### Founder decisions required before implementation freeze

None. Every founder item formerly listed here is resolved below. Empirical release evidence and
the two independent security reviews remain required; closing product choices does not manufacture
that evidence.

### Empirical release-lock gates

| ID | Evidence to freeze | Current posture | Owner/output |
|---|---|---|---|
| E-001 | Release refresh of the 2026-07-17 implementation-locked Python 3.14.6, uv/uv_build 0.11.29, APSW 3.53.3.1/SQLite 3.53.3, dependency, Ruff 0.15.22, Pyright 1.1.411, Node 26.5.0/npm 12.0.1, MCP 1.28.1, and provider SDK pins | Implementation identities are frozen in ADR-007 and the owning repository specs; re-evaluate newest stable versions at release lock without inferring support from a pin. | Dependency refresh review, regenerated `uv.lock` and npm lock, version manifest, exact runtime/capability evidence. |
| E-002 | Exact supported Codex versions and protocol behavior | Implementation now represents Codex skill support with jointly empty capability-profile IDs, supported versions, and hook map, classifying integration as unsupported/incompatible. Local `0.139.0` and names-only `0.144.5` observations advertise nothing; every populated exact cell must first run the critical capability matrix. | ADR-005, capability evidence, support matrix. |
| E-003 | Advertised OS/architecture/filesystem/keyring matrix | macOS arm64 and manylinux x86-64 are candidates only until clean-artifact jobs and restore drills pass. | ADR-003/007, platform capability evidence. |
| E-004 | Ownership heartbeat/stale thresholds, operation/import/check lease durations, writer-queue depth, MCP idle-route cache | Preserve generation fencing regardless of measured durations; choose bounded values from fault/contention runs. | Runtime/storage conformance evidence. |
| E-005 | WAL/checkpoint/page/backup/soak budgets, object-layout scale, and property/state-machine run budgets | Public caps already bound correctness; tune operational thresholds without weakening atomicity or coverage. | Nightly fault/soak evidence and runbooks. |
| E-006 | Argon2id recovery parameters | Calibrate on the slowest advertised profile, record parameters in each artifact, and pass clean-profile restore. | ADR-004 independent review and recovery evidence. |
| E-007 | Exact AI-powered review provider/model/endpoint profile, current provider data-use record, case cap, timeout/retry budget, cost/usage fields | One bound profile only; recommendation eligibility requires current artifact-bound training and retention facts for the exact route, with human-access and exception facts disclosed separately. Unprofiled endpoints remain unavailable and provider credentials never use environment/config/ordinary client channels. **Status (2026-07-22 Issue 6 slice, no flip):** production live-provider composition remains design-gated; the privacy-fenced optional path now has audited not-configured/not-run receipt disclosure (`semantic_review_not_configured` / `semantic_relevance_review_not_run`, distinct from `optional_semantic_review_blocked_by_policy`) and failure degradation that preserves local-check truth without a false clean. **Status (2026-08-05 Issue #139 slice, no capability flip):** the package catalog records favorable current policy evidence for the exact OpenAI API, Anthropic commercial API, direct xAI API, and Fireworks Responses `store=false` routes. Gemini remains conservative because the binding does not prove paid tier; OpenRouter and Vercel remain conservative because their bindings do not constrain downstream/fallback providers; owner-declared routes remain unknown. These records support setup advice only. Whether each host/model honors the AI-powered review protocol in the installed runtime remains unclaimed until authorized live evidence records the exact request, response, route, and receipt. **Status (2026-09-04 issue #582, design flip of "one bound profile only"):** one bound primary profile plus at most one declared fallback, and the fallback is exactly the other external authority — API provider and Codex subscription in either order via the nonsecret `[semantic_fallback]` selector — never a second API provider or a generic endpoint. The fallback is a separately credentialed, separately approved exact binding, engaged only for the closed could-not-serve set with its own retry budget and receipt, and named in provenance as `fallback_from` (ADR-006/ADR-009 amendments 2026-09-04). Recommendation eligibility still reads the primary's exact route; no live paired-dispatch interoperability is claimed. | ADR-006/009 opt-in live capability and data-use-profile evidence. |
| E-008 | Release build reproducibility, SBOM/checksum/provenance formats, artifact allowlist, and public-boundary detector vocabulary | No signing claim until a tested end-user verification command exists. | Packaging suite and release workflow evidence. |
| E-009 | Codex skill materiality/activation examples | Freeze examples from bounded dogfood evidence; v0.1 must prefer explicit activation and avoid triggering on trivial work. | Skill fixtures and Codex capability evidence. |
| E-010 | Local service endpoint, peer-credential, permission, lifecycle, keyring, memory-protection, and relock matrix | No platform support claim until a clean-profile service proves authenticated local attachment, locked/ready transitions, crash recovery, suspend/session-lock relock, and secret-canary absence. | Service/control capability evidence and platform matrix. |
| E-011 | Privacy classifier, never-send scanner, minimizer/redactor, consent, endpoint binding, and receipt matrix | No “policy enforced” claim from configuration alone; every profile, channel, scope intersection, denial, and dispatch path must produce exact evidence. Imported Codex command/model text is intentionally verbatim only in encrypted local objects and receives no import-time content scan; every later disclosure crosses the one authoritative classifier/secret scan, tested across shell assignments, inline auth/header flags, bearer/API-key forms, credential URLs, and JSON/UTF-8/chunk splits. | ADR-009 privacy conformance, property, integration, and live-profile evidence. |
| E-012 | Public security, conduct, and support routes | Before public release, prove that private vulnerability reporting is enabled, the single maintained private mailbox `support@finishup.dev` (serving security fallback, conduct, and support per the 2026-08-20 F-006 amendment) is monitored by maintainers, and the repository issue route is available for ordinary support. | Repository policy-link check plus dated maintainer delivery/response drill. |
| E-013 | Exact harness lifecycle trigger points and observation events a hook profile may bind to; context compaction among triggers | Codex `0.144.5` currently exposes `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, and `Stop`, but names alone are not support evidence. A v0.1 exact capability cell may declare a trigger arm and/or a nonempty `observation_events` set only after an installed-artifact run freezes event, payload/privacy boundary, permitted action, coalescing/loop guard, gap codes, and failure behavior for each arm. Observation evidence must prove dual-source ingest (hooks primary; selective session-stream reconciliation), consent/revoke behavior, and that `hook_observed` is earned only from real observation evidence. Unproven cells remain `None` / empty observation arms; unprofiled harnesses stay cooperative-only. **Status (2026-09-05, issue #494 / ADR-027, no capability flip):** the lineage and project grouping model is ratified. Mapping `SubagentStart` / `SubagentStop` or any other host delegate signal onto a child task remains evidence-gated in #506–#508. This status populates no capability cell and does not earn `hook_observed`. | ADR-010 installed-artifact capability evidence and exact harness support-matrix cell. |
| E-014 | Publication-ceremony budget and work-package grouping examples | Dogfood must measure publications per work package, model-authored event bytes, token/latency overhead, abandoned or stale-ledger rate, skipped checks, and user-visible chatter. Large inventories must compare grouped work packages with per-file publication amplification; no threshold is inferred from file count alone. | Harness-neutral capability/conformance fixtures plus bounded dogfood evidence used to freeze guidance examples and budgets. |
| E-015 | Exact structural subject-state capture matrix | No support claim until installed-artifact tests freeze Git/object-format and OS cells, symlink/submodule/racy-worktree behavior, file/byte caps, exclusions, sanitized environment, path/content-free output, and no network or trusted-service reachability. | ADR-011 CLI/subprocess, packaging-boundary, privacy, and capability evidence. |
| E-016 | TOML as alternate nonsecret settings surface, including official OpenAI vs owner-declared OpenAI-compatible HTTPS origin+model | **Working (ADR-014).** Config validates constrained `https_origin`, rejects secrets/free `base_url`, mutual-excludes official vs owner-declared, and writes the same fields from wizard/menu/`finishup provider endpoint`. Owner-declared data-use defaults to `unknown` (never `assisted`). Privacy desired-state export/apply classifies widen vs tighten and never silently widens. Remaining: optional live owner-declared host probe before advertising verified interoperability beyond the protocol cell. | ADR-014, ADR-006/009 amendments, config/privacy/openai_responses specs, unit fixtures; live probe optional. |
| E-017 | Agent Plugins portable-carrier host cells (ADR-023, issue #149) | The Claude Code issue #154 candidate populates static/render plus exact local CLI `2.1.241` project-marketplace install, fresh-session activation, skill registration, tool visibility, and connected plugin MCP evidence. Strict validation, source/render/cache identity, disabled default, list/details discovery, and exact init-event reduction are proven. A correlated model call was blocked because the isolated Claude config was not authenticated; only SessionStart/SessionEnd hook delivery was observed and the separately installed older FinishUP lacked the new ingress command. Full hook-event/accepted-observation, model use, AI-powered review dispatch, privacy receipt, and workflow receipt remain unobserved, so the full support cell is not yet populated. Every other host/scope/format surface remains independent. | ADR-023, `claude-code-cli-native-project-2.1.241.case.json`, per-host installed-artifact capability evidence and support-matrix cells. |

### v0.1.0 public-alpha gate dispositions — 2026-08-20

v0.1.0 may ship as a **public alpha** under a maintainer-accepted narrowed claim set. Each
empirical gate below carries exactly one dated disposition; a later dated re-disposition in the
0.2 section that follows supersedes it for that release while the original row stays as history:

- **Closed by decision** — a dated product decision replaces the calibration or refresh for the
  alpha; the decision itself is the recorded answer and manufactures no support evidence.
- **Narrowed** — the stronger public claim the gate was protecting does not ship; only the
  already-bounded wording in `docs/public-claims.json` ships, and any claim whose own text names
  missing evidence stays `not_yet_evidenced`.
- **Open** — still blocks tagging v0.1.0.

Every deferred or narrowed gate reverts to a release blocker for any later release that widens the
affected claim, and for the first non-alpha release regardless.

| ID | v0.1.0-alpha disposition |
|---|---|
| E-001 | Closed by decision — v0.1.0 releases on the frozen 2026-07-17 implementation locks unchanged; no refresh is performed and pins still advertise no platform/provider support. A dependency refresh review is re-required for the first non-alpha release. |
| E-002 | Not applicable (narrowed) — v0.1.0 ships jointly empty capability-profile IDs, supported versions, and hook map; no populated exact Codex capability cell ships. |
| E-003 | Narrowed — macOS arm64 and manylinux x86-64 remain candidate cells evidenced only by the CI and release jobs that actually ran for the exact candidate; no keyring/filesystem matrix or restore-drill-backed support wording ships. |
| E-004 | Closed by decision — the reviewed working thresholds ship as explicit uncalibrated operational defaults; the generation-fencing correctness invariants are CI-evidenced independently of the chosen durations, and no tuning or capacity claim ships. |
| E-005 | Closed by decision — same treatment as E-004 for WAL/checkpoint/backup/soak budgets; public correctness caps stay CI-evidenced, nightly fault/soak calibration is deferred, and no operational-threshold claim ships. |
| E-006 | Narrowed — Argon2id parameters ship as fixed reviewed defaults recorded in each artifact; the clean-profile restore drill is not evidenced, so `recovery.machine_bound_vs_portable` stays `not_yet_evidenced` and portable-restore wording ships only in its own drill-gated conditional form. |
| E-007 | Not applicable (narrowed) — no live AI-powered review provider profile ships; production live-provider composition remains design-gated and the catalog data-use records remain setup advice only, exactly as already stated in this gate's posture. |
| E-008 | Narrowed — the release workflow's machine gates (clean source identity, checksums, SBOM, artifact allowlist, evidence bundle) are the only packaging claims; no signing claim and no reproducibility claim ships. |
| E-009 | Not applicable (narrowed) — the shipped skill examples remain as authored with the explicit-activation preference; no activation-quality or materiality-threshold claim ships. |
| E-010 | Narrowed — local service endpoint, lifecycle, and secret-boundary behavior is evidenced by the per-PR subprocess suites on the CI platforms; no broader platform relock/keyring/memory-protection matrix ships. |
| E-011 | Narrowed — privacy enforcement claims are bounded to the per-PR conformance, property, integration, and subprocess evidence; no live-profile claim ships. |
| E-012 | Closed by decision (2026-08-20, issue #366) — GitHub private vulnerability reporting is enabled, `yoetz.dev` is registered with active MX records, and the maintained `support@yoetz.dev` mailbox exists. The maintainer accepts those routes for the public alpha without making a delivery-time, response-time, availability, or monitored-SLA claim; a completed delivery/response drill is required before any later release makes one. `https://schemas.yoetz.dev/0.1/` is deployed from the exact candidate before tagging and every hosted byte is re-fetched and compared by the tagged workflow. |
| E-013 | Not applicable (narrowed) — no trigger arm and no observation arm ships; every capability cell remains `None`/empty, `hook_observed` is unearnable in v0.1.0, and unprofiled harnesses stay cooperative-only. |
| E-014 | Closed by decision — publication-ceremony guidance remains qualitative, informed by bounded dogfood use; no numeric budget or grouping-threshold claim ships, and measurement is required before any later budget claim. |
| E-015 | Narrowed — `finishup state capture` ships fail-closed with no advertised capability cells; `support.structural_subject_state_capture` stays `not_yet_evidenced`. |
| E-016 | Working (unchanged, ADR-014) — the optional live owner-declared host probe is not performed and verified interoperability beyond the protocol cell is not advertised. |
| E-017 | Open, narrowed (row added 2026-09-05; the gate post-dates the 2026-08-20 alpha and was never a v0.1.0 tag gate). The Claude Code `claude-code-cli-local-project-2.1.241` cell ships as an implementation/fixture pin declaring a `SessionStart` trigger arm with `observation_events=()`: its fixture proves strict validation, source/render/cache identity, disabled default, discovery, fresh-session plugin/skill/tool registration, and connected plugin-owned MCP, while a correlated model call, accepted observation, AI-powered review dispatch, privacy receipt, and workflow receipt remain unobserved for that version. The 2026-09-04 live capture on Claude Code `2.1.251` proves only the bare-JSON-string `PostToolUse` `tool_response` shape and adds no capability-profile entry (`docs/runbooks/claude-code-integration.md`). Cursor `cursor-ide-3.17.8` and `cursor-cli-2026.07.09-a3815c0` are implementation/fixture pins; the SDK rows are metadata-only. No host cell is `supported`, and `support/runtime-support.json` ships every cell array empty under `development_unverified`. |

### 0.2 re-dispositions — 2026-09-05

The 2026-09-16 source-only #499/#507 repair adds durable lifecycle events and a validated Codex
child-start correlation bridge. It does not change E-013 or any capability cell. Isolated source
fixtures are separate from the still-required fresh installed native run and independent semantic
review; see [Codex integration](runbooks/codex-integration.md#subagent-correlation-507).

The #754 follow-up teaches that bridge Codex 0.153.4 multi-agent v2: the delegated child's own
rollout header is an identity source, and `token_usage_record` plus 0.153.4's new fractional JSON
leaves stop counting as coverage gaps. It flips no capability cell and earns no exact rollout
profile — 0.153.4 stays on the structural compatibility profile — and the v2 evidence read from a
stopped isolated instance is observation, not certification. Whether 0.153.4 emits
`SubAgentActivity` with `multi_agent_v2=false`, whether its `SubagentStart` hook payload carries
`subagent_id`, and whether a delegated child thread ever runs the hook bridge all remain open; see
[Codex integration](runbooks/codex-integration.md#multi-agent-v2-01534-754).

- **E-013 — Narrowed (was "not applicable" for v0.1.0; that row stays above as history).** What
  ships in 0.2: hook observation ingress exists for all three first-party hosts. The Codex plugin
  renders `PreToolUse`/`PostToolUse`/`PermissionRequest` hooks
  (`src/finishup/adapters/integrations/codex_plugin.py`), the Claude Code marketplace plugin renders
  `SessionStart`, `PostToolUse`, `PostToolUseFailure`, `PermissionDenied`, `Stop`, and `SessionEnd`
  (`claude_code_integration.py`), and the Cursor IDE plugin renders
  `sessionStart|sessionEnd|afterMCPExecution|afterFileEdit|stop` (`cursor_integration.py`); every
  install goes through the host's explicit preview→confirm plugin ceremony. Consented accepted
  rows are stored in the task ledger under `ObservationSource`
  `claude_hook|codex_hook|codex_session_stream|cursor_hook` (bundle migration `0009`, issues
  #576/#586). `src/finishup/application/observation_materialize.py` materializes the `hook_observed`
  publication channel for every accepted hook envelope, and the `hook_observed` artifact-observation
  class with `harness_observed` authorship only for a gap-free `codex_hook` envelope; `claude_hook`
  and `cursor_hook` rows keep `published_only`/`service_authenticated` under that channel. So
  `hook_observed` is earnable in 0.2, from real observation evidence only. Capability cells:
  `CODEX_HARNESS_PROFILE` stays jointly empty (unprofiled/unadvertised);
  `claude-code-cli-local-project-2.1.241` declares a `SessionStart` trigger arm with
  `observation_events=()`; `cursor-ide-3.17.8` declares a `sessionStart` trigger arm plus those
  five observation events, and `cursor-cli-2026.07.09-a3815c0` is `None`. Still not claimed: no
  `supported` release cell exists — `support/runtime-support.json` ships every cell array empty
  (`session_event_cells: []`) under `development_unverified`; no installed-artifact run has frozen
  event, payload/privacy boundary, permitted action, coalescing/loop guard, gap codes, and failure
  behavior per arm as this gate requires; the Claude `2.1.251` `PostToolUse` capture proves a
  payload shape only; and unprofiled harnesses stay cooperative-only. Wider wording must first add
  that evidence and update this ledger in the same review.

### Explicit v0.2 or later deferrals

- Product-telemetry, crash-diagnostics-upload, and capability-testing transports. Those three
  channel rows stay explicit but unavailable/off: enablement is rejected with
  `channel_unavailable`, no dormant consent is created, and a later exact transport capability
  requires a fresh local-human transition. *(Amended 2026-09-05: `update_checks` left this list.
  It is the one owned non-LLM transport — an independently policy-gated, allowlisted PyPI request
  carrying only the package identity, never task or user content, and never auto-upgrading
  (`src/finishup/adapters/privacy/update_checks.py`, `src/finishup/application/package_update.py`;
  claim `privacy.v01_update_checks_only_non_llm_transport`).)*
- Live Git/filesystem artifact inspection during import review; v0.1 compares recorded evidence
  only.
- Chunked import/object formats above the exact 4 MiB source/object cap.
- Remote service exposure. *(Narrowed 2026-09-05: this bullet formerly also deferred Codex
  app-server integration and additional first-party harnesses. The exact digest-bound Codex
  app-server subscription evaluator ships (`src/finishup/adapters/providers/codex_app_server.py`,
  issue #480, E-007 status 2026-09-04), and Claude Code and Cursor ship as first-party harness
  adapters (`src/finishup/adapters/integrations/claude_code_integration.py`,
  `cursor_integration.py`; ADR-023, E-017) — none with a `supported` release cell. Only remote
  service exposure remains deferred here, alongside the multi-user hosting and remote-control
  bullet below.)*
  Additional harnesses are additive by construction under ADR-010: an adapter plus a
  `HarnessId` value, with no port, guidance, or registry change. Hooks land on
  `HarnessProfile.hooks_by_capability_profile`, whose exact values distinguish two arms.
  Observation hooks report what the harness saw and are the only arm that makes `hook_observed`
  earnable; for first-party Codex they are a **required v0.1 capability** once the exact cell is
  proven (ADR-010 amendment 2026-07-22), via local `ObservationPort` control methods rather than a
  seventh MCP tool. Trigger hooks fire on a harness lifecycle event — context compaction is the
  motivating case — and prompt the agent to re-ground by calling `status`; they earn no coverage,
  because the `status` result they cause discloses only what that call would already have returned
  under the ordinary provenance rules and the `agent_context` ceiling. An exact v0.1 capability
  cell may declare either or both arms after E-013 passes; unsupported cells remain `None`.
  Remote service exposure remains deferred. No adapter silently installs or configures hooks;
  every hook install goes through the host's explicit plugin ceremony.
- MCP prompts. v0.1 ships tools, resources, and the `instructions` string only.
- Launchd/systemd convenience installers, multi-user service hosting, remote control, and
  independent concurrent service writers; the single-user persistent local service and
  authenticated local IPC are v0.1 requirements.
- Standalone public `finishup doctor` CLI command and support-bundle schema. *(2026-09-05: the
  terminal interface's read-only `/doctor` report and `finishup service diagnostics` (one durable
  owner-only diagnostic record by correlation id) ship next to `version --json` and the startup
  gates; the standalone CLI command and bundle schema remain deferred without a version promise.)*
- Broad waiver scopes, noninteractive/model waivers, or waiver of local policy classes.
- Structural task/workflow status without keys; the locked service exposes only its bounded service
  lifecycle/reason status, while all six task operations fail closed when required keys are locked.
- Generic headless passphrase input remains deferred. v0.1 unattended readiness uses only an
  existing vault through a release-tested OS keyring; passphrase mode requires the confidential
  human ceremony. **Scoped exception (ADR-015/016, amended 2026-07-31):** vault initialization and
  provider credential set/rotate require action-bound OS user presence before foreground-console
  review. The current runtime fails closed because no production presence adapter is wired.
  Initialization uses a
  helper-generated, credential-store-verified secret; provider credentials are entered inside the
  confidential ceremony. `review_only` irreversible operations remain catalogued with
  `implemented=false` until durable review consumption exists at owning CLIs. This is not a
  standing `--yolo`, general headless vault API, or unlock path for an already-locked vault.
- A native vault broker/subprocess; v0.1 uses the in-service `SecretMemoryPort` boundary.
- Sigstore or other signing claims until verification is documented and tested.
- A combined rendered skill handbook; v0.1 ships the two separately owned reference documents.
- Global/user Codex skill installation scope; v0.1 mutates only one explicitly selected trusted
  project after preview and confirmation.
- In-place repair of a quarantined route; v0.1 recovery builds/verifies a new target and switches
  routes through the catalog state machine.

### FinishUP rebrand release gates (ADR-048) — 2026-10-14

The rename (#1055) is implemented with full backward compatibility; the steps code cannot take
are release gates tracked on #1056: registering `finishup.dev` and proving its mail; keeping
`yoetz.dev` (and `https://schemas.yoetz.dev/0.1/`) registered and serving permanently; renaming the
repository to `TheGaySupreme123/finishup` and never recreating one named `yoetz`; claiming the
`finishup` PyPI and npm names; Trusted Publishing for both `finishup` and the existing `yoetz`
PyPI project and npm package; a release-workflow dry run of the transitional jobs; a live
upgrade of a real 0.2.5 installation with each host's reconnect and disconnect; and confirming
that the README logo URL
(`https://raw.githubusercontent.com/TheGaySupreme123/finishup/main/docs/assets/finishup-logo.png`)
resolves before publishing, which needs the rename and the logo on `main`, because PyPI renders
that README, with that absolute URL, as the package description. Removing the
`yoetz` alias is a later-release decision gated on status reporting no legacy launcher bindings.
Schema `$id`s can move to a FinishUP host only with a future protocol namespace bump.

### Resolved founder and working decisions reflected across the tree

- **v0.1.0 public-alpha reconciliation (2026-08-20):** every empirical gate carries a
  dated disposition in the v0.1.0 disposition table, and none blocks the public-alpha tag;
  `docs/public-claims.json` is reconciled so `evidenced` means the claim has concrete
  checked-in test or fixture coverage and its non-live suites run in per-PR CI, while the
  claims whose own wording names missing capability or drill evidence
  (`recovery.machine_bound_vs_portable`, `support.structural_subject_state_capture`) stay
  `not_yet_evidenced` and are not asserted as release evidence.
- Ignored architecture/strategy files are private drafting inputs only; the committed ADRs,
  `docs/INTERFACES.md`, and the public code and tests are self-contained public authority.
- Public schema `$id` values are real immutable hosting routes below
  `https://schemas.yoetz.dev/0.1/`. The checked-in `schemas/` tree deploys byte-for-byte at that
  prefix, the local gate resolves the complete manifest with networking disabled, and the release
  gate publishes then re-fetches the same bytes. Hosted availability never becomes a runtime
  dependency.
- **F-001:** FinishUP uses the unmodified official Apache License 2.0 text and the exact SPDX expression
  `Apache-2.0`. v0.1 does not invent or require a project-wide copyright-holder notice; applicable
  ownership and repository history remain intact.
- **F-002:** The project adopts Contributor Covenant 3.0. T3 Code may inspire the clarity and
  contributor experience of repository documents, but it is not an authority for FinishUP runtime,
  protocol, privacy, or security architecture.
- **F-005:** The official npm Pyright package remains an exactly pinned contributor/CI tool only.
  Node/npm are not FinishUP runtime requirements. The formerly deferred `npx finishup` launcher is now
  built as its own reviewed distribution surface under ADR-012: a dependency-free delegation-only
  package at `support/npm-launcher/` pinned to the exact PyPI version. The separate publication
  decision was made for v0.1.0 on 2026-08-20 (issue #366); npm publication follows PyPI inside the
  protected tag workflow and the downloaded public tarball must match the approved bytes.
- **F-020 (ADR-012, 2026-07-21):** Founder-authorized first-run setup wizard. `finishup setup
  run|status` and `finishup integrate <harness> mcp status|preview|install` automate Codex discovery
  and the runbook's check-then-add MCP registration behind preview→confirm→execute; bare `finishup`
  on an interactive terminal with no completion marker launches the wizard once (every non-TTY
  bare invocation still prints help). Foreign same-name MCP entries are preserved, never
  replaced; privacy setup and provider credentials remain their existing trusted ceremonies, which
  the wizard points to but never automates.
- **F-006 (amended 2026-08-20):** Private vulnerability reporting uses GitHub's private
  vulnerability-reporting surface, with the single maintained private mailbox `support@yoetz.dev`
  as fallback; private conduct reports use the same mailbox with a "Code of conduct" subject;
  ordinary support and bug reports use repository issues. The original decision named distinct
  `security@`/`conduct@` routes; the maintainer consolidated to one monitored mailbox for the
  solo-maintained v0.1 era — the routes may split again without a claim change. The v0.1.0 alpha
  makes no mailbox delivery-time, response-time, availability, or monitored-SLA claim.
  Amended 2026-10-14 (ADR-048, #1055): the rename moves this mailbox to `support@finishup.dev`
  (conduct issue-template route `conduct@finishup.dev`), and the public documents already name it.
  Proving that address receives and is monitored, and re-running the E-012 drill against it, is a
  release gate on #1056; `yoetz.dev` and its mail stay alive.
- The persistent per-user local service is in v0.1 and is the sole owner of keys, decrypted state,
  durable writers, privacy policy enforcement, and outbound dispatch. CLI, MCP, and UI are clients.
- **F-007:** v0.1 keeps vault keys, provider-credential handles, and decrypted state inside the
  trusted local FinishUP service behind swappable `VaultPort`/`SecretMemoryPort` boundaries. Verified
  page-lock/no-core protections and best-effort overwrite are used where available; a native vault
  broker is deferred. This is a FinishUP-specific decision, not an inheritance from T3 Code.
- **F-008:** Unattended readiness is required and is provided in v0.1 by automatic unlock of an
  existing vault through an approved, release-tested OS keyring. If that path is unavailable or
  locked, the service remains alive in explicit `locked`; passphrase vaults require the confidential
  human ceremony. Arguments, environment, config, stdin, files, MCP, transcripts, and LLM context
  are not passphrase-ingress channels.
- **F-009:** v0.1 permits only reviewed bundled provider adapters from a closed registry as trusted
  in-process service code. They receive an approved case and one-attempt transport capability, not
  ambient repositories or state. This is capability minimization, not an OS sandbox.
- **F-010:** Pristine automatic keyring initialization requires both verified keyring create/load
  support and an action-bound `UserPresencePort` for the exact release cell. Otherwise FinishUP writes
  no immutable keyring-mode state and offers explicit passphrase initialization. Existing keyring
  vaults may unlock for permitted local work, but durable widening and credential mutation remain
  fenced without strong presence. `HumanAuthorityCapability.source=unavailable` is not a second
  authorization gate for an already reauthenticated exact local-model policy row; that row remains
  independently fenced by classifier, exact profile, generation, and `consume_local` checks.
- **F-011:** `confirm_every_request` uses a foreground exact prepared-case preview and one explicit
  decision for one physical attempt inside existing durable policy. Every retry needs a new decision;
  durable widening and credential mutation still require strong action-bound reauthentication.
- **F-012:** Candidate/user/repository/config/transcript credentials remain non-overridable
  never-send data. A separately provisioned vault credential may be consumed only once as
  authentication metadata for the exact profile-bound HTTPS endpoint selected by the reviewed
  registry, using platform CA trust and hostname validation, and never enters model content,
  previews, receipts, logs, config, environment, transcripts, or reusable SDK state. v0.1 does not
  claim certificate or SPKI pinning.
- **F-013:** FinishUP may connect only to an exact approved owner-only AF_UNIX local-model endpoint and
  does not launch/download the model or perform DNS/IP networking. The separate runtime receives
  plaintext and is therefore an explicitly trusted disclosure sink unless its exact support cell
  proves enforceable network isolation; FinishUP does not claim away another process's authority.
- **F-014:** Keep the external-LLM-denied installation seed, but make `assisted` the upstream CLI's
  recommended review-context recipe after an explicit technical-user setup decision. It uses a
  standing exact-repository policy beneath a machine installation ceiling, public-structural plus
  ordinary-user-content classes, rich goal/
  obligation/claim/timeline/local-check-basis context, bounded problem-local excerpts already
  recorded in the frozen case, and an exact endpoint whose current data-use record states training
  `prohibited`, retention `none|bounded`, and provider human access `prohibited|restricted`. The
  recipe's editable current-evidence guard is on. Known-broad, unknown, or stale posture removes the
  recommendation; an explicit custom loosening may turn the guard off without retaining that claim. It
  does not prompt per ordinary check/retry. Users may choose stricter, broader, custom, or forked
  behavior; never-send and scope remain non-overridable for upstream-conforming builds. Repository
  identity is the installation-keyed commitment of the trusted session's canonical Git common root,
  never public `workspace_ref`; linked worktrees share, independent clones do not. Upgrade migration
  preserves machine bytes and may consume only bounded pre-upgrade route or one first-repository
  carry-forward entitlement without reapproval. New repositories remain Private.
- **F-015:** Harness integration is a port and Codex is its first adapter (ADR-010). Agent guidance
  is owned once, harness-neutrally, under `guidance/` with exactly one packaged copy;
  `IntegrationsPort` is parameterized by a closed `HarnessId` (exactly `codex|cursor`) plus a
  reviewed `HarnessProfile`. At the port layer, adding a first-party harness is one `HarnessId`
  value plus one adapter and requires no new port or guidance fork. The frozen v0.1 service methods
  `integration_preview|integration_execute` remain Codex-only; Cursor lifecycle uses the sibling
  `PluginArtifactPort` surface instead. `HarnessProfile.hooks_by_capability_profile` binds every
  exact profile ID to either
  `None` or, after E-013 passes, a descriptor that may declare a trigger arm and/or a nonempty
  closed `observation_events` set. For first-party Codex, observation is a required v0.1
  capability once capability-proven: it earns `hook_observed` only from real observation evidence,
  through local `ObservationPort` control (not a seventh MCP tool). Trigger-only cells remain valid
  recovery ergonomics without raising coverage. Unproven cells stay `None` / empty observation
  arms and keep cooperative coverage honest.
- **F-021 (2026-07-22):** First-party Codex observation is in protocol `0.1` (not deferred to
  v0.2). Dual sources are hooks (primary, low-latency) and selective session-stream reconciliation.
  Shared types are `ObservationSource`, `ObservationEnvelope`, `ObservationCursor`,
  `ObservationStatus`, and `AdviceSnapshot`. Observation consent is one workspace-level
  confirmation via a private workspace commitment, separate from egress consent; revocation stops
  new ingestion and retains already-kept evidence. That confirmation is the existing workspace observation
  consent, not the first-class `prj_` project object ratified in ADR-027. `AdviceSnapshot`
  surfaces via nonblocking hooks and ordinary
  `status`. Batch `ImporterPort` JSONL import stays a separate support surface. Existing v0.1 data
  remains readable; migrations may add only observation consent/cursor/dedup/advice state.
- **F-016:** Any MCP host is supported with no integration. Initialize `instructions` carry
  `guidance/agent-instructions.md` as the only inlined guidance document, followed by the generated
  route-profile suffix; its catalog paragraph names the other four URIs and the `resources/read` →
  `read_guidance` → installed-copy chain that reaches them.
  The string must still carry every rule whose absence would cause harm, because it is the only
  tier guaranteed to arrive — but naming a path served by an equally unconditional tool satisfies
  that, and the string is bounded because at least one host charges it once per advertised tool
  (issue #300). The five guidance documents remain exposed as read-only
  `finishup://guidance/<name>` resources. The templates keep all six operations and all nine ordinary
  publication families authorable when a host drops schema metadata, without changing catalog
  admission authority. MCP declares
  tools and resources only. `mcp/descriptors.py` owns every agent-read string, loads it from verified
  packaged resources with no runtime composition or fallback, and is bound by the guidance wording
  lint. An unprofiled host therefore earns `cooperative_mcp`/`self_asserted`/`published_only` — the
  weakest honest coverage — rather than a warned-about degraded mode. When a host returns an empty
  `resources/read` body, MCP also registers `read_guidance` so the same document can arrive as
  tool text (issue #203).
- **F-017:** `ClientInfoModel.kind` gains the transport-neutral `cooperative_agent` value so every
  harness has exactly one honest identity and no unprofiled host must misreport itself as
  `codex_cli` or `test_client`. `kind` is provenance only: assurance derives from the integration
  channel, so no `kind` value participates in `Coverage`, and recognising a harness first-party stays
  additive.
- **F-018:** Local client disclosure splits by audience. Ordinary human-readable rendering to an
  attached controlling terminal resolves to a new `local_human_view` sink and is not gated by the
  agent ceiling: a local human reading a vault they unlocked is not a third-party disclosure, and
  gating their own terminal protects nobody. `--json`, non-TTY or redirected streams, and every
  `mcp_bridge` client resolve to `agent_context`; the client never selects its own sink. Terminal
  emulation by a same-UID process is the stated threat-model limit already bounding the unlock TTY
  contract. *Superseded in part by ADR-009 round 3 (2026-10-14):* an agent's pseudo-terminal passes
  every terminal test, so no presentation fact selects `local_human_view` any more; the owner's
  full receipt is a reauthenticated one-use `owner_receipt_view` grant.
- **F-019:** `agent_context` becomes provenance-conditional on a computed, closed
  `DisclosureProvenance`. Material the requesting writer authored at the frozen frontier, and kernel
  prose derived solely from it, project without a category grant, because that content already sits
  in the host's context and withholding it protects nothing while breaking the
  `check → respond → recheck` loop on the default install. Other-writer material, imports, and
  provider-derived AI-powered review prose still require the explicit grant. Provenance is computed from the
  ledger and never asserted; ambiguity denies; `sensitive_confidential` and every never-send kind
  stay absolute under every provenance. This amends the ADR-009 boundary and is recorded there.
- Every outbound provider request follows classification, policy intersection, local
  minimization/redaction/secret scanning, optional trusted-human preview of the exact prepared
  case, gateway revalidation, and binding to one provider/model/endpoint profile. Network channels
  remain independently consented.
- `semantic_required` requires AI-powered review success for a complete verdict, not for returning
  useful local truth: every post-local-check provider absence, policy denial, refusal, timeout, invalid,
  stale, late, or exhausted outcome returns the local findings with verdict
  `incomplete_check`, explicit reason, and no AI-powered findings.
- ~~Every future source, resource, fixture, test, script, workflow, and public document has one
  owning natural-language file spec before implementation begins.~~ **Superseded 2026-07-25:** the
  spec-first tree completed its purpose — all 626 declared files were built — and was retired rather
  than maintained as a second copy of a shipped system. The authority chain is now ADR →
  `docs/INTERFACES.md` → code and tests. The final tree is recoverable at tag `specs-tree-final`.
- The public workflow has exactly six operations; import/review, backup/restore/migrate,
  integration, version, and MCP serving are bounded support surfaces rather than extra MCP tools.
- Candidate findings are ID-free pure-kernel values; the application allocates and durably pins
  finding IDs before publication.
- Coverage unordered dimensions are sorted unique sets; AI-powered review terminal states distinguish
  `late` from dependency-`stale` and never use an ambiguous `completed` state.
- Receipts summarize a frozen subject frontier, receive IDs/time/version inputs explicitly, and
  use exactly three bounded conclusions.
- v0.1 waiver scope is one finding, authorized only by an explicitly confirmed interactive local
  human flow.
- Import source identity uses a keyed commitment plus exact Codex capability profile and mapping
  version; the ordinary source digest remains inside encrypted audit material.
- The ordinary v0.1 import request requires stderr absent with exact false/zero constants; it
  accepts neither raw stderr nor a caller-created stderr commitment.
- Version manifests serialize optional components as `{status: "absent"}` and expose a bounded
  resource summary by default; the full resource list requires the explicit resources option.
- Alpha Codex support is an explicit tested-version set, never an inferred continuous range;
  `release-probe` is CI/environment/CLI-only and invalid in user config.
- `common/operation-result-1.0.0.schema.json` is a separately public language-neutral schema, and
  the public-claim map is committed as canonical JSON.
- v0.1 uses exactly the registered `ObjectKind` vocabulary, a one-level two-hex object shard, and a
  24-hour orphan safety window.
- Every mutating maintenance operation requires an exact digest-bound interactive confirmation in
  v0.1; no destination history silently waives it.
