# ADR-010 — Harness integration is a port; Codex is the first adapter

**Status:** Working decision for spec drafting (2026-07-16; trigger-profile amendment 2026-07-17;
first-party Codex observation amendment 2026-07-22). Ratification requires the packaging
byte-parity run plus a capability run proving an unprofiled MCP host completes the workflow from an
installed artifact, and — for first-party Codex cells that advertise observation — installed-artifact
evidence that observation ingest earns `hook_observed` only from real observation evidence.
**Implemented by:** `guidance/`, `src/yoetz/ports/integrations.py`,
`src/yoetz/ports/observation.py`, `src/yoetz/domain/observation.py`,
`src/yoetz/application/integrations.py`,
`src/yoetz/adapters/integrations/codex_skill.py`, `src/yoetz/mcp/descriptors.py`,
`src/yoetz/mcp/resources.py`, `src/yoetz/mcp/server.py`,
`schemas/common/client-info-1.0.0.schema.json`.
**Relates to:** ADR-002 (canonical protocol), ADR-005 (Codex capability identity), ADR-007
(packaging/release), ADR-009 (egress/privacy).

## Context

### Required-startup amendment (issue #692, 2026-09-21)

Native Claude Code and Cursor may opt into a generated tool gate through the owner-reviewed plugin
lifecycle. Default optional observation remains separate. A static startup cue is independent of
observation consent/storage. Readiness combines scope-bound accepted host workflow results with the
current repository-bound service projection; mapping alone cannot admit work. Pending writes retain
their identities and completion still needs the ordinary receipt workflow. The gate never approves
Claude tools and asks for Cursor MCP admission, granting no privacy, credential or disclosure
authority (ADR-018). New prompts and resumed scopes require fresh effective plans. Executable and
host timeout failures bound enforcement. See [required startup](../runbooks/required-startup.md)
for controls and native acceptance limits. Maintainer acknowledgement is recorded on #692.

Yoetz is intended to work with any agent through MCP, with Codex as the first harness targeted by a
first-party integration. Codex remains untested rather than supported until an exact capability
cell satisfies E-002 and E-013. The drafted v0.1 tree did not express that split, and drifted toward
Codex being the only harness that could work well:

1. `IntegrationsPort` named its adapter in its own method set — `preview_codex_skill`,
   `install_codex_skill`, `status_codex_skill`, `remove_codex_skill` — with `CodexSkillSource` and
   `CodexSkill*Command` types. Every other port in the tree names a capability (`LedgerPort`,
   `ObjectStorePort`, `OutboundGatewayPort`) with adapters underneath. Adding a harness meant
   editing the shared registry, so a fork could not add one without touching the core.
2. All agent guidance — the ten-step workflow, the publication policy, the coverage rules — lived
   under `skills/codex/yoetz/`, physically inside the Codex-specific tree, in both the spec tree and
   the packaged resources. None of that content was Codex-specific. A second harness would have had
   to duplicate it and drift, or reach into another harness's directory.
3. `ClientInfoModel.kind` was the closed set `codex_cli|yoetz_cli|test_client|importer`. An
   arbitrary MCP host had no honest value to send, in a product whose thesis is honest provenance.
4. The MCP surface exposed six tools and nothing else: no `instructions`, no resources, and no owner
   for the tool description text. A non-Codex host therefore received the operations with none of
   the rules — including the forbidden-content rules, which are privacy-relevant, and the
   coverage-wording rules, which are the honesty product itself.

The through-line is that "Codex is first" had been encoded as "Codex is the only one that works."

## Decisions

1. **The guidance core is owned once, harness-neutrally, under `guidance/`.** It owns
   `agent-instructions.md`, `workflow.md`, `publication-policy.md`, `coverage-and-receipts.md`, and
   `request-templates.md`,
   packaged byte-identically under `src/yoetz/resources/guidance/`. Exactly one packaged copy exists
   regardless of how many harnesses ship, which makes drift structurally impossible rather than
   merely tested. A harness adapter may choose layout, filename, and header; it may not vary a byte.

2. **`IntegrationsPort` is harness-parameterized.** Methods are `preview_skill`, `install_skill`,
   `status_skill`, and `remove_skill`, each taking an exact `HarnessId` (closed; membership is
   exactly `codex|cursor`) plus a `HarnessProfile` carrying `skill_root`, `frontmatter_profile`,
   `capability_profile_ids`, `supported_versions`, and `hooks`. Adding a first-party harness is one
   `HarnessId` value plus one adapter under `adapters/integrations/`; it changes no method, no shared
   type, and no guidance. This is what makes the fork path real rather than aspirational, and it
   makes the shared registry smaller, not larger.

3. **Hook support is exact-profile capability data, not a release-wide boolean.**
   `HarnessProfile.hooks_by_capability_profile` maps each advertised capability-profile ID to
   `HarnessHookProfile | None`. A v0.1 cell may declare a trigger arm, an observation arm, both, or
   neither after the corresponding installed-artifact evidence passes; an unproven cell remains
   `None`. Observation is a **required v0.1 capability for first-party Codex** once the exact cell
   is capability-proven: it is the only integration arm that earns `hook_observed`, and only when
   real observation evidence exists. Trigger-only cells remain valid ergonomics and still earn no
   coverage. Unprofiled or unsupported cells keep both arms absent. Support is never inferred
   across neighboring host versions.

4. **Three delivery tiers, with tier 0 self-sufficient.** Tier 0 is the MCP initialize
   `instructions` string, and it carries `guidance/agent-instructions.md` verbatim — the safety
   floor, including the catalog paragraph that names every other document and the
   `resources/read` → `read_guidance` → installed-copy recovery chain. That string reaches every
   host unconditionally. Tier 1 exposes the five documents as `yoetz://guidance/<name>` MCP
   resources for hosts that return the resource text. Tier 2 installs them on disk for a first-party
   harness. Because tier 0 is the only tier guaranteed to arrive, it must carry every rule whose
   absence would cause harm, rather than summarizing and deferring — but "carry the rule" is
   satisfied by naming a reachable path, and tier 0 is also charged per advertised tool by at
   least one host, so it is bounded (see the 2026-08-17 amendment). `workflow.md`,
   `coverage-and-receipts.md`, `publication-policy.md`, and `request-templates.md` are
   resource/disk/`read_guidance`-only.

5. **MCP declares tools and resources only.** No prompts, sampling, roots, completions, or resource
   subscribe/listChanged. Resources are static reviewed product documents: they reach no service,
   carry no user content, and are therefore served while the service is absent, locked, or draining —
   exactly when an agent most needs to know Yoetz is unavailable rather than invent a session. A
   resource URI is a key into a frozen table, never a path.

6. **`mcp/descriptors.py` owns every agent-read string** — the six workflow tool names, the
   read-only `read_guidance` and `closure_prepare` support tools, descriptions, and annotations,
   plus `instructions` — loaded from verified packaged resources, never composed at runtime, and
   bound by the same honesty lint as the guidance ("verified", "proved", "authenticated", "complete"
   rejected unless the sentence states the exact sufficient coverage). `status`, `read_guidance`,
   and `closure_prepare` carry `readOnlyHint=true`;
   `receipt` carries `readOnlyHint=false` because it stages a receipt object and appends a
   `receipt_recorded` event. Every tool carries an explicit `idempotentHint=true`. Nothing carries
   `destructiveHint`, because no Yoetz operation deletes recorded evidence. `read_guidance` is
   guidance transport only: it is not a ledger operation and does not use the service client.
   Observation does **not** add a workflow tool: live observation is local CLI/service control
   through `ObservationPort` (ingest/status/pause/resume/revoke), and advice surfaces through
   existing nonblocking hooks plus ordinary `status` / findings / coverage machinery.

7. **`ClientInfoModel.kind` gains `cooperative_agent`**, the transport-neutral honest identity for
   any harness without a first-party integration, valid with `cooperative_mcp` or `local_cli`.
   `codex_cli` remains a capability claim bound to an installed Codex profile and is not a generic
   agent token. Assurance derives from the integration channel, so no `kind` value participates in
   coverage; recognising a harness first-party is additive and is never required for it to work.

8. **`HarnessHookProfile` distinguishes trigger hooks from observation hooks, and only the
   observation arm touches coverage.** A trigger hook fires on a harness lifecycle event — context
   compaction is the motivating case — and prompts the agent to re-ground by calling `status`. It
   earns no coverage: it observes nothing, and the `status` result it causes discloses only what
   `status` would already have returned under the ordinary provenance rules and the `agent_context`
   ceiling. It therefore touches no coverage lattice value, strengthens no claim, and changes no
   honesty wording. An observation hook reports what the harness saw and is the only arm that earns
   `hook_observed`, and only when real observation evidence exists (never from a trigger alone, a
   consent marker, or an empty/degraded observation status).

   For first-party Codex in protocol `0.1`, observation is a required integration capability once
   the exact support cell is proven. Dual sources feed `ObservationPort`: **hooks are primary**
   (low-latency structural envelopes) and **selective session-stream reconciliation** fills gaps
   without replacing the hook path. Future unrecognized Codex events are accepted only as a stable
   envelope plus allowlisted structural facts; unknown semantics become opaque gaps and never infer
   success. Batch `ImporterPort` JSONL import remains a separate support surface that may reuse
   mapping vocabulary but is not live observation. App-server integration and additional harnesses
   remain deferred.

   Whether a specific harness exposes usable trigger or observation points is capability evidence
   rather than a spec choice. E-013 freezes exact trigger and observation event, payload/privacy,
   coalescing/loop, gap, and failure behavior from an installed-artifact run before a cell advertises
   either arm. Unproven cells remain `None`.

   **Exact-worktree Codex dogfood parity amendment (2026-08-29, issue #464).** A retained Codex
   dogfood cell may not start substantive model work until the exact disposable Git root, candidate
   package, launcher, executable/home, route, plugin source/inventory/cache/activation, and that
   root's independent observation consent all pass the executable parity gate in
   `scripts/check_codex_dogfood_parity.py`. Primary-checkout consent and normal-target activation
   never transfer. `installed_not_activated` is a failed preflight with the exact-target
   recommendation recovery path; missing consent is blocked with the trusted local grant path.
   After launch, skill delivery, a correlated model-issued MCP call, advertised hook events,
   mapping, accepted envelopes, drain, advertised session-stream reconciliation, AI-powered review
   provenance, receipt, influence scope, rollback, and unchanged normal state remain separate
   cells. Unsupported and not-run states stay explicit and cannot be aggregated into green. Any
   performed or failed cell must be placed in scope; an out-of-scope pass, failure, or block makes
   the report invalid instead of silently disappearing from aggregation.

   The current Codex `0.144.5` capability candidate exposes `PreToolUse`, `PermissionRequest`,
   `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `UserPromptSubmit`, `SubagentStart`,
   `SubagentStop`, and `Stop`. This inventory nominates candidates but does not freeze support:
   E-013 still requires installed-artifact payload, privacy, and behavior evidence before use.

## Consequences

### Cursor local amendment (2026-08-22, issue #153)

`HarnessId` adds exactly `cursor`; `cursor_integration.py` is its one adapter. The current local
implementation profiles are Cursor IDE `3.17.8` and Cursor Agent CLI
`2026.07.09-a3815c0`. Local TypeScript SDK `1.0.23` and Python SDK `1.0.24` over bridge protocol
`sdk.v1` were originally nominated as neighboring cells, but issue #412 defers them for planned
`0.2`: their package/bridge/precedence fixtures are metadata-only experimental scaffolding and do
not enter `capability_profile_ids`, `supported_versions`, hook maps, or a public support claim. A
new design-gated issue plus operational SDK execution, bridge, negative-control, model-call, and
exact evidence is required before promotion. The Python package has no `1.0.23` release. Exact
artifact digests, OS, architecture, activation source, configuration scope, format, and MCP
owner/source remain evidence per IDE/CLI cell. No cell inherits another cell's proof, and Cursor
Cloud remains outside this amendment.

The portable projection reuses the canonical Agent Plugins skill bytes. The native projection is
generated independently at `.cursor-plugin/plugin.json`; it may add only proven Cursor components.
It is not derived from the portable JSON and never co-locates both manifests. Local plugin
activation uses Cursor's documented explicit user development root or CLI `--plugin-dir`; a
filesystem copy is not discovery, activation, model delivery, or receipt proof.

Cursor hook ingress is a separate `cursor_hook` observation source. The exact advertised event set
is `sessionStart`, `sessionEnd`, `afterMCPExecution`, `afterFileEdit`, and `stop`. Hooks are
fail-open and advisory. Before storage, the adapter discards prompts, thoughts/reasoning, response
text, paths, file contents/edits, tool arguments/results, transcripts, command output, and email.
`afterAgentThought` is deliberately not registered. A declaration or `sessionStart` earns no
observation coverage; only consented accepted `cursor_hook` envelopes can do so.

**Amendment (2026-08-28, issue #426): installed Cursor plugin status binds live MCP runtime
process evidence when a bounded scan is available.** File `mcp.json` and marker route are not the process
that answers model calls. After plugin replace, Cursor can keep a shared `mcp-process` helper
whose child still has `yoetz mcp serve --semantic off` while the extension host already launched
`--host cursor`. Status therefore classifies exact known serve suffixes and Cursor-helper parents
into `mcp.runtime` (`unobserved|matched|full_restart_required`) without retaining argv. Only an exact
`yoetz` launcher token followed by a known serve suffix is classified; an unavailable or truncated
scan remains `unobserved`. A
policy-installed tree with a contradictory helper child reports `full_restart_required` and must
not be described as activated. Reload Window is not sufficient; a full application quit is the
documented activation instruction. Agent guidance treats `route_semantic_ceiling` against
installed `policy` as that mismatch, not an owner privacy decision, and does not mint a fresh
AI-powered check against the stale process. A live installed strict route remains the ordinary
terminal ceiling. Recovery never authorizes egress or changes privacy settings.

**Amendment (2026-08-29, issue #468): the plugin-owned Cursor `mcp.json` binds the exact launcher
the hooks bind, and status verifies executable, package identity, control schema, and route
separately.** A bare `command: "yoetz"` let Cursor's sanitized desktop PATH resolve an older ambient
runtime (control schema 2.1.0) behind a marker-valid then-current plugin (2.3.0); the model's
`start` then reached an incompatible bridge and no task, evidence, or receipt could exist. Cursor's
MCP reference admits a full path in `command`, so the native entry is now `launcher[0]` plus
`[*launcher[1:], "mcp", "serve", "--host", "cursor", …]` from the same `/3` marker launcher the
hooks use; the entry is a managed member, so carrier bytes bind it. Route recognition accepts a bare
`yoetz` or a known launcher (this artifact's or the installed marker's) with the exact serve
arguments. `CursorPluginStatus.launcher` reports executable state (`matched|drifted|missing|
unbound|unobserved`), the installed entry's `mcp_binding` (`exact_launcher|ambient_path|…`), and a
bounded identity probed by running the installed launcher's read-only `version --json`; the live
runtime observation compares helper-child argv prefixes with the installed launcher and reports
`executable_activation`, forcing `full_restart_required` on a mismatch. Carrier-byte equality is
never runtime proof; package, discovery, runtime, model-use, observation, AI-powered review, and
receipt facets stay separate. A tree rendered before this amendment stays marker-valid and reports
`modified` with `mcp_binding: ambient_path` until one exact previewed replace. The portable
Agent-Plugins carrier is byte-identical by design and keeps the bare route; it is not a native
activation claim.

The append-only local-control schema `2.1.0` admits `cursor_hook`, a keyed HMAC
`changed_paths_digest`, and the Cursor source-coverage row while retaining `2.0.0` byte-for-byte.
Cursor's documented `afterMCPExecution` result is content and is discarded; because the host does
not publish a validated `success` or `result_status` field for that event, ingress never fabricates
either value.

**Amendment (2026-09-05, issue #596): native Cursor MCP binds the service handshake to the active
MCP session's roots.** A native Cursor helper may start from the user's home directory, so its
process CWD cannot select repository privacy authority. The `--host cursor` bridge asks the MCP
client for `roots/list` on the first workflow call, decodes only local `file:` roots, bounds their
URI/path input, and canonicalizes each through the shared safe workspace resolver. It accepts one
canonical repository (equivalent roots in that repository are aliases); missing, unsupported,
remote, malformed, unsafe, oversized, or distinct-repository roots fail closed with the existing
`SESSION_CONFLICT` / `repository_identity_required` boundary before connecting to the service.
The locator is retained only in the bridge's private client slot, revalidated before each workflow
call, and is never derived from public `workspace_ref`, model arguments, or transcript content. The
reviewed Cursor 3.19.7 host bundle advertises `roots.listChanged: false`, so revalidation runs on
every workflow call even when no change notification is available. A changed or unusable roots/list
result, or a roots-list-changed notification, retires the slot and
its service client; the host must create a fresh MCP session to bind again, preventing one process
from crossing repository authorities. Generic MCP bridges keep their existing process
CWD behavior. The server still advertises only tools/resources: roots are a standard client-to-
server handshake input, not a Yoetz tool or new server capability.

**Amendment (2026-09-07, issue #616): Cursor root compatibility and explicit project selection.**
The reviewed Cursor implementation emits absolute local filesystem paths in `roots/list.uri`,
where the MCP SDK expects file URIs, and its shared MCP process can include roots from other open
projects. The Cursor adapter accepts a strictly absolute local path as that host's compatibility
shape, alongside local file URIs; every root still passes the same bounded safe canonicalization.
Other URI schemes, malformed paths, unsafe roots, and invalid response shapes remain refusals.

An owned project MCP registration renders `--project-root ${workspaceFolder}`. This is a startup
selector, validated against the exact project registration, launcher, route, and directory/config
identity. It selects one canonical repository from the active client's validated root inventory; the
selected repository must be present in that inventory. It cannot supply authority when the client
has no usable roots. Without a validated selector, the one-canonical-repository rule still applies.
Empty or unsupported responses, request failure or timeout, mismatches, and changed registrations
fail before the service handshake. Registration and selected-root identity are revalidated before
each workflow call, and a change retires the bridge's client slot. Public workflow fields, hook
payloads, environment guesses, and process CWD remain outside this decision. This adds no privacy
grant or AI-powered review admission: those checks retain their independent scope.

**Amendment (ADR-012, 2026-07-21):** MCP server registration is added as a *sibling* port,
`HarnessMcpPort` (`ports/harness_mcp.py`), with its own Codex adapters
(`codex_discovery.py`, `codex_mcp.py`). It deliberately does not extend `IntegrationsPort`:
registration is global, file-free, and marker-free, so reusing the skill-install types would
misuse fields designed for on-disk trusted-project content. The guarantee below is unchanged —
adding a harness is still one `HarnessId` value plus adapters, with no shared-type edits.

**Amendment (2026-08-14, issue #203):** Initialize `instructions` still begin with
`guidance/agent-instructions.md` verbatim. They then append `workflow.md` and
`coverage-and-receipts.md` so those Step 0 documents arrive on the transport-independent channel
when a host yields an empty `resources/read`. MCP resources remain the on-demand copies for hosts
that return the text; first-party disk copies remain the empty-read recovery path. This does not
add a seventh tool. *(Superseded by the 2026-08-17 amendment below; the seventh tool it declined
to add was added days later by `read_guidance`, which made the append unnecessary.)*

**Amendment (2026-08-17, issue #300): tier 0 is bounded, and the inlined set is one document.**
`INITIALIZE_GUIDANCE_URIS` is back to `agent-instructions.md` alone.

The `instructions` string is sent once, but a host may render it anywhere. Codex copies it verbatim
into the `description` of every advertised tool, so tier 0 is charged once per tool on every turn
of every session — seven copies today. Under the 2026-08-14 append that was 41 KB × 7 ≈ 288 KB of
advertised surface, six-sevenths of it duplicate. A dogfood session found it as a truncation
warning, not a test.

Two things changed since that append. `read_guidance` (a plain `tools/call`, immune to the empty
`resources/read` that motivated #203) now serves every guidance document, and it is advertised in
`tools/list` — the same unconditional channel as `instructions`, so the recovery path is itself
tier 0. And `agent-instructions.md` carries the catalog paragraph naming all five URIs and the
`resources/read` → `read_guidance` → `references/<name>.md` chain. A document that is named by a
tier-0 string and fetchable by a tier-0 tool is reachable without being inlined; Decision 4's
"carry every rule whose absence would cause harm" is met by the safety floor plus that path, not by
concatenation.

The reason this reversal is safe where the original inlining was needed is the tool, not optimism
about hosts — so the packaged `SKILL.md` no longer claims the two documents are already in context.
That claim, left stale, would be worse than the #203 bug it patched: it licenses skipping a fetch
the agent has not made.

Tier 0 is now bounded rather than merely trimmed. `SERVER_INSTRUCTIONS_BUDGET` caps the instructions
block per route profile, and `ADVERTISED_SURFACE_BUDGET` caps instructions-charged-per-tool plus
every description plus every advertised input schema. Both are asserted in
`tests/conformance/surfaces/test_mcp_contract_matrix.py`, beside the per-schema budgets that have
bounded the adjacent surface since #128. Per-item budgets cannot catch this class of growth: every
item can sit inside its own bound while the total doubles. Anyone inlining a document here again
will fail CI rather than a live session.

**Amendment (2026-10-03, issue #951): same-session specification recovery.** MCP advertises
`plan_published/1.1.0` and `plan_revised/1.1.0`, including `task_statement`, so a caller can supply
missing review input without superseding the session and writer that own its parked check. The
older plan variants remain available and reject that field. These two variants add two branches,
two payload definitions, and 3,000 bytes to the advertised schema. The measured publication schema
is 51,432 bytes and the strict generic-host aggregate is 252,168 bytes. Their reviewed ceilings are
52,000 and 253,000 bytes respectively; the compact native-host instruction ceilings are unchanged.

**Amendment (2026-09-30, issue #918; also records #789): tier 0 is host-profiled.** The bridge's
declared `--host` selects the tier-0 body. `generic` keeps `agent-instructions.md` verbatim.
`claude` receives a compact body sized for Claude Code's observed 2,048-character cap (#789).
`codex` and `cursor` receive one host-neutral compact body with a 2,048-byte cap, because Codex
code mode charges tier 0 once per advertised tool and the full document cost 19.8 KB per copy.
Each compact body still carries the rules whose absence would cause harm before the first read:
when to call `start`, never to claim Yoetz is active before it returns, never to fabricate state,
the consent, disclosure and coverage-wording boundaries, and all five URIs with `read_guidance`
and an instruction to read `agent-instructions.md` before the first `start`. That is the same
"name a reachable path" rule as the 2026-08-17 amendment, applied to the safety floor itself. The
route tail and destination disclosure are composed identically for every body. Separately, on
`codex` only, a `read_guidance` result's text `content` points at `structuredContent.text`
instead of repeating the document; tier 1 and tier 2 bytes and the output schema are unchanged.

**Amendment (2026-10-03, issue #950; residual #918): bounded guidance delivery.** The additive
`read_guidance` 1.1.0 request/result schemas retain URI-only full-document responses up to 64 KiB
and automatically select page zero for larger documents. The document/offset bound is 1 MiB;
individual response-body bounds remain unchanged. The UTF-8-safe page route binds a document URI,
source-byte revision/digest, offsets, byte counts,
page count, completion, and an exact continuation. Codex keeps its bounded pointer and reads the
page body from `structuredContent`; generic, Claude Code, and Cursor page text carries explicit
begin/end markers. A final `complete` flag records service emission only. The supported consumer
assembler rejects clipped markers, missing or duplicate pages, stale identity, offset/length
mismatches, and a final digest mismatch before exposing guidance. The frozen 1.0.0 schemas remain
available for compatibility, and generated resource/skill mirrors continue to come from the
resource ripple.

**Amendment (ADR-023, 2026-08-21, issue #149): tier 2 gains a portable carrier; artifact and
activation are sibling ports.** Tier 2 on-disk delivery may now be carried either by a host-native
projection (the existing Codex layout) or by a portable Agent Plugins 1.0.0 artifact, both
generated from the neutral `PortablePluginPlan` — never from each other. The carrier changes reach,
not authority: tiers 0 and 1 are byte-for-byte unchanged, guidance stays owned once under
`guidance/` with no byte variation per ADR-010 decision 1, and a host consuming the portable format
still earns exactly the coverage its evidence cell proves. Following the `HarnessMcpPort`
precedent above, `PluginArtifactPort` (preview/install/status/remove of a rendered artifact) and
`HostActivationPort` (discovery/activation observation and authorized preview/apply/remove) are sibling
ports, never `IntegrationsPort` overloads; a host adapter may compose them but cannot collapse
their state or authority. The fork guarantee is extended, not weakened: a standards-compliant host
is reached by a projection plus a host profile, still with no shared-type edits.

**Issue #150 implementation detail.** The portable skill wrapper is neutral Agent Skills
frontmatter (`name` and `description` only) plus relative links to byte-identical packaged guidance
references. The slice is `external_registration`, so it emits no `mcp.json`; Tier 0/1 and the
existing six-operation MCP registration remain unchanged. `PluginArtifactPort` now exists as the
sibling boundary, while activation and new host capability cells remain unimplemented and
evidence-gated.

**Issue #151 implementation detail.** The same neutral plan now has a separately selected
`plugin_managed` projection. It adds only root `mcp.json`, with one exact stdio route and an
explicit pre-preview `strict|policy` profile. It never invokes `HarnessMcpPort`: external/global
registration and plugin-managed configuration are mutually exclusive owners. Component validation
keeps Agent Plugins' narrow failure boundaries, and real initialize/tools-list conformance remains
the same six operations; this artifact slice still creates no host activation or model-use claim.

**Amendment (2026-08-14, issue #222):** Codex hook stdout is event-specific. `SessionStart`,
`PostToolUse`, and `UserPromptSubmit` keep `hookSpecificOutput.additionalContext`. `Stop` and
`SubagentStop` have no such field: JSON that includes `hookSpecificOutput` is marked Failed with
`hook returned invalid stop hook JSON output`. When Stop has advice, Yoetz emits
`decision: block` plus `reason` so the text reaches the model as a continuation, and it does not
block again when the host sets `stop_hook_active`. `SessionEnd` has no output schema and the host
discards stdout, so it is not advice-safe and never consumes a pending delivery.

**Amendment (2026-08-28, issues #420, #435, #338, #428):** Codex's hooks reference was re-read on
2026-08-28: Stop / SubagentStop still admit only the common output fields plus
`decision`/`reason`, and `decision: block` is documented as a continuation prompt built from
`reason`, so the #222 behaviour stands and the loop guard remains `stop_hook_active` plus delivery
identity. Claude Code documents `hookSpecificOutput.additionalContext` at Stop / SubagentStop as
non-error feedback. The Claude ingress renders every advice-bearing event in its installed profile
in that shape, preserves the raw `PostToolUseFailure` name at the host-output boundary, and never
emits `decision: block`. Its renderer knows the SubagentStart / SubagentStop shapes, but the current
native profile does not advertise those events; widening that profile remains separately reviewed.
Workspace-binding outcomes are diagnosed host-agnostically
in the shared ingress (`workspace_unresolvable`, `workspace_unconsented`, `paused`), the two storage
outcomes of a status read carry distinct retryability advisories and the same lowercase diagnostic
tokens, and `yoetz observe` verbs report pre-store conditions as typed public outcomes instead of
`internal_error`. Cursor's reference states `session_id` is "the same as `conversation_id`"; the
alias persisted at `sessionStart` is therefore a defensive bound, not a required join.

**Amendment (2026-09-26, issue #844):** `connect_provider` is standing advice only when service
composition records effective review intent: verification is not disabled, a provider endpoint is
bound, network egress is permitted, and an LLM inference channel is enabled. The verification
default alone, including absent config, does not intend a provider. A private or no-egress install,
an install with no provider endpoint, and a disabled verification setting do not ask Codex, Claude
Code, or Cursor to connect, sign in, or repair one. When intent is recorded and the provider is
structurally unusable, `connect_provider` is still produced, including when the fact has no factory
id. Delivery stays on the standing session-boundary channels: Codex and Claude Code `SessionStart`
and `Stop`, and Cursor `sessionStart`. `PostToolUse` does not carry it. Cursor `stop` still does
not emit `followup_message` for advice. No privacy widening, provider connection, or credential action is implied.
The one later exception is the Stop-time closure gate (ADR-033, #977): Codex `decision: block`,
Claude Code `additionalContext`, and Cursor `followup_message`, once per ledger frontier.

**Amendment (2026-08-14):** Hook advice delivery no longer falls back to the workspace-wide
`advice_snapshot` for task-scoped conditions. Before a Codex session is mapped, task-scoped
advice is selected only from that Codex session's retained envelopes. After mapping, delivery
uses the mapped Yoetz session snapshot when present, otherwise the current Codex session's
envelopes. Workspace-standing machine conditions (`connect_provider`) remain readable from the
workspace snapshot at the documented session-boundary cadence. Suppression is keyed by Yoetz
session when mapped and by Codex session commitment when unmapped, so one task cannot silence
or re-enable another. No new durable field or observation-authority change.

**Amendment (2026-07-22):** First-party Codex observation is required for v0.1 completion of the
Codex integration, still on protocol version `0.1`. Observation is a sibling local-control
capability (`ObservationPort`), not a seventh MCP tool and not an `IntegrationsPort` overload.
Existing v0.1 ledger/object data remains readable. Bundle migration `0002` owns consent, cursor,
dedup, structural envelopes, and the current advice snapshot. Migration `0003` owns authenticated
encrypted workspace-locator/content references, canonical logical identity claims, exact-digest
check-policy trust, generation-fenced verification jobs/results, and advice history/delivery state.
Migration `0004` owns inspection snapshots, workspace→Yoetz-session routing, and session-scoped
current advice without rewriting `0003`. Migration `0009` rebuilds the `0002` cursor and envelope
tables so their source CHECK admits `claude_hook` and `cursor_hook` beside the Codex sources: the
domain enum is the closed set and the DDL follows it, never the reverse (issue #576). Repositories own those tables; coordinators do not issue
private SQL.
Observation consent is workspace-level and separate from egress consent. The plaintext local boundary
records a private workspace commitment, structural outbox/quarantine evidence, and encrypted object
identities—never raw task content or a raw path in logs/status/SQLite.
AI-powered review composition keeps this observation workspace commitment separate from the
`TaskRoute.repository_privacy_commitment`: it derives the observation key only through the durable
workspace-to-Yoetz-session route, verifies the route is for the exact runtime task, and repeats that
check before disclosure. Missing or contradictory route membership is an explicit content gap; the
privacy commitment is never used as an observation-workspace fallback.
Hook ingress and every consent/control lifecycle entry point derive that commitment from one shared
workspace canonicalizer: the nearest safe Git root for a Git subdirectory, or the exact safe
directory for non-Git workspaces. Authority never searches ancestor commitments. Pre-existing
exact-subdirectory grants remain non-authorizing until an operator explicitly regrants them.

Hook `PostToolUse` and a completed session-stream tool record (rollout `function_call_output`,
historically exec-JSONL `item.completed`) for one host call normalize before materialization to
the same semantic kind, correlation identity, roles, operation digest, and ledger IDs. The canonical
host-call identity remains the content and ledger-dedup key; the durable claim identity additionally
binds the materialization version and exact draft-role tuple. Thus distinct phases such as
`PreToolUse` action and paired `PostToolUse` action/result never contend, while hook/stream copies of
the same phase merge source coverage and prevent duplicate appends (issue #309). Cursor advancement is coupled to durable outbox
insertion; overflow leaves later stream input replayable. Unsupported visible future events retain
an opaque envelope, encrypted visible payload when available, and an explicit gap. Session stop is
source-generation fenced, pending work drains fairly across mapped sessions, and quarantine is bounded by
count, byte budget, and a clock-fenced 14-day age with an explicit operator reclaim; every drop
retains aggregate commitment/count/time range plus a loss gap, with involuntary evictions and
operator reclaims counted separately.

An observation route that encounters bundle `STORAGE_CORRUPT` records the exact terminal
`observation_storage_corrupt` gap and quarantines that Codex session's pending delivery backlog.
An identity-claim conflict is instead envelope-scoped `dedup_conflict`: it quarantines that row and
does not arm the generation latch (issue #309).
The READY-generation coordinator suppresses further recovery attempts for that Codex session so a
poisoned mapped task cannot starve healthy sessions or ordinary control. The suppression is not a
durable claim that repair is impossible: composing a new READY generation clears it and permits one
fresh recovery probe after operator repair or restart. A successful probe clears that session's
current corruption condition; the workspace gap heals only after no affected session remains.
Maintenance re-sweeps always yield to the event loop before repeating.

After every completed tool action, ready-service composition captures a descriptor-safe structural
workspace digest. Real state change enqueues exact-policy verification; unchanged state does not.
Approved checks never execute inside the hook RPC budget. A generation-fenced
`ObservationVerificationSupervisor` owned by the ready application lifecycle drains pending jobs:
one job runs per workspace through the enforcing sandbox, newer pending state coalesces older
pending work, abandoned generation leases recover after restart, and a result becomes current only
if post-run state still matches. Sandbox absence is an explicit unavailable result, never a pass.
Bundle migration `0004` owns durable inspection snapshots, workspace→Yoetz-session routes, and
session-scoped current advice; migration `0003` is immutable. Local advice consumes this
evidence offline and materializes through existing `finding_recorded`; ordinary
`status(view="advice")` loads only the advice for the routed workspace and Yoetz session, and safe
hook context surfaces the same bounded finding/evidence identities. The MCP registry remains the
six workflow tools plus read-only `read_guidance` and `closure_prepare` support tools. Observation
is not a workflow tool.

A fork can make Yoetz first-party on another harness by writing one adapter and one profile. It
edits no port, no registry, no guidance, and no schema. That is the property this ADR exists to
guarantee, and it follows from the ports/adapters pattern the rest of the tree already uses.

Any MCP host works on day one with no integration, no skill, and no configuration: six workflow
tools, `read_guidance`, the read-only `closure_prepare` support route, the tier-0 instructions,
and five fetchable guidance documents. The
request-template resource keeps
all six requests and all nine ordinary publication families authorable when a host drops schema
metadata; the catalog schema remains admission authority. The host earns `cooperative_mcp` with
`self_asserted` authorship and `published_only` artifact observation — the weakest honest coverage,
which the coverage vector already expresses precisely. That is not a degraded mode needing a warning
label; it is an accurate one.

**Amendment (2026-10-03, issue #953): bounded closure preparation is an MCP support route.**
`closure_prepare/1.0.0` exposes the existing mechanical closure composer through the same
cooperative identities and explicit selections as the CLI. It reads one pinned, privacy-projected
inventory and prepares at most one request; it never appends, judges work, or claims completion.
The bridge refuses a result after the complete host projection and JSON-RPC serialization would
exceed the stdio frame bound, including Cursor's structured-content plus canonical-text copies,
and directs larger inventories to the CLI `--output` fallback. This adds a read-only support tool,
not a workflow operation or a new authority boundary.

First-party Codex integration therefore buys ergonomics and, when the observation arm is
capability-proven and consented, stronger coverage via `hook_observed`. It never buys a different
public contract. "Codex first" means "the first harness where we deliver guidance natively and the
first where observation can earn `hook_observed`", not "the only harness that works."

A trigger-only v0.1 profile remains a valid ergonomic: it improves recovery reliability but leaves
the coverage vector unchanged. An observation-capable cell must still prove real observation
evidence before any `hook_observed` claim. Profile declaration is not installation authority; no
adapter silently edits host configuration. The exact support cell must prove each advertised arm
through the reviewed host mechanism, or select `None` / empty `observation_events` and retain the
honest weaker coverage.

The cost is one extra indirection for the single harness that exists today, and five guidance files
whose ownership must be respected: a harness restating a shared rule instead of linking to it is a
drift failure, enforced at build.

## Alternatives considered

**Keep guidance under `skills/codex/` and let other harnesses copy it.** Rejected: duplication with
no single owner is exactly the drift the one-owner-per-file method exists to prevent, and it would
force every fork to fork the content.

**Grow `ClientInfoModel.kind` per harness (`claude_code`, `cursor`, …).** Rejected: every new host
would need a Yoetz release and a frozen-schema change, and an unrecognized host would still have
nothing honest to send. The generic value costs nothing because `kind` carries no authority.

**Ship `instructions` only, without resources.** Rejected: it leaves the deep material Codex-only and
gives an agent no follow-up channel, which was the original defect. The bounded, stable-heading
reference documents were already designed for on-demand retrieval.

**Leave the MCP surface bare and document the limitation.** Rejected: the omitted rules are not
polish. An unguided agent publishing transcripts is a privacy failure, and one claiming Yoetz
verified work is the exact dishonesty the product exists to prevent.

### Claude Code native amendment (2026-08-27, issue #154)

`HarnessId` adds exactly `claude`. Its first and only populated candidate profile is
`claude-code-cli-local-project-2.1.241`: a local process, project-scope, marketplace-installed
native plugin on the exact recorded executable/OS/architecture identity. Desktop local/SSH,
Desktop remote, web/cloud, synced, managed/user/local marketplace scopes, Agent SDK, and headless
cells do not inherit this result. Claude Code remains absent from the Agent Plugins compatibility
roster, so the adapter projects from `PortablePluginPlan` and canonical skill bytes rather than
claiming portable-format consumption.

The exact hook arm is `claude-code-hooks-2.1.241-v1` with `SessionStart`, scoped-Yoetz
`PostToolUse`, scoped-Yoetz `PostToolUseFailure`, `Stop`, and `SessionEnd`. It is advisory,
single-flight/coalesced/best-effort under the existing `HarnessHookProfile` contract. Only accepted
consented `claude_hook` envelopes can earn observation coverage; installing, enabling, listing, or
starting a session cannot. The host's plugin namespace is `/yoetz:yoetz`; its MCP server/tool names
are `plugin:yoetz:yoetz` and `mcp__plugin_yoetz_yoetz__<operation>`. Namespacing changes no Yoetz
operation schema and adds no MCP tool. An exact successful scoped `start` `PostToolUse` binds the
Claude host session to that cooperative task by transiently extracting and validating only the
start result's structural task/session/writer identifiers and frontier. Raw result content is not
retained or admitted into observation evidence.


## Instruction loading clarification (issue #613)

Tier 0 remains the intake cue and safety floor. The skill routes through the existing five
registered guidance resources: workflow before start, publication policy before publish, and
coverage/receipts before check. Setup, consent, credential/vault and import procedures live in
request templates and load only for those operations; recovery details load on a corresponding
error or continuation. They remain available through MCP and installed reference copies.

This changes instruction placement and authoring guidance, not runtime authority or wire schemas.
Required AI-powered review follows an explicit user requirement, effective verification policy,
or a named acceptance criterion requiring independent AI-powered judgment. Qualitative work alone
does not turn an optional review into a requirement. A required review cannot be silently
replaced with local-check coverage, and every host and Yoetz approval boundary still applies.

## Compatible host upgrade amendment (2026-09-08, issue #656)

Decision 3 is clarified: "support is never inferred across neighboring host versions" governs
*certification*, not the decision to perform an already-understood operation.

- **Claude Code plugin admission** uses a compatibility floor instead of a one-element exact list.
  Any parseable version at or above `CLAUDE_CODE_MINIMUM_VERSION` (`2.1.233`, where the plugin and
  hook surfaces exist) previews and applies. The preview and status carry
  `version_provenance`: `tested` for an exactly proven cell in
  `CLAUDE_CODE_HARNESS_PROFILE.supported_versions` (currently `2.1.241`), `untested` otherwise.
  A version below the floor or unparseable is refused as `format_unsupported` with
  `version_unsupported` and `minimum_version`. `supported_versions`, the capability profile, and
  the hook cell are unchanged: an admitted `untested` host earns no proven cell.
- **Hook version mapping** (Claude and Cursor) keeps its exact tables. A supplied unknown version
  maps to the `untested` profile token and ingests compatible events under the conservative
  paired contract; an omitted version takes the legacy post-only carrier for that host. No
  unknown version is aliased to a proven profile. For Cursor, the Agent CLI build resolves to
  `untested` because only the IDE cell owns the reviewed hook set.
- **Codex** session-stream admission follows the ADR-005 structural admission amendment.

Exact evidence remains required before a version, cell, or arm is promoted; this amendment only
stops a routine compatible host release from disabling capabilities Yoetz already understands.
