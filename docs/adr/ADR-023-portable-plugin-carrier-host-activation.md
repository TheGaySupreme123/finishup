# ADR-023 — Portable plugin carrier and host activation

**Status:** Accepted (2026-08-21), acknowledged in
[issue #149](https://github.com/TheGaySupreme123/finishup/issues/149#issuecomment-5371952502).
Issue #149 suggested the name ADR-020; that number was taken by typed evidence digest provenance
before this document landed, so the accepted decision set lives here unchanged.
**Implemented by:** the skills-only artifact slice (#150) and optional exclusive plugin-managed MCP
slice (#151) are implemented by `ports/plugin_artifacts.py` and
`adapters/integrations/portable_plugin.py`. Later children of #148 still own activation and
per-host capability cells.
**Relates to:** ADR-005 (exact capability identity), ADR-007 (packaging/release), ADR-008
(trust boundary), ADR-009 (egress/privacy — deliberately not amended), ADR-010 (harness
integration port), ADR-012 (first-run setup wizard), ADR-016 (human review), ADR-018 (MCP route
egress ceiling).

## Context

FinishUP has the right security split but no neutral package model. The current Codex renderer
(`src/finishup/adapters/integrations/codex_plugin.py`) directly produces `.codex-plugin/plugin.json`,
`.mcp.json`, skills, and hooks with no owning port, and its generated `.mcp.json` hard-imports the
policy serve command with no strict variant — a generated file claiming a route the artifact does
not own, exactly what ADR-018 exists to prevent. Generalizing that renderer would make a Codex
artifact the source for Cursor and Claude, merge installation with activation, and conflate format
compatibility with tested support.

The Agent Plugins specification 1.0.0 (Published) standardizes a portable plugin directory: a
`plugin.json` manifest at the plugin root, shared skills, and an optional MCP configuration. It
intentionally does not standardize installation, trust, consent, hooks, observation, marketplaces,
credentials, or proof, and it prescribes no install root — each client chooses. That thinness is
useful: the portable format can carry FinishUP's shared guidance to any standards-compliant host
without FinishUP inheriting authority claims it must then disown.

This change is about platform reach, not user experience. Adopting the universal standard lets
FinishUP reach every host that speaks it while preserving first-class support for hosts that do not.
The user-facing install surface — the ADR-012 wizard and `finishup integrate` commands, one
preview/apply experience — does not change; only the backend selection of what is rendered where
becomes host-derived.

## Decisions

1. **A portable plugin is a carrier, never an authority.** A portable artifact may carry common
   metadata, shared skill/guidance bytes, and an optional exact MCP declaration. It cannot
   authorize disclosure, store credentials, unlock the vault, approve observation, call providers
   directly, strengthen coverage, or replace a FinishUP receipt. The trusted local service remains the
   sole state, privacy, and provider authority (ADR-008, ADR-009); plugin and MCP clients remain
   untrusted. Nothing a host does with the artifact — discovery, activation, marketplace listing —
   creates authority, consent, or coverage.

2. **One canonical neutral plan: `PortablePluginPlan`.** Every manifest and configuration —
   Agent Plugins `plugin.json`, the Codex-native layout, any future Cursor or Claude Code native
   projection, and a plugin-managed `mcp.json` — is a generated projection of one pure plan
   carrying: common metadata; canonical skill/resource byte sources (the packaged `guidance/`
   mirrors, byte-identical per ADR-010 decision 1); a `PluginFormatProfile`; `McpOwnership`
   (`external_registration | plugin_managed`) with the exact `strict | policy` route profile when
   plugin-managed; an optional host-extension profile; schema and renderer versions; and the
   complete managed-file inventory with sizes and SHA-256 digests. Agent Plugin JSON is never the
   input for a Claude, Cursor, or Codex native manifest; projections share only the plan.

   Host-targeted skill entrypoints may differ to describe that host's invocation, context delivery,
   and recovery, independently of carrier format. They are canonical packaged sources selected by
   the owning renderer and included
   in its source refs and digest-bound inventory. The five shared `guidance/` references remain
   byte-identical across projections and own ledger, evidence, consent, and receipt semantics;
   entrypoints must not fork those contracts. A generic portable export retains a neutral skill;
   a Cursor-targeted portable artifact carries the Cursor skill. The neutral portable skill contains
   no host-specific restart procedure. This clarification follows the maintainer's scoped personalization request
   recorded on [#613](https://github.com/TheGaySupreme123/finishup/issues/613#issuecomment-5608159518).

3. **The upstream revision is pinned for vendoring.** The portable projection targets Agent Plugins
   specification 1.0.0 exactly. Its two canonical schemas are pinned for vendoring by URL and
   digest:
   `https://agent-plugins.org/schemas/1.0.0/plugin.schema.json`
   (SHA-256 `0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883`) and
   `https://agent-plugins.org/schemas/1.0.0/mcp.schema.json`
   (SHA-256 `6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb`). As with ADR-007
   decision 11, the #150 implementation must vendor those exact bytes before any renderer or
   validator ships; the packaged vendored copy then becomes the runtime authority and upstream
   availability is never an operational dependency. Upstream v1 is intentionally thin and may
   evolve; adopting a newer revision is a reviewed change to this pin, never an ambient upgrade.
   #150 must register the vendored schema bytes and every generated/committed artifact tree under
   the `scripts/sync_resource_ripple.py` owning fixed-point before adding them; mirrors are never
   hand-edited. The two digests above were re-fetched and confirmed against the canonical HTTPS
   bytes on 2026-08-21; that live comparison is design evidence, not a runtime dependency.

4. **Sibling capabilities, not a catch-all port.** The skill-focused `IntegrationsPort` is not
   broadened. Two sibling ports are registered, following the `HarnessMcpPort` precedent
   (ADR-010/ADR-012): `PluginArtifactPort` — `preview_artifact`, `install_artifact`,
   `status_artifact`, `remove_artifact`, with interrupted-swap recovery expressed through status
   reconciliation, never automatic repair — and `HostActivationPort` — `observe_discovery`,
   `observe_activation`, and, only when authorized, `preview_activation` / `apply_activation`
   and `preview_removal` / `apply_removal`.
   `HarnessMcpPort` keeps external/global MCP registration; `ObservationPort` keeps consented
   observation. A host adapter may compose these ports; it cannot collapse their state or
   authority, and no port's status field implies another's.

5. **Host product, format, and capability cell stay distinct.** Codex CLI, ChatGPT desktop, Cursor
   IDE, Cursor CLI, Cursor cloud, and Claude Code are distinct `HostSurface` values and distinct
   evidence cells. Each exact host profile records version/build, accepted format, skill discovery,
   activation, MCP ownership, trigger events, observation events, observability limits, and
   evidence fixture IDs. Speaking the Agent Plugins format earns no first-party identity, no
   populated capability cell, and no coverage — ADR-005's rule becomes more load-bearing as format
   compatibility gets cheaper, not less. At this ADR's acceptance `HarnessId` remained exactly
   `codex`; the acknowledged issue #153 amendment adds `cursor` with one local adapter and no port
   change. Fixed terminology: a Cursor surface consuming the portable artifact is a **portable**
   cell and one consuming a generated native projection is a **native** cell — separate cells even
   on the same product; Claude Code is a **native dual-target** host whose project-scope and
   user-scope install targets are separate cells, with only project scope in initial design scope.

6. **Hybrid per-host install roots, one install surface.** A host that supports the portable
   format receives the portable artifact in that host's own client plugin root; a host that cannot
   consume it receives a generated native projection in a distinct, per-host documented native
   root. The user-facing installer is unchanged: setup detects the host and derives format and
   root; the user approves exact before/after bytes and never chooses a root, format, or migration
   path. For Codex the client plugin root is the existing `.agents/plugins/finishup`, so migration
   from the bespoke layout to the portable layout is a whole-directory, marker-identified,
   digest-bound replacement at the same root under the existing ADR-012 preview/apply and
   activation ceremony — exactly one managed tree exists there at a time, its format identified by
   its managed marker, and the bespoke Codex fallback remains the shipping control until a portable
   projection is capability-proven and explicitly approved. Portable and native projections must
   have disjoint path inventories wherever both could exist; a collision is a refused preview,
   never a merge. Native roots for non-supporting hosts (e.g. Claude Code) are frozen in that
   host's profile registration, with fixture evidence, before any render targets them. Upgrade,
   remove, interrupted recovery, and rollback follow the existing whole-directory swap rules; there
   is no pathname rollback.

7. **Exclusive MCP ownership.** Under `external_registration` the portable artifact omits
   `mcp.json` and the existing `HarnessMcpPort` registration remains authoritative. Under
   `plugin_managed` the artifact includes a generated `mcp.json` and no second native or global
   registration may own the `finishup` server name. Observed ownership is the closed
   `McpOwnershipState` (`absent | external | plugin | dual | foreign | ambiguous`); dual, foreign,
   and ambiguous are explicit reported states — never silently resolved, chosen between, or
   overwritten. Child-issue shorthand is reconciled to this enum: `owned` is not a seventh state
   and must resolve to `external` or `plugin` from the observed source, while `foreign_present`
   projects to `foreign`; unknown or conflicting evidence projects to `ambiguous`, never to an
   effective route. In plugin-managed mode the exact argv and the `strict | policy` route profile
   are chosen before approval and bound into the preview and artifact digests; runtime
   configuration, environment, agent input, and later privacy widening cannot change the route
   (ADR-018).

8. **Idempotent mutations with honest ambiguity.** Every mutating artifact or activation request
   carries an exact request identity. Same-request replay returns the stored result or reconciles
   through status; a timeout or connection loss returns `outcome_unknown` and never implies
   failure; a retry cannot create a second stage, apply, or remove operation. Status distinguishes
   the closed `PluginOperationState` (`not_started | in_progress | completed | refused |
   outcome_unknown`) without user-controlled structural content.

9. **The safe artifact lifecycle is preserved wholesale.** Every mutation targets one selected
   trusted project and keeps the current protections: exact before/after preview and accepted
   digest; stale-preview rejection; safe-root/path containment with no symlink members; complete
   inventory, sizes, and SHA-256 digests; no portable/host-extension path collisions; no overwrite
   or removal of unmanaged or modified content; failure-atomic replacement with conservative
   recovery; installed-byte verification; and no inference from filesystem presence to activation.

10. **Proof facets stay independent.** Public and setup status keep these facets separate, and no
    document, status field, or summary may imply one from another: source, rendered artifact,
    installed bytes, host discovery, host activation, skill delivery, MCP owner, MCP binding, MCP
    runtime, model-controlled use, trigger capability, observation consent, observation evidence,
    service readiness, AI-powered review readiness, provider dispatch, privacy receipt, and the
    final workflow receipt. Format validation in particular proves none of activation, observation,
    AI-powered review dispatch, or closure.

11. **Authority: standalone mutation is assigned to ADR-016 `review_only`.** The
    install/remove/activation-apply paths of the new ports must consume the ADR-016 `review_only`
    single-shot trusted review of the exact plan digest (ADR-016 is amended accordingly). #150
    owns the first implementation of that operation-specific prepare/consume boundary; this
    design-only change does not make any new mutation available. An
    ordinary TTY confirmation, `--accept`, a same-UID process, or a host marketplace prompt is not
    and cannot silently become `UserPresencePort` authority. Issue #409 adds a scoped production
    adapter for the pinned macOS Cursor cell: Apple LocalAuthentication authenticates one fresh
    device owner against a prompt naming the exact operation, preview digest, and pending review;
    only then may the already-bound single-shot pending be consumed. Cancellation, timeout,
    unavailable policy, non-macOS hosts, and every binding mismatch fail before mutation. Other
    standalone paths remain render/preview/status-only until they wire an independently proven
    authority cell. Before #150 implements the
    boundary they do not exist at all. The ADR-012 setup wizard's
    already-authorized digest-bound composition remains the separately authorized install path and
    is unchanged. Agent preparation is never trusted human review (ADR-015/ADR-016).

    **Amendment (2026-08-25, issue #419).** Codex marketplace removal is authorized the same way
    Codex marketplace activation already is: the ADR-012 digest-bound `--accept` composition on
    `finishup integrate codex plugin remove` and `finishup integrate codex mcp remove`. That path does
    not consume `plugin_artifact_apply`. Using the Cursor OS-presence cell here would fail closed
    on this host and would mis-name the authority Codex activation already uses. Cache purge is
    default-off. Removal never deletes the skill tree, consent records, or the observation store.

    **Amendment (2026-09-13, issue #719).** The `plugin_artifact_apply` presence cell is chosen
    per platform through one selector shared by the Cursor and Claude Code native lifecycles:
    macOS keeps the #409 LocalAuthentication adapter; Linux, including WSL 2, re-authenticates
    the invoking account through Linux-PAM with the password entered only at the trusted
    foreground console (ADR-016 amendment of the same date); every other platform fails closed
    with `human_authority_unavailable`. Neither host inherits a proof its platform did not earn,
    and `preview` reports the selected cell so the operator sees which ceremony the accepted
    mutation will demand.
    After a successful activation removal, `inspect_activation` follows the #347/#387 closed
    states: `installed_not_activated` when the managed plugin source at `.agents/plugins/finishup`
    remains, and `not_installed` only when that source is also absent.

12. **Phased rollout, ADR-009 untouched.** Slice 1 is explicitly skills-only with
    `external_registration`: the portable artifact carries metadata and shared skill bytes, omits
    `mcp.json`, and will ship render/preview/status plus the authorized install paths of decision
    11 only after #150 implements and tests them. The native Codex behavior in
    `docs/runbooks/codex-integration.md` remains the control.
    Plugin-managed MCP is a separately reviewed child issue. Every new host cell (ChatGPT desktop,
    Cursor surfaces, Claude Code) remains evidence-gated under E-017; E-002/E-013 continue to gate
    Codex unchanged. No consent, disclosure, or observation behavior changes, so ADR-009 is
    deliberately not amended; if a later slice changes any of those, it must amend ADR-009 first.

### Implemented slice-1 artifact (issue #150)

The portable projection contains exactly `plugin.json`, `skills/finishup/SKILL.md`, and the five
`skills/finishup/references/*.md` guidance mirrors. It contains neither `mcp.json` nor the
Codex-specific `skills/finishup/manifest.json`. The root manifest validates offline against the
byte-pinned Agent Plugins 1.0.0 schema, and the immediate-child skill uses only `name` and
`description` frontmatter. Unknown root manifest fields are reported and ignored for component
loading; fatal known-field violations reject the manifest, while an invalid skill component is
reported at its own boundary.

### Implemented slice-2 MCP projection (issue #151)

`plugin_managed` adds only root `mcp.json`, generated in exact policy and strict variants from the
same plan. The route uses bare executable `finishup`, contains no secrets or environment, and remains
exclusive with native/global registration. Preview and artifact identities bind the full bytes,
route profile, and current ownership state. Offline validation preserves the specification's
top-level/component/server failure boundaries. Provider status combines external and plugin
observations conservatively; no host cell or activation claim is created by this implementation.

The exact standalone mutation operation is `plugin_artifact_apply`, risk class `review_only`,
bound to the complete preview digest. Agent-chat authorization is forbidden. The pinned macOS
Cursor CLI uses the issue #409 LocalAuthentication adapter, Linux and WSL 2 use the issue #719
PAM trusted-console adapter, and a host without a production cell fails closed before target
mutation. The ADR-012 setup composition remains the separate
existing authority path. The Codex native tree
continues to ship as the active control; #150 adds the portable renderer and whole-directory
migration/rollback implementation but makes no discovery or activation claim.
The exact Codex project root/scope and skills-only member inventory are registered by fixture
`agent-plugins-codex-project-root-1`; its proof limits explicitly deny discovery, activation, and
coverage inference.

## Consequences

Adding a standards-compliant host becomes a projection and a host profile, not a renderer fork —
the ADR-010 property ("one `HarnessId` value plus one adapter") extends to packaging. The current
`codex_plugin.py` renderer becomes an adapter behind `PluginArtifactPort` producing the
Codex-native projection of the plan, and the marketplace/activation mechanics in
`codex_marketplace.py` become a `HostActivationPort` adapter; both refactors are behavior-preserving
and land only after the names in `docs/INTERFACES.md` and this ADR. The generated `.mcp.json` route
hazard is closed structurally: route bytes exist only in a plugin-managed projection, generated
from the plan's bound route profile.

The cost is a third managed-artifact vocabulary to keep honest (portable format, native
projections, and their proof facets), a vendored upstream schema pin to maintain, and a per-host
root model that must be frozen cell by cell instead of assumed. The distinct-cells rule means
FinishUP will frequently be *format-compatible* with a host it does not *support*; status wording must
keep saying so.

ADR-007, ADR-010, ADR-012, ADR-016, and ADR-018 are amended in the same review as this ADR.
`docs/OPEN_QUESTIONS.md` gains gate E-017 for portable-carrier host cells. Child issue scopes under
#148 must be reconciled against this ADR before their implementation PRs open.

The reconciled execution map is explicit: #150 owns the skills-only portable renderer, schema
vendoring, artifact lifecycle, and first `review_only` consumer; #151 alone may add
`plugin_managed` MCP; #152 proves Codex CLI and ChatGPT desktop as separate cells while retaining
the native fallback; #153 owns the separate Cursor portable/native cells; #154 owns the Claude
Code native dual target and must not claim Agent Plugins consumption; and #155 consumes those
bounded cells for cross-host evidence without repairing their implementations. All remain children
of #148. #151 is not on the critical path for the skills-only #152 pilot, and no child may populate
E-017 or widen a support claim from format conformance alone.

## Alternatives considered

**Generalize the existing Codex renderer.** Rejected: it makes a Codex artifact the source for
other hosts, merges installation with activation, and gives a generated `mcp.json` a route it does
not own.

**Use Agent Plugin JSON as the canonical input for every manifest.** Rejected: the upstream format
is intentionally thin; deriving native manifests from it would smuggle format limits into the plan
and invert ownership. The neutral plan is authoritative; every format is a projection.

**One standards root for every host, including non-supporting ones.** Rejected: hosts that cannot
consume the portable format would need shims or copies inside a root they do not read, and the
migration risk lands on exactly the hosts least able to verify it. Distinct native roots keep each
host's cell honest.

**Broaden `IntegrationsPort` into a catch-all.** Rejected: skill-install types carry
trusted-project file semantics that artifact and activation state must not reuse; the
`HarnessMcpPort` sibling precedent already proved the split keeps the fork guarantee intact.

**Treat a host marketplace prompt or `--accept` as review authority.** Rejected: ADR-016's
presence rule exists precisely because same-UID automation can fabricate both; a standing trust
change needs the single-shot digest-bound review lane or the already-authorized setup ceremony.
Issue #409's macOS adapter therefore creates a fresh LocalAuthentication context with reuse
disabled for every exact pending.

**Ship phase 1 render/preview/status-only and defer the authority question.** Rejected by
maintainer decision: the `review_only` lane is designed now so implementation does not later
improvise authority. Issue #409 makes only the exact pinned macOS Cursor cell usable; neighboring
cells remain unavailable rather than inheriting that proof.

### Claude Code native/project amendment (2026-08-27, issue #154)

`PluginFormatProfile` adds exactly `claude_code_plugin_native`; `HarnessId` adds exactly `claude`.
The native plugin root is `plugins/finishup/` inside a generated strict private marketplace source;
only its manifest lives at `.claude-plugin/plugin.json`, while skills, hooks, and optional
`.mcp.json` are siblings at the plugin root. Shared skill/reference bytes remain identical to the
portable projection, but neither Agent Plugins JSON nor Codex/Cursor native JSON is an input.

The initial `HostSurface.CLAUDE_CODE` cell is narrowed to Claude Code CLI/local process/project
scope/private-marketplace delivery and profile `claude-code-cli-local-project-2.1.241`. Neighboring
Claude products and scopes stay explicit unpopulated cells. `defaultEnabled:false` is required.
Source generation, project marketplace registration, cached installation, discovery, enabled
setting, loaded-session root, skill use, MCP owner/binding/runtime/model call, hook
configuration/delivery/consented evidence, AI-powered review dispatch, privacy receipt, and
workflow
receipt remain independent facts.

`ClaudeCodeMcpSource` is exactly
`local|project|user|plugin|claude_ai_connector`, in Claude's observed precedence order. The winner
is reported separately from ADR-023 ownership: plugin plus any external exact route is `dual`, two
same-owner sources are `ambiguous`, any non-exact same-name entry is `foreign`, and unreadable
reachable state is unobserved `ambiguous`. Install/update/enable refuses those unsafe owner states;
remove disables no foreign source and deletes only the exact managed project installation/source.

Claude lifecycle actions are `install|update|enable|disable|remove|noop`. Each mutation consumes the
same exact-preview `plugin_artifact_apply` review lane and reconciles through independent
list/settings/cache read-back. A nonzero/lost CLI outcome that did not reach the exact target is
`outcome_unknown`; it is never guessed failed or rolled back across host-owned settings/cache.
Marketplace `strict:true`, project scope, manifest version, source/render/cache digests, exact host
identity, settings preimage, MCP owner, and requested action are preview-bound. Installation starts
disabled; enabled state still does not prove a loaded session.

#### Launcher binding and development export (2026-08-27 dogfood follow-up)

The first live Claude dogfood failed on two carrier-level facts: the rendered `.mcp.json` and
hooks launched a bare `finishup` from the host's PATH, so the plugin bridge, hook process, and
long-running service came from different installations on one machine; and a
`defaultEnabled:false` carrier does not load under `claude --plugin-dir`, so no supported
development activation existed. The Claude carrier therefore binds the exact invoking launcher
(shared with the Cursor native carrier through `finishup.adapters.integrations.launcher`), records it
in a version 2 source marker, and folds it into the artifact digest. A separate `development`
render (`defaultEnabled:true`) exists only for `finishup integrate claude plugin export`, which writes
the plugin root to a caller-chosen new directory without touching host state or consuming review
authority; preview refuses that carrier, and it never earns marketplace-installed proof. The
marketplace cell still installs disabled.

The dogfood's third failure was not a carrier fact: an upgraded bridge could not talk to the
previous installation's still-running service, and could not ask it to stop. That is resolved in
the local-control client (`service_incompatible`, supersede-on-upgrade, `finishup service restart`);
see `docs/INTERFACES.md` under the trusted local service contract.


### Cursor Agent CLI project binding compatibility (issue #786, 2026-09-19)

Maintainer-approved: Agent CLI can explicitly register `project_binding=registered-project` where
that native client lacks MCP roots/list. The accepted registration preview binds the exact local
project, launcher, isolated instance, route, and mode. The bridge requires that exact owned entry
and revalidates configuration and repository directory identities for every workflow call; drift
retires it. This is a distinct operator-selected CLI path, never a CWD, hook, public argument, or
clientInfo fallback. Default desktop registrations retain their mandatory native-root exchange.
Existing privacy, capture, disclosure and authenticated plugin-install ceremonies are unchanged.
See `docs/INTERFACES.md` and the Cursor integration runbook for commands and failure boundaries.
