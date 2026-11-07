# FinishUP architecture

How the system is put together and why. This page describes shape and ownership; the code under
`src/finishup/` is the executable truth, and the ADRs under [`docs/adr/`](adr/) are the decisions that
bind it. Shared names — ID prefixes, error codes, event families, coverage dimensions, port
signatures — live in [`docs/INTERFACES.md`](INTERFACES.md).

## The one-sentence version

A persistent local service owns the keys, the decrypted state, the writers, the privacy authority,
and all outbound access; the CLI, the MCP bridge, and any future UI are clients that ask it to do
things. By default that service runs on your own machine; the owner may instead select a FinishUP
server they run elsewhere, which then holds the same authority on its host (see
[Client and server](#client-and-server)).

## Trust topology

```
  agent (via MCP)   human (via CLI)   human (terminal UI)
         \                   |                  /
          \                  |                 /
           +--------- control protocol --------+
                              |
                    +---------v----------+
                    |   trusted local    |   owns: vault keys, decrypted state,
                    |      service       |          storage writers, privacy policy,
                    +---------+----------+          outbound dispatch
                              |
        +---------------------+---------------------+
        |                     |                     |
   SQLite bundle        object store           provider egress
   (structural)         (encrypted)            (policy-gated)
```

The boundary is the point. A client process never holds an encryption key or a decrypted bundle
handle, and never talks to a provider directly. That is what makes "the agent cannot quietly
exfiltrate your repository" a structural property rather than a promise
([ADR-008](adr/ADR-008-local-service-vault-trust-boundary.md),
[ADR-009](adr/ADR-009-data-egress-privacy.md)).

Privacy authority has two durable levels: the machine policy is an installation ceiling, while
external LLM work also requires an exact row for the installation-keyed commitment of the trusted
session's canonical repository. The service derives that identity from actual/configured working
directory, resolves Git's common root (or a resolved non-Git directory), and discards the raw path.
Branches and linked worktrees share authority; independent clones do not. The public
`workspace_ref` used to attach a task is a different, model-controlled identity and cannot select
privacy authority.

Secret material never travels over an ordinary CLI argument, environment variable, config file,
log, trace, transcript, or LLM context. Credentials are provisioned through a confidential terminal
ceremony ([ADR-015](adr/ADR-015-elevated-bootstrap-consent.md),
[ADR-016](adr/ADR-016-human-review-non-default-actions.md)). The API key for a FinishUP server on
another machine is entered at a masked prompt (or read once from an owner-only key file) and kept
in the OS credential store or, where none is usable, an owner-only credential file
([ADR-051](adr/ADR-051-client-server-cut-and-server-targets.md)).

The terminal interface sits on the human-CLI leg and is bound by the same rule. It has no
credential path of its own: when a secret is needed it suspends itself and hands the controlling
terminal to that same ceremony, so no secret byte enters the interface's widget state, transcript,
or any snapshot of it ([ADR-017](adr/ADR-017-full-screen-terminal-interface.md) decision 7).

## Module map

| Package | Role |
|---|---|
| `protocol/` | Canonical wire form: IDs, request/result models, canonical JSON, digests. Pure. |
| `domain/` | Values and events — the vocabulary of what happened. Pure. |
| `kernel/` | Local-check truth: reducers, projections, the check engine, ranking, proof-based finding resolution, receipt building, and the versioned policy packs under `kernel/policies/`. Pure — no IO, no clock, no network. |
| `ports/` | The interfaces the application depends on. First-class boundaries: `ledger`, `objects`, `keys`, `runtime`, `semantic`, `privacy`, `importer`, `integrations`, `subject_state`, `observation` ([ADR-010](adr/ADR-010-harness-integration-port.md)), `plugin_artifacts` ([ADR-023](adr/ADR-023-portable-plugin-carrier-host-activation.md)), `control`, `harness_mcp`, `maintenance`, `check_sandbox`, `workspace_inspect`, `secret_memory`; the rest are small effect ports (`clock`, `ids`, `diagnostics`) and read-only catalogs (`start_catalog`, `publish_response_catalog`). |
| `adapters/` | Concrete implementations of those ports: `sqlite/`, `objects/`, `keys/`, `memory/` (the in-memory reference used for conformance parity), `providers/`, `privacy/`, `importers/`, `integrations/`, `control/`, plus the single-module adapters at the package root — `mcp_stdio.py`, `git_subject_state.py`, `repository_identity.py`, `workspace_inspect.py`, `session_events.py`, `runtime.py`, `approved_checks.py`, `check_sandbox.py`, and `observation_semantic_advice.py`. |
| `application/` | Use cases. One module per public operation (`start`, `publish_work`, `check`, `respond`, `status`, `receipt`), plus egress, privacy policy and privacy control, maintenance, package update, import review, recommendations, harness integration (`harness_mcp`, `applied_mcp_route`, `codex_plugin`, `integrations`), the AI-powered review case and attempt builders, and the observation family (`observation_coordinator` with its `drain`, `health`, `verification`, `materialize`, `check_policy`, `advice`, and `control` modules). |
| `service/` | The persistent trusted process: lifecycle, vault, unlock, control protocol, composition. |
| `cli/`, `mcp/` | Client surfaces. Thin — they translate, they do not decide. |
| `tui/` | The full-screen terminal interface. Presentation only. `runtime.py` is the sole bridge to application services and originates no decision; `render.py` is pure text with no rendering-framework import, so safety-relevant wording is snapshot-tested; `widgets/` holds no security logic. |
| `config/`, `observability/`, `version.py` | TOML settings, privacy-safe logging, resource manifest and identity. |
| `resources/` | Generated byte-mirror of the repo-root `schemas/`, `fixtures/`, `guidance/`, `skills/`, `migrations/`, and `support/` trees, packaged with the wheel and verified against `resources/manifest.json` at load. Edit the root sources; `scripts/sync_resource_ripple.py` converges this mirror. |

`memory/` existing alongside `sqlite/` is deliberate: the conformance suite runs the same scenarios
against both, so "the durable adapter behaves like the reference" is a test result rather than an
assumption.

Multi-agent work has three separate owners. `application/lineage.py` and
`adapters/sqlite/lineage_catalog.py` own recoverable delegation and attachment capabilities;
`application/lineage_coordinator.py` records authorized child dependency snapshots in the parent
ledger, and `kernel/lineage.py` evaluates those frozen snapshots for checks and receipts.
`application/projects.py` owns project membership and admission, while `application/coordination.py`
and `adapters/sqlite/project_coordination.py` own attributable overlap detections and durable
delivery. `application/task_views.py` builds their read-only status views. Host observations enter
through `ports/host_lineage.py` and `adapters/sqlite/host_lineage.py`; a provisional observation has
no task bundle until a separately authorized child start binds it.

`tui/` sitting beside `cli/` rather than inside it is also deliberate. It is a second presentation
of the same operations, not a second authority over them: every gate — preview digests, foreign
MCP entries, privacy widening, vault state, provider readiness — is enforced by the owning service
and merely transcribed by the interface. The split makes that reviewable, because anything in
`tui/` that reached past `runtime.py` would be visible as an import.

## Client and server

[ADR-051](adr/ADR-051-client-server-cut-and-server-targets.md) (Proposed) separates the FinishUP
*client* — everything between the agent or user and the service: hooks, the MCP bridge, the CLI
and the terminal interface — from the *server*, without moving a package. The cut line is a
contract: every module carries one side, and an AST test that also sees imports inside functions
fails on any crossing that its ledger of today's crossings does not list. That ledger may only
shrink. A `finishup.client` module may carry one kind of entry only, `client_outbox`: the drain that
delivers what a remote root's hooks captured opens that root's own observation outbox, a module the
service's observation store still shares.

| Side | Modules |
|---|---|
| **SHARED** (imports SHARED only) | `protocol`, `ports`, `domain`, `config`, `observability`, `resources`, `legacy_names`, `version`; `service.control_protocol` and `service.confidential_protocol` (wire codecs); `adapters.control`; the credential-store primitives `adapters.keys.os_keyring` and `adapters.keys.owner_file_store`; the pure renderers `kernel.fact_lineage` and `kernel.claim_verification`. |
| **WORKSPACE** (imports WORKSPACE and SHARED only; CLIENT and SERVER may import it) | The workspace readers, which run wherever the workspace is: in the local service for a local root, and in the client's workspace agent for a remote one. `adapters.git_change_capture`, `task_input_read`, `approved_checks`, `check_sandbox`, `workspace_inspect`, `home_project_reads`, `input_summary`, `git_subject_state`, `git_rev_parse`, `git_version`; `adapters.workspace_root` (the one rule for "which directory is this workspace"); and `application.observation_check_policy` (the repository's own `checks.toml`). None of them reaches storage, the vault, providers, the service or a client surface. |
| **CLIENT** | `cli`, `mcp`, `tui`, the new `client` package, `service.client`, `service.confidential_client`, the host integration adapters under `adapters.integrations` (except the observation store), `adapters.workspace_binding`, `workspace_fingerprint`, `mcp_stdio`, `process_lifetime`, `release_runtime`, `package_upgrade`, and the client-side application modules `harness_mcp`, `host_connection`, `codex_plugin`, `applied_mcp_route`, `upgrade`, `package_update`, `observation_drain`. |
| **SERVER** | The rest of `service`, `application`, `kernel` and `adapters`: storage, the vault, providers, privacy and the runtime. |
| **GATEWAY** (server host) | `gateway`: a same-user control client of the service, used only by the approaches that run one. It imports SHARED modules and `service.client`, never a workspace reader, and never touches the vault or storage. |

Commands carry a scope too. Each CLI and terminal-interface command is `any`, `server_host` (vault
setup and unlock, provider and privacy configuration, backup, restore, migrate, observation store
administration) or `client_only` (host registration and `finishup server …`). A `server_host`
command is refused while a remote target is active, with `requires_server_host`.

**Targets.** The client talks to one *target*: the ambient local service by default, a named local
service (its own isolated root, vault and ledger, started on demand), or a FinishUP service the
same owner runs on another machine. The owner adds targets with `finishup server add` and picks
one with `finishup server use`, which writes an owner-only selection file. That file is the
lowest-precedence root source: the isolation variable and a runtime pin always win, a selection
that names a missing root fails closed instead of falling back, and no host registration records
it.

**The workspace agent.** The service reads the agent's working tree for the task base, the
check-time change, requested-output facts, task inputs, declared tests, reviewer file reads,
observation verification and approved checks. A server on another machine cannot. For a remote
target the client sends a keyed workspace *claim* instead of a path, and a client-side workspace
agent answers the server's bounded `workspace_call`s with the same adapters and fences the local
service uses. Evidence obtained that way is labelled `client_attested`, and every non-local receipt
rendering says so in one fixed line. When no agent can be reached the receipt carries a typed gap;
nothing passes silently.

### Topology by target

```
LOCAL (default; unchanged)
  hook / MCP / CLI / TUI ──AF_UNIX, peer-UID check──► <ambient runtime>/control.sock ──► service

NAMED LOCAL (each an ADR-028 persistent instance root)
  selected "work" ──► <state>/servers/t_1a2b3c4d/run/control.sock ──► service #2 (own vault, ledger)
  selected "lab"  ──► <state>/servers/t_9f8e7d6c/run/control.sock ──► service #3

REMOTE (local_port, ssh, https; the owner's own server)
  client host                                           server host (same owner)
  hook / MCP / CLI / TUI ═══ control frames, route per approach ═══► service (vault, ledger)
  workspace agent ◄═════════ workspace_call / workspace_reply ══════ workspace hub
  human-control and secret channels: never leave the server host
```

**Direct dial (approach B of [ADR-051](adr/ADR-051-client-server-cut-and-server-targets.md)).**
No relay runs on the client machine. Every client process opens its own control stream:
`finishup.client.transports` picks it from the active root's `target.json`, in place of the fixed
Unix connect in `service.client`, and `ServiceClient` runs the unchanged protocol above it.

```
local, named local   in-process connect_control ─AF_UNIX─► <root>/run/control.sock
ssh                  in-process `ssh -W <remote control.sock>` over a persistent master
                     (<troot>/run/m, ControlPersist 15 min) ─► sshd as owner ─► control.sock
https, local_port    in-process HTTPS binding v1 as a byte stream (finishup.client.https_binding)
                     ─► finishup service gateway (same UID; key + scope) ─► control.sock
```

| Module | Role |
|---|---|
| `finishup.client.transports` | Chooses the transport per root; `UnixTransport`, `SshTransport` (fixed, secret-free OpenSSH argv; closed failure phases from OpenSSH's diagnostics), `HttpsTransport`. Loads no network client. |
| `finishup.client.https_binding` | The binding as a byte stream: sessions, calls with long-polled results, cancels, `workspace_reply` posts, the `workspace_call` long-poll; TLS by CA file or certificate pin. The only client module that imports `httpx`. |
| `finishup.client.direct_runtime` | `server connect`/`disconnect`/`test` for remote kinds: the SSH master (`ssh -fN`, `ssh -O exit`), the gateway check, `server add ssh://…` endpoint discovery. |
| `finishup.client.agent_session` | Where the client serves its workspace when no call runs: the MCP bridge's background agent connection and drain (`BridgeBackgroundWork`, a 15-minute lease renewed by the bridge's calls), and the foreground agent of `server connect --agent`. |
| `finishup.client.remote_remedy` | The one remedy every surface names on a remote root: the remote phase and its ADR-030 directive, never a local-service command. |
| `finishup service gateway` (server host) | The HTTPS edge, identical to approach A's: keys, scopes, sessions, long-polls. |

The workspace agent runs in the client processes themselves. The CLI, the terminal interface and
the MCP bridge connect with `service.client.serving_workspace_binding`, so each answers the
workspace calls of its own operations on its own connection; hooks and drains are claim-bound
without an agent. The MCP bridge also holds a background agent connection for work that outlives a
call and delivers what hooks could not, and `finishup server connect NAME --agent` serves a
CLI-only owner. Agents of one client share keyed opened-workspace handles, so any of them answers
a verification another began. Each client process that dials an HTTPS target reads the target
credential itself (the ADR-008 amendment of this approach).

## The six operations

`start`, `publish_work`, `check`, `respond`, `status`, `receipt` — identical request and result
contracts on the CLI and over MCP ([ADR-002](adr/ADR-002-canonical-protocol.md),
[ADR-010](adr/ADR-010-harness-integration-port.md)). Everything else — import/review,
backup/restore/migrate, integration, version, service, MCP serving — is a bounded support surface,
not a seventh operation.

Flow for a typical task:

1. **`start`** opens a task and issues a session and a writer identity.
2. **`publish_work`** records bounded, participant-published facts: plan, obligations, claims,
   actions, results, evidence. On this cooperative path the participant publishes; FinishUP does not
   infer observation or verification from those assertions.
3. **`check`** runs the local policy packs over the recorded state, producing findings with
   an exact coverage vector. If AI-powered review is configured and requested, an advisory
   provenance-labeled pass runs inside the privacy policy and is deterministically fenced.
4. **`respond`** answers a finding: act, supply evidence, revise the claim, dispute, or state an
   unresolved limitation. A response never erases a finding.
5. **`receipt`** projects the honest summary: what was checked, at what coverage, what is still
   open. Available as `json`, `markdown`, or `text`.

With separate workspace observation consent, first-party harness hooks may retain selected visible content as
secret-scanned encrypted objects. The observation coordinator can materialize only eligible tool
output, changed-file, diff, and bounded inspection objects as `observation_captured` immutable
evidence. That path proves retention and byte identity, not correctness, reproduction, or egress
authority; ordinary `publish_work` cannot self-award it.

## External AI-powered evaluator authorities

External review has two closed runtime shapes behind the same privacy gateway. HTTP profiles use a
one-attempt credential handle minted from the FinishUP vault. The Codex subscription profile instead
launches one exact digest-bound Codex app-server process group and gives it a secret-free attempt
authority; Codex alone owns ChatGPT OAuth and the upstream OpenAI body. Both receive only the
approved canonical case after repository-scoped policy authorization, and both terminate in a
privacy receipt.

The Codex process runs from an empty per-attempt directory with a dedicated owner-private home,
scrubbed environment, strict no-tool configuration, an ephemeral thread, and app-server v2 JSONL
over stdio. Account and model readiness happen before case disclosure. The service rejects tool
requests or extra output and must verify process-group cleanup before success. Provenance binds the
observable case/runtime boundary and explicitly says that the upstream body is unavailable; it
does not invent HTTP-level evidence.

## Determinism and honesty rules

These are enforced in code and locked by tests; they are the reason the system is worth trusting.

- **Coverage-bounded language.** "No issue detected at coverage X" is never rendered as "verified".
- **Local-check results depend only on canonical recorded inputs** plus the versioned policy and
  engine identity. Same inputs, same version, same findings.
- **AI-powered output is advisory**, provenance-labeled, and fenced. `semantic_required` never
  erases a completed local-check result: unavailability returns that result as `incomplete_check`
  with an exact gap, not a failure.
- **Nothing user-controlled** — payloads, titles, paths, prompts, model output — reaches SQLite
  structural tables, logs, errors, or MCP text summaries.
- **Every retryable write has an idempotency identity.** A timeout never proves failure.
- **Every network channel is independently authorized.** No profile overrides the never-send set,
  and effective policy loosens only through a reauthenticated decision the user makes: the trusted
  local ceremony, or — for one exact prepared, expiring consent target — the user's explicit
  current-chat instruction relayed by a capable agent through the consent lane (ADR-016), an
  attestation FinishUP cannot independently authenticate.
- **Machine capability is not repository consent.** External LLM admission requires the exact
  repository grant before provider construction or credential minting; a first grant may atomically
  combine a machine-ceiling widening with repository-row creation.

## Storage

One SQLite bundle per task holds structural rows; content-bearing material lives in the encrypted
object store and is referenced by digest. Migrations under `migrations/` are append-only and CI
enforces that ([ADR-003](adr/ADR-003-storage-sqlite-durability.md)). Task lineage and first-class
projects ([ADR-027](adr/ADR-027-task-lineage-and-project-scope.md)) do not change that layout: a
child is another bundle, and lineage or project membership lives in the catalog. The service, not
a client, projects parent rollup and project status. Recovery paths — backup,
restore, migrate, quarantine — are documented in [`docs/runbooks/`](runbooks/).
Observation migration 0008 adds only nullable digest/byte bindings for the secret-scanned inner
content; it adds no plaintext column and leaves older unbound rows readable at weaker coverage.
Migration 0009 rebuilds the observation cursor and envelope tables so their source CHECK admits
every `ObservationSource` member, including the Claude Code and Cursor hook sources, preserving
existing rows and identities.

Catalog migration preserves accepted machine-policy bytes. It may consume only bounded
pre-upgrade route or one first-repository entitlement to clone that authority into a narrower child
row without reapproval; later repositories inherit nothing. Schema decoders for older control
shapes remain readable but cannot bypass the repository/authority-digest gate.

## Harness integration

FinishUP works with any MCP host with no integration, no installed skill, and no configuration: the
host gets the six operations, read-only `read_guidance`, a short always-delivered instruction set,
and the same guidance documents every harness ships, fetchable on demand.

Codex is the first harness with a first-party integration because its skill surface delivers that
guidance natively. The guidance itself is harness-neutral, owned once under [`guidance/`](../guidance/),
and shipped byte-identically everywhere. Integration is a port with Codex as its first adapter
([ADR-010](adr/ADR-010-harness-integration-port.md)) — a fork can make FinishUP first-party on another
harness by adding an adapter and a profile, without touching the core.

Integration buys ergonomics, never a stronger claim. An agent publishing over MCP earns the weakest
honest coverage, and the coverage vector says so exactly.

The accepted packaging design extends this reach without moving any authority
([ADR-023](adr/ADR-023-portable-plugin-carrier-host-activation.md); its skills-only artifact slice
is implemented by issue #150 and later capabilities remain phased under #148). One neutral
`PortablePluginPlan` projects into either a portable
Agent Plugins 1.0.0 artifact, for hosts that consume the universal standard in their own client
plugin root, or a generated host-native projection in a distinct documented root for hosts that do
not. The artifact is a carrier, never an authority: installation, activation, MCP ownership, and
observation stay separately owned sibling capabilities (`PluginArtifactPort`,
`HostActivationPort`, the existing `HarnessMcpPort` and `ObservationPort`), and format
compatibility with the standard earns no support claim, activation claim, or coverage.

`src/finishup/ports/plugin_artifacts.py` owns the neutral plan and lifecycle types.
`src/finishup/adapters/integrations/portable_plugin.py` owns the Agent Plugins 1.0.0 projection,
offline validation, optional exclusive route-bound `mcp.json`, Codex-root preview/status, and
failure-atomic whole-directory migration. It
reads only packaged `skills/portable/`, `guidance/`, and vendored `support/agent-plugins/` bytes.
The existing `codex_plugin.py` remains the native fallback and is not a source for the portable
manifest.

Cursor is the second first-party harness and remains local-only. The adapter at
`adapters/integrations/cursor_integration.py` owns exact IDE/CLI/SDK identity capture, the
Agent Plugins and Cursor-native projections, explicit user-scope lifecycle, MCP source precedence,
live classified MCP process identity for activation mismatch (`cursor_mcp_runtime.py`),
and the pinned `sdk.v1` TypeScript/Python profiles. The lifecycle consumes one exact
`plugin_artifact_apply` pending only after the scoped presence cell selected per platform by
`artifact_presence.py` obtains a fresh OS-authenticated result: `macos_artifact_presence.py`
(Apple LocalAuthentication) on macOS, `linux_artifact_presence.py` (PAM re-authentication through
the trusted foreground console) on Linux and WSL 2, and fail closed elsewhere; this does not
populate the service-wide presence cell. The one service-wide `UserPresencePort` is
`adapters/keys/macos_user_presence.py` (Apple LocalAuthentication, composed only on macOS), and the
service uses it only for the owner receipt view ([ADR-009](adr/ADR-009-data-egress-privacy.md)
round 5). Cursor-native hooks enter through
`hooks cursor-observe`. On the default structural profile, this boundary retains only allowlisted
structural scalars and a one-way changed-path digest. On that profile, it drops prompts, reasoning,
response text, file paths and contents, edits, MCP arguments/results, transcripts, command output,
and email before observation storage. A separately selected ordinary-work profile can also retain
visible tool content under its matching per-host content consent; see the
[Cursor runbook](runbooks/cursor-integration.md#hooks-and-observation) for capture limits and
acceptance coverage. The adapter never reads or mutates Cursor caches. Cursor Cloud is not a
registered local capability.

Claude Code is the third first-party harness, but it is a native dual target rather than an Agent
Plugins client. `adapters/integrations/claude_code_integration.py` generates a strict private local
marketplace and Claude-native plugin from `PortablePluginPlan`, then delegates project installation,
update, enablement, disablement, and qualified removal to the exact Claude executable. Status reads
Claude's project settings/list result and exact cache bytes while keeping enablement distinct from
loaded-session activation. It observes local/project/user/plugin/connector MCP sources without
turning Claude's precedence winner into a FinishUP ownership claim.

Claude-native hooks enter through `hooks claude-observe`. On the default structural profile, only
the exact scoped FinishUP MCP tool names and bounded structural lifecycle facts survive; raw Claude
prompt/transcript/path/tool/result/error content is discarded before storage. A separately selected
ordinary-work profile can also retain visible tool content under its matching per-host content
consent; see the [Claude Code runbook](runbooks/claude-code-integration.md#hooks-and-observation)
for capture limits and acceptance coverage. The `claude_hook` source is carried on local-control schema
`2.2.0`. The initial capability fixture covers only local CLI `2.1.241`, macOS arm64, project scope,
and private marketplace install. Desktop, remote, web/cloud, synced, managed/user/local scope,
Agent SDK, loaded-session/model-use, AI-powered review, privacy-receipt, and workflow-receipt cells
require
their own evidence.
