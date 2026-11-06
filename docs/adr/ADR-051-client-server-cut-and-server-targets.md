# ADR-051 — Client/server cut line, server targets and the workspace agent

**Status:** Proposed for [issue #903](https://github.com/TheGaySupreme123/finishup/issues/903).
Design gates: protocol (control envelopes 2.10.0 and the workspace frames), privacy/egress (the
FinishUP server hop), storage layout (target roots and the selection file), release/packaging
(client and edge processes, version lockstep) and the `OPEN_QUESTIONS` flip. Maintainer
acknowledgement: on 2026-11-05 the maintainer explicitly requested this scoped work — separate the
FinishUP client from the server inside this repository; let a client use the local server, several
local servers including ones reached on localhost ports, a server on another machine over SSH and
web-hosted servers over HTTPS with an address and an API key; deliver three complete pull requests,
one per way of doing the separation, each "full, plug and play". Under the intake rule in
`AGENTS.md`, that explicit request is the design-gate acknowledgement for this scope. The GitHub
integration available to the session returned 403 both for creating an issue and for commenting,
so the acknowledgement is recorded here and in each pull request body; #903 stays the owning
issue. The acknowledgement grants no runtime, credential, disclosure or destructive-action
authority.
**Implemented by (shared foundation, identical in all three pull requests):**
`tests/unit/architecture/` (boundary map, crossing ledger and the AST boundary test),
`src/finishup/cli/command_scope.py`, the `src/finishup/client/` package (targets, credentials,
`target_runtime`, `workspace_claim`, `workspace_agent`, `workspace_ref`, `remote_binding`,
`observation_outbox`, `attribution`), `src/finishup/cli/server.py`,
`active_root()` and the `selection` binding in `src/finishup/config/paths.py`,
`src/finishup/ports/workspace_agent.py`, `src/finishup/adapters/workspace_root.py`,
`src/finishup/service/workspace_hub.py`, `src/finishup/service/workspace_routing.py`,
`src/finishup/application/observation_workspace.py`, the claim path of
`src/finishup/service/control_protocol.py` and `src/finishup/service/daemon.py`, the
control-envelope 2.10.0 schemas and fixtures, and the closed tokens in
`src/finishup/protocol/errors.py` and `src/finishup/protocol/recovery.py`. Each approach adds the
modules its topology section names.
**Amends:** ADR-001, ADR-008, ADR-009, ADR-018, ADR-026, ADR-028 and ADR-031; each carries a dated
amendment note pointing here. **Relates to:** ADR-002 (idempotency scope), ADR-010 (Cursor roots),
ADR-030 (typed recovery directives), ADR-048 (frozen `yoetz` identifier namespace), issue #903 and
closed pull request #946.

## Context

FinishUP runs one persistent per-user service that owns the vault, the ledger, the privacy
authority and all outbound access (ADR-001, ADR-008). Every client — hooks, the MCP bridge, the CLI
and the terminal interface — reaches it over an owner-only Unix-domain endpoint whose path is
derived from one root (ADR-026). Isolated roots and runtime pins (ADR-026, ADR-028) already let
several services run side by side, but nothing lets the owner choose among them, and nothing
reaches a service on another machine.

Issue #903 asks for a thin local client and a server that owns the ledger, vault, checks,
AI-powered review and receipts: HTTPS with an address and an API key (pluggable so OAuth can
replace the key later) or SSH with server-authorized keys and a verified host key; the same wire
contract for both; credentials never exposed to agents, hooks or MCP; the server enforcing the same
method allowlist; receipts that name the producing service; defined behaviour on disconnect; a
decision for every host; schemas and fixtures.

Pull request #946 (closed unmerged on 2026-11-05) recorded one `remote-mode.json` and refused to
connect with `remote_egress_not_authorized`. Its draft ADR took the number 033, which now belongs
to task facts. It is superseded by this ADR because:

- only the *local service* would forward, so a client machine still needed a full vault and
  ledger just to proxy, and two vaults raised the question of which one is locked;
- it was not a client/server split, and it never answered how the network hop is authorized;
- it held one remote record, with no named targets and no several local servers;
- it never reached end to end, so it left the service's reads of the agent's working tree
  unsolved.

This ADR keeps from #946 the endpoint normalization, the refusal of plain HTTP, the same operation
contracts on every transport, a server-enforced method allowlist, receipts that name the producer,
and a decision per host.

The hardest coupling is not the transport. The service reads the agent's working tree directly:
repository identity at handshake, the task change base, the ADR-031 check-time change and its
requested-output probes, task-input snapshots, declared-test pinning, the reviewer's `read_file`,
observation verification and approved checks. Several of these run after the client call has
returned (the detached semantic check, the reviewer loop, the observation sweeper). A server on
another machine cannot read that tree, and a server-side directory that happens to have the same
path is a different tree.

The maintainer's request on 2026-11-05 fixes the outcome: a remote target must work end to end,
including check-time change capture, reviewer file reads, task inputs, approved checks and
observation, with no coverage gap standing in for any of them. Gaps are allowed only as honest,
typed outcomes when the client side cannot be reached.

## Decisions

### 1. The cut line is an enforced contract, not a package move

- Every module under `src/finishup/` is labelled CLIENT, SERVER, SHARED, WORKSPACE or GATEWAY in
  one boundary map. GATEWAY is reserved for a same-user control client of the daemon on the server
  host (`finishup.gateway`), used only by the approaches that run one. CLIENT covers `cli`, `mcp`,
  `tui`, `service.client`, `service.confidential_client`, the host integration adapters (except the
  observation store the service also opens), the client-side application modules and the new
  `finishup.client` package. SHARED covers `protocol`, `ports`, `domain`, `config`,
  `observability`, `resources`, `version`, the control-protocol framing and the Unix-socket
  adapter. Everything else is SERVER.
- WORKSPACE is the layer of workspace readers, which run wherever the workspace is: in the local
  service for a local root and in the client's workspace agent (decision 5) for a remote one. It
  holds the Git capture, task-input, approved-check, sandbox, inspection, home-project and
  input-summary adapters, the Git subject-state, `rev-parse` and version helpers, the shared
  `adapters/workspace_root.py` rule and the repository check-policy parser
  (`application.observation_check_policy`). CLIENT and SERVER modules may import it; a WORKSPACE
  module may import only WORKSPACE and SHARED modules, so a workspace reader never reaches storage,
  the vault, providers, the service or a client surface, and no ledger entry may excuse one.
  SHARED and GATEWAY modules may not import it.
- An AST test walks every module, including imports inside functions, and fails on any crossing
  not recorded in a ledger. The ledger is seeded with today's crossings, measured by the test
  itself, and may only shrink: a ledger entry that no longer occurs also fails. Each entry carries
  a closed disposition: `server_host_only`, `shared_pure`, `to_rpc` or `client_outbox`. The last is
  the only one a `finishup.client` module may carry, and it names one module: the client's drain
  opens its own root's observation outbox to deliver what that root's hooks captured to a remote
  server, which never opens that root. The import crosses only because the outbox and the
  service's observation store still share `adapters.integrations.observation_local`; it closes
  when the outbox moves out of that module.
- A command-scope registry labels every CLI and terminal-interface command `any`, `server_host`
  or `client_only`. One guard, `require_server_host()`, refuses a `server_host` command while a
  remote target is active, with `requires_server_host`. A test walks the command tree and the
  interface's command registry and fails on an unlabelled command.
- New client-side code lives in `finishup.client`. Hooks may load target selection, but never
  `httpx` or a client transport module, at import time; the hook import-diet packaging test locks
  that.
- No existing file moves. Moving `cli/`, `mcp/` and `tui/` would rewrite the console-script target
  the Codex RECORD proof depends on, the entry fast paths, the tests that patch connection
  factories by name and the resource mirrors, and change no behaviour. A rename-only change may
  follow later.

### 2. A target is an isolated root, selected by an owner-only file of lowest precedence

- **Roots.** Each target is one root at `<ambient state dir>/servers/t_<8 hex>/` holding
  `target.json` (tag `yoetz.server-target/1`, ADR-048 namespace). The short id keeps every socket
  path beneath the root inside the AF_UNIX limit even under `~/Library/Application Support/`. A
  `local` target's root is a persistent ADR-028 instance root with its own vault, ledger, config,
  endpoints and on-demand service. A remote target's root holds only client state: startup gates,
  hook memos, the bridge↔hook records, the observation outbox and spool, and whatever its
  approach's client-side process needs.
- **Selection.** `<ambient config dir>/server-selection.json` (tag `yoetz.server-selection/1`)
  holds one `target_id`. Absent, the ambient service is used exactly as today.
- **Precedence.** A new `active_root()` resolves `FINISHUP_ISOLATED_ROOT` (or its legacy alias),
  then the ADR-028 runtime pin, then the selection file, else ambient. `isolated_root()` keeps
  meaning "explicitly isolated" (variable or pin). Every root that follows the target — state,
  runtime, config, log, cache, bundle — derives from `active_root()`; registrations and launch
  lines stay on `isolated_root()`. An AST test locks the classification of every call site, so a
  selected root is never stamped into a host registration and connecting a host while a target is
  selected does not freeze it onto that target. `isolation_binding()` gains the value
  `selection`, carried by isolation report 1.1.0.
- **Fail closed.** A selection that names a missing, malformed or unsafe root fails with
  `isolation_root_invalid` and never falls back to the ambient service. `server use` refuses while
  the variable or a pin is in force (`selection_overridden`). `server status` always names the
  source that decided the root.
- **Names.** A target name matches `[a-z0-9][a-z0-9-]{0,15}`; `local` is reserved. A name appears
  only in `target.json` and in owner displays (`server list`, `server status`, `server test`).
  Errors, logs, hook output, MCP text and receipts name a target by its id only.
- **No new variable or argv token.** The entry fast paths, the Claude Code, Cursor and Codex
  registration classifiers, the Cursor live-process classifier and the configuration variable
  allowlist are untouched.
- **Propagation.** Claude Code hooks and MCP (no environment in the registration) learn the target
  from the selection file. Cursor hooks and MCP, and Codex external and cache MCP, use their
  stamped root when they were connected under explicit isolation, and the selection file
  otherwise. Bare-`PATH` Codex plugin hooks, agent-shell CLI calls and the startup-gate probe
  inherit the environment and otherwise read the selection file. The MCP bridge reads the
  selection once per process and never switches mid-session; hooks follow a new selection at
  once, so `server use` tells the owner to restart open sessions.

### 3. Four target kinds, a closed set

| Kind | Address | Notes |
|---|---|---|
| `local` | none; a named root on this machine | "Several local servers": each named root runs its own service, started on demand. |
| `local_port` | `https://127.0.0.1:<port>` or `https://[::1]:<port>` | The "localhost ports" kind. Same as `https`, but the origin must be loopback. |
| `ssh` | `ssh://[user@]host[:port]`, optional `--remote-root` (the server's isolated root) and `--remote-launcher` (absolute path of the server's `finishup`) | Owner-equivalent: the SSH login is the service owner. |
| `https` | `https://host[:port][/base]` with `--ca-file` or `--tls-pin sha256:…` | No userinfo, query or fragment. Plain `http` is refused. |

Every kind except `local` is a *remote kind* for consent, the zero-network refusal and the
workspace agent, including `local_port`: a loopback port can forward anywhere.

`finishup server add|list|use|status [--json]|test|remove|login|logout|connect|disconnect` manages
targets; each mutating command has its reverse (see *Reverse states*). `connect`, `disconnect` and
`test` dispatch through one small interface, `finishup.client.target_runtime.TargetRuntime`
(`ensure_ready(root)`, `stop(root)`, `probe(root) -> ProbeResult`). The foundation ships the
`local` implementation; each approach registers its remote implementations. Two server-host
commands are added: `finishup service start` (idempotent on-demand start plus status) and
`finishup service endpoint --json` (endpoint, absolute launcher, release, manifest digest, whether
the runtime directory is tied to the login session, and linger state).

### 4. Wire contract: control envelopes 2.10.0

The four control envelopes move to **2.10.0** together through the schema generator and the
resource ripple.

- **Claim or locator, never both.** The hello gains an optional `workspace_claim`
  `{schema_version: "1.0.0", identity_kind: "git_common_root" | "directory", digest:
  "sha256:<64 hex>"}`. A hello carries either it or `workspace_locator`; both is
  `workspace_binding_conflict`. The client computes the digest as `HMAC-SHA256(claim_salt,
  "yoetz/workspace-claim/v1\0" ‖ kind ‖ 0x00 ‖ canonical root)`, where the canonical root comes
  from the one shared rule in `adapters/workspace_root.py` and `claim_salt` is 32 random bytes
  kept per target in `target.json`. No path crosses the wire for a remote target.
- **The server derives, it does not trust.** The daemon commits the claim with the installation MAC
  under the new domain `yoetz/repository-claim/v1` over `kind ‖ digest`, producing
  `RepositoryPrivacyContext(identity_kind="client_claim", workspace_locator=None)`. The repository
  fence works on that commitment unchanged. The server never resolves a filesystem path for a
  claim-bound connection. The composition flag `ServiceComposition.refuse_workspace_locators`
  (off by default) lets a network edge close any hello that names a locator. A claim on a locked
  service binds no handle and no agent.
- **Agent declaration.** The hello gains an optional `workspace_agent` `{schema_version: "1.0.0",
  operations: [...], max_reply_bytes: <int>}`: this connection answers workspace calls for its
  claimed workspace.
- **Hello-result.** It gains a required `workspace_binding: "none" | "local_path" |
  "client_claim"` and an optional `workspace_handle` (`client:<16 hex>`, the first 16 hex of the
  claim commitment). Coverage decisions are derived from `workspace_binding`, never from the
  client's word.
- **New frames.** `workspace_call` (server→client, a new `oneOf` branch of the control result:
  `kind`, `protocol_version: "1.0"`, `call_id`, `service_instance_id`, `service_generation`,
  `operation`, `arguments`, `deadline_ms`) and `workspace_reply` (client→server, a new branch of
  the control request: `kind`, `protocol_version: "1.0"`, `call_id`, `outcome: "ok" |
  "unavailable" | "refused" | "failed"`, `result`, `reason`). The daemon sends server→client
  frames only to connections whose hello declared `workspace_agent`.
- **Claim-bound start.** On a claim-bound connection a `start.workspace_ref` must equal the
  connection's handle; an absolute path or another value is refused with
  `workspace_ref_not_portable`, and a handle sent on a connection without a claim is
  `workspace_binding_conflict`. Without this rule the reviewer's workspace root would be a server
  directory that happens to share the path. A start may omit `workspace_ref`, exactly as on a local
  connection: the task then records no workspace root, so nothing names a directory the server
  could read, and its task base and check-time change come only through the connection's claim
  (amended 2026-11-06: the real-environment run showed that refusing the omission broke the
  minimal `create` that works locally, because `workspace_ref` is admitted only with
  `external_ref`). The MCP bridge, the
  CLI and the SessionStart auto-attach rewrite an absolute `workspace_ref` to the handle before
  sending; a claim-bound connection with no handle sends nothing and answers
  `workspace_ref_not_portable` without naming a path.
- **What stays identical.** Framing (6 MiB frames, 1 MiB ordinary), all 32 methods and their
  bodies, `rpc_id` multiplexing and cancel, the client-kind gate and the client's exact-set check,
  and idempotency by `(installation_id, request_id)`. The YZH1 human-control and YZS1 secret
  channels are never forwarded or exposed beyond the service host.

### 5. The workspace agent and its eighteen operations

The server reaches the agent's working tree only through a client-side **workspace agent** that
answers bounded `workspace_call`s on a connection that declared it.

- **One catalog.** `ports/workspace_agent.py` is the single source of truth for each operation's
  name, argument codec, result codec, argument byte bound and result byte bound; every result
  stays under the 6 MiB frame. Bytes travel as base64 strings inside canonical JSON, and every
  codec round-trips exactly. The eighteen operations:
  - **Git:** `read_task_base`, `capture`, `capture_metadata`, `probe_requested_paths`,
    `count_change_lines`, `classify_undeclared_references`;
  - **reads:** `read_outside_inputs`, `snapshot_outside_inputs`, `read_declared_test`,
    `read_text_beneath`, `list_beneath`, `lstat_candidates`;
  - **observation:** `open_workspace` (returns an opaque remote handle), `load_check_policy`,
    `subject_state_capture`, `list_changed_paths`, `inspect`, `run_approved_check`.
- **Real adapters, existing fences.** The agent runs each operation against the same local
  adapters the service uses today, with all their fences: owner-UID checks, ignore rules, link
  refusal, object verification, size and time bounds, the approved-check sandbox. Two
  confinements are added: an operation's workspace must be the agent's own claimed root, and
  outside reads stay inside the admitted roots the server names and the existing exclusions. The
  server names the claimed workspace by its handle, never by its path: a read root or an exclusion
  may be the handle, and a declared-test location may be `client:<16 hex>/<relative>`; the agent
  maps them to its own root and refuses any other handle (`workspace_not_claimed`). An outside read
  never enters the claimed workspace through an outside root, nor the client's protected
  directories — its own FinishUP directories and the everyday installation's under both
  application names — whatever the server excludes. The agent refuses unknown operations and
  never runs a command that did not come from the repository's owner-approved
  `.finishup/checks.toml` (`check_not_approved`). HOME decisions are made by the agent on the
  client, never by the server's own home directory. Every non-`ok` reply carries one closed reason,
  and change capture's own reasons keep their exact `ChangeCaptureUnavailable` tokens.
- **The hub.** `service/workspace_hub.py` keeps live agent channels keyed by workspace handle; a
  connection that declared the agent registers at handshake and unregisters on close.
  `WorkspaceAgentHub.call(handle, operation, arguments, *, timeout_seconds)` sends a
  `workspace_call` under that session's write lock and awaits the correlated reply. With no channel
  it waits a bounded time for one — 5 seconds inside a live control call, 30 seconds for
  background work such as the detached review and recovered jobs — then raises the typed
  `WorkspaceAgentUnavailable`, whose reason is closed. Each call is bounded by the catalog's call
  deadline, a channel serves at most four calls at once, and pending argument bytes are bounded. A
  dropped channel fails its pending calls, except that a read whose channel dropped is sent once
  more to another live channel of the same claim (never an approved check, which may already have
  run); a pending call keeps its connection out of idle close; a reply on a connection that
  declared no agent closes it. The hub logs closed tokens only.
- **Routing.** `service/workspace_routing.py` wraps every workspace port and callable the service
  composes. An absolute-path workspace goes to the existing local adapter unchanged; a
  `client:<16 hex>` handle goes to the hub, and no local adapter is ever handed it. Callers that
  ran synchronously on the event loop — the reviewer broker's file reads, declared-test pinning,
  the observation verification steps and the post-run hash — move to a worker thread at their call
  sites, with no other behaviour change. A composition built without the hub fails a claim-bound
  read as unavailable (`hub_unavailable`), never as a local read. Several connections of one
  client may serve the same claim; a call naming a workspace an agent opened for observation
  verification that the answering agent does not know (`handle_unknown`: another connection now
  serves the claim, or the agent restarted) opens the workspace again on that agent, exactly as
  first opened, and is retried once.
- **The client side.** A connection to a remote root sends a `ClientWorkspaceBinding` (the claim,
  and optionally the agent) in place of its locator. `binding_for_active_root(locator, *,
  serve_workspace)` builds it from the active target's `claim_salt` and returns none for a local
  root, so every approach decides the same way. A client that serves an agent answers at most four
  workspace calls at once in worker threads; a client without one still rejects a `workspace_call`
  as a malformed frame, so a local connection is unchanged.
- **Observation over claims.** Observation verification and approved checks for a `client:`
  locator route through the hub, and the client drains the outbox and spool it captured for a
  remote root over its own claim-bound connection (`ClientObservationDrain`; which long-lived
  client process holds it is the approach's choice). `observation_ingest` is allowed on a
  claim-bound connection, and the server's sweeper reads only its own state directory, so it
  never touches a client root. Decision 12 says whose consent and keys govern such an ingest.
- **Local stays local.** Local targets never declare an agent, so the default path is unchanged.

### 6. Honest outcomes

- **Provenance.** Every piece of workspace evidence obtained through the hub is labelled
  `client_attested`. The fixed line is "Workspace evidence was read on the client machine by the
  FinishUP workspace agent and attested over the connection; the server did not read the
  repository itself." Two renderers carry it, and neither puts anything user-controlled beside it:
  - The service ends the text and markdown receipt of a claim-bound task (its session opened with
    a `client:` handle, a durable fact a replay reads alike) with a "Workspace evidence" section:
    the fixed line, then `Served by FinishUP service <service_instance_id> (connection:
    client_claim).` The stored receipt document and JSON receipts are unchanged.
  - The client ends every human status and receipt rendering of a claim-bound connection — CLI
    text, the MCP status and receipt text, the terminal interface's task views and receipt — with
    the fixed line (unless the rendered text already carries it) and `This client reached FinishUP
    service <service_instance_id> (transport: <token>).` The id is the one the hello-result named.
    The token is a closed set supplied by whoever builds the connection: `unix` (the default, a
    service's local control endpoint), `connector` (a local relay that carries the connection on),
    `ssh` (an SSH channel the client process opened) or `https` (HTTPS the client process speaks).
    The MCP structured result, CLI JSON output and a local connection's output are unchanged
    byte for byte.
- **Typed gaps when no agent is reachable.** An operation that ends `workspace_agent_unavailable`
  fires the existing gap for what it would have read, and the new reason
  `workspace_agent_unavailable` joins the check-time change unavailable reasons
  (`check_time_change_unavailable_workspace_agent_unavailable`, with its own fixed sentence). A
  review whose file read finds the agent gone ends `workspace_agent_unavailable` and records an
  unavailable result of failure class `transport`, never a judgment. A missing reply is never a
  pass, and an unknown change state fails closed for no-material-work. A refused operation is
  `workspace_agent_refused`.
- **No silent fallback.** A remote root never spawns or supersedes a local service and never
  falls back to the ambient one; a service refuses to run in a root whose target is remote
  (`target_root_is_remote`). Writes fail closed and stay retryable through the existing
  reconnect, operation-status probe and `request_id` replay. There is no local write queue: a
  queued write would let a receipt describe work the server never recorded.
- **No replay across targets.** Idempotency is scoped by installation (ADR-002 decision 4). A
  `request_id` sent to one target is never replayed against another.
- **No user-controlled text.** Target names, hosts, addresses and paths never appear in errors,
  logs, hook output, MCP text or receipts. Remedy text lives once in `protocol/recovery.py`, and
  local remedy text keeps its exact bytes.

### 7. Credentials are pluggable and never on an agent-facing surface

- `finishup.client.credentials.CredentialSource` is the interface, so OAuth can replace an API key
  later. `KeyringOrFileCredential` stores the key in the OS credential store under service
  `yoetz.server-credential.v1`, account = target id, and falls back to the existing owner-only
  file store at `<target root>/config/credential` where no platform store is usable.
- `server login` reads the key from a masked prompt or, for automation, from a `--key-file`
  (owner-only, read once); `server logout` deletes it; `server remove` deletes it with the root.
- The credential never appears in argv, the environment, `target.json`, a host registration, a
  log, hook output, an MCP frame or JSON output.
- SSH keys, `ssh-agent` and `known_hosts` stay with OpenSSH. FinishUP stores no SSH key, never asks
  for a password, and runs OpenSSH with `BatchMode=yes` and `StrictHostKeyChecking=yes`.
- Which client process reads the credential is part of each approach's topology. Any process
  running as the same user can read the credential store or the file, as it can read today's
  auto-unlock custody; the claim is that no surface an agent reaches reveals or switches it.

### 8. Consent per remote target, on the trusted console

- `server add` and `server use` for a remote kind need the trusted foreground console, a versioned
  disclosure and the owner typing the target name. `target.json` records `authorized_at` and
  `disclosure_version`; a new disclosure version requires a fresh confirmation before use.
- The disclosure says what leaves the machine: task statements, published work, evidence, check,
  respond and receipt traffic, the workspace claim (a keyed digest, not a path), observation rows,
  and the workspace evidence the server asks the workspace agent for — the task base and
  check-time change, requested-output facts, reviewer file reads, task inputs, declared tests,
  observation inspection and approved-check results, each within its existing bound. It says what
  does not leave: the workspace's absolute path, credentials, and the human-control and secret
  channels. It says that the server's own privacy policy decides any AI-powered review egress from
  there.
- Agents cannot select or add a remote target: there is no MCP tool for it, and the CLI refuses
  without a trusted console.
- The hop is refused in the zero-network state: when the local service's effective policy is
  zero-network, and, when no local service exists, while the configuration bootstrap leaves
  `network_egress_permitted` false. The client re-checks before it opens the hop.
- **Honest limit.** This is a trusted-console decision, not a vault-reauthenticated ceremony,
  because a client machine may have no vault.

### 9. Scopes, not self-declared client kinds, bound a key

An HTTPS or `local_port` key carries a scope, `agent` or `operator`, that the server-side edge
enforces as a method allow-list; the daemon's client-kind gate stays as a second layer.

| Scope | Methods |
|---|---|
| `agent` | The six workflow methods, `service_status`, and `observation_ingest` on a claim-bound connection: what hooks, the MCP bridge, the closure gate and the startup-gate probe use. |
| `operator` | `agent` plus `project`, `review`, `import_codex_jsonl`, `observation_status`, the read and tighten privacy methods (`privacy_get_setup`, `privacy_get_effective`, `privacy_pending_list`, `privacy_receipts_list`, `privacy_receipts_get`, `privacy_propose_policy`, `privacy_tighten_policy`) and `service_lock`. |
| Never over HTTPS | `service_stop`; `backup_*`, `restore_*`, `migrate_*` and `integration_*` (they name server paths); `observation_pause`, `observation_resume`, `observation_revoke`; the human-control and secret channels. |

A hello that carries `workspace_locator` is refused at an HTTPS edge. The owner receipt view needs
a ceremony bound to its own connection on the service host, so a remote `receipt` returns the
ordinary view. An SSH target is owner-equivalent and allows every method, as locally; scoped SSH
through a forced command is later work.

### 10. Version lockstep

The client and the server run the same release. The handshake already requires an exact
`schema_manifest_digest` match; a mismatch on a remote target is `remote_incompatible`, whose text
names both releases (release versions are not user-controlled). A remote service is never
superseded by a client. A compatibility window is a later decision.

### 11. What stays on the server host

Vault setup, unlock and passphrase changes, provider and AI-powered review configuration, privacy
ceremonies, elevated bootstrap, backup, restore and migrate run on the server host. Observation
store administration (`observe …`, `/observe`) acts on the active root's own observation store,
which on a remote target is the client's store and its authority (decision 12), so it runs on the
client. Over SSH, `finishup service start|stop|restart|status|lock|unlock|diagnostics`
can run there through `ssh -t`, whose remote pseudo-terminal passes the trusted-console check.
On the client every `server_host` command is refused with `requires_server_host`, whose remedy
says to run it on the server host (through `ssh -t` for an SSH target; by the server's operator for
an HTTPS target).

### 12. Observation on a remote target

For a remote target the hooks run on the client, the owner granted observation consent there, and
the rows were captured there. The server holds none of it and must not borrow it.

- **The client is the authority.** The client's observation store under the target root (consent,
  content-capture profiles, selection, approved-check policy trust, the observation key that
  computes every session and workspace commitment), its lifecycle mappings and its outbox and
  spool stay on the client. The `observe` commands and `/observe` administer that store, so they
  are labelled `any`. The observation key never leaves the client.
- **Client attestation.** On a claim-bound connection each `observation_ingest` body carries
  `client_attestation` (control-request 2.10.0): `schema_version`, `consent`
  (`active`, `paused` or `revoked`), `granted_at`, `content_capture_profiles`,
  `authority_generation` (the client's content-capture fence), `check_policy_digest` (the one
  policy digest the owner trusted there, or null) and `route` (the FinishUP task, session and
  writer the client's mapping names for the host session, or null). The client builds it from its
  own store and mapping when it sends the row (hook pass, `observe drain` and the background
  drain alike), and replaces any workspace-locator content with the connection's handle, so no
  path leaves the client.
- **Accepted as `client_attested`, never verified.** The server cannot recompute a commitment made
  under the client's key, so on a claim-bound connection it accepts the envelope's session
  commitment and the attested consent, profiles, fence, trust and route as client-attested. It
  records them keyed to the claim in a separate claim store, `<state dir>/observation-claims/<16
  hex of the handle>/` (an ordinary observation store and lifecycle-mapping directory holding only
  that claim's workspace, under a key the server generates), and runs the unchanged observation
  coordinator over it with the claim's handle as the workspace. Its own observation store,
  mappings and consent are never read or written for a claim.
- **What the server still decides.** Only the connection's own claim is touched. The attested
  route must name a task whose route was opened on a connection carrying the same claim (its
  route commitment is the claim commitment); any other route is refused with `consent_missing`
  before anything is written. The server's own observation switch and vault gate apply.
  Verification opens the claimed workspace by its handle through the workspace agent (decision 5)
  and never through a stored locator.
- **Refusals keep their closed reasons.** A claim-bound ingest without an attestation is refused
  with `consent_missing`, before anything is read or written; an attestation without a route is
  `mapping_missing` (retryable, as locally); a paused or revoked consent is refused exactly as a
  local one is. When too many claims are busy at once the row is refused `service_unavailable`
  (retryable). An attestation on a connection that carries no claim is a malformed request
  (`frame_invalid`). A locator-bound or unbound connection keeps today's checks byte for byte:
  commitment against the server's key, consent and mapping from the server's own store.
- **Consent changes travel with the next row.** A pause, resume or revoke on the client is mirrored
  into the claim store when the next row arrives; a revoke runs the service's own revocation for
  that claim (task stores deactivate their locator and trust rows), and later rows are refused.
  Rows the server already accepted stay accepted, as for a local revoke.
- **Honest receipts.** Text and markdown receipts of a claim-bound task whose coverage includes
  hook-observed evidence add one fixed line after the workspace-evidence line: "Hook observations
  were captured on the client machine under its own observation consent and delivered over the
  connection; the server did not verify that consent or the session commitments." Logs carry the
  `client_attested` label and closed tokens only.
- **Limits.** Advice the service prepares for hooks to deliver stays in the claim store and does
  not yet reach a remote client's hooks. After a server restart a claim's pending verification
  resumes when that claim delivers its next row. The server's check barrier reconciles only its
  own store's capture handoffs, and a claim-bound `check` that asks to await observations reports
  that wait `unavailable`: the rows wait in the client's outbox, which the server cannot read.

## Topology (approach-specific)

### Approach A — edge relay: a connector per target, a gateway per HTTPS server

Agent-facing processes do not change. Every hook, MCP bridge, CLI and terminal process keeps
dialling `<root>/run/control.sock` with the same owner-only checks and peer-UID authentication. For
a remote target root that endpoint is served by a vault-less **connector** on the client machine;
the server's service still never opens a network socket.

```
SSH (owner-equivalent)
  client host                                                    server host (same owner)
  hook/MCP/CLI/TUI ─AF_UNIX─► <troot>/run/control.sock
                              finishup connector (no vault) ─AF_UNIX─► <troot>/run/upstream.sock
                                (ssh -M -S <troot>/run/m -L upstream.sock:<remote endpoint>)
                              ════ one warm SSH connection, one channel per client connection ═══►
                                                               sshd child (owner) ─AF_UNIX─► control.sock ─► service

HTTPS and local_port
  hook/MCP/CLI/TUI ─AF_UNIX─► <troot>/run/control.sock
                              finishup connector (holds the API key)
                              ════ HTTPS binding v1: sessions, calls, long-polls ════►
                                                               finishup service gateway (same UID; key, scope)
                                                                 └─AF_UNIX─► control.sock ─► service

Both kinds: workspace_call frames flow server → client and workspace_reply frames client → server
through the same relay; human-control and secret channels never leave the server host.
```

- **Connector** (`finishup.client.connector`; `finishup connector run --root <troot>`, hidden,
  `client_only`). `service.client` starts it on demand for a remote root instead of
  `service run`, and `finishup server connect` starts it explicitly; it never supersedes anything.
  A client replaces a running connector (by its stamped pid) only when an older release of this
  client started it; a newer one is kept, since it serves the upgraded clients and also relays a
  process that predates the upgrade. It takes the singleton flock `<troot>/state/connector.lock`, stamped with its pid, release and
  schema-manifest digest; binds `run/control.sock` through the existing Unix-socket listener,
  clearing a stale endpoint only while it holds that lock; runs with a scrubbed environment (no
  FinishUP variable and nothing secret-shaped; `SSH_AUTH_SOCK` is kept so OpenSSH can use the
  owner's agent, and `DBUS_SESSION_BUS_ADDRESS` so an HTTPS target's key stored in a Linux
  desktop's Secret Service can be read); refuses any hello that names a `workspace_locator`; and exits after 15 idle
  minutes. It writes `<troot>/state/connector-status.json` (`yoetz.connector-status/1`:
  `generation`, `phase` of `starting|ready|unavailable|stopped`, a closed `reason`, a
  `correlation_id`, `pid`, `started_at`). A client whose connection the connector accepted and
  closed reads that status and raises `service_unavailable` with the remote phase as `phase`; the
  MCP availability latch keys on the status generation, which moves on every change of phase or
  reason, so a repaired connection clears it.
- **SSH.** One OpenSSH master per target with the fixed, secret-free argv `-M -S <troot>/run/m -N
  -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes -o
  StreamLocalBindMask=0177 -o StreamLocalBindUnlink=yes -o ServerAliveInterval=15 -o
  ServerAliveCountMax=3 -p <port> -L <troot>/run/upstream.sock:<remote endpoint> <[user@]host>`.
  Each local connection gets its own channel and an unparsed byte pump; only the first frame (the
  hello) is read, to refuse a locator and to note a claim. When sshd cannot reach the server's
  endpoint on a client's connection (an idle-stopped service), the connector runs the server's
  own `<remote launcher> service start` once over the master, pinned to the remote root, and
  retries; the connector's own background agents never start it, so a service the owner stopped
  stays stopped until a client connects. `server add
  ssh://…` records the endpoint and an absolute launcher from one interactive `ssh … finishup
  service endpoint --json`, in which OpenSSH itself asks the owner to confirm a new host key. The
  socket-path bound counts OpenSSH's 17-byte temporary suffix on the master path.
- **HTTPS and `local_port`.** Each local connection is one gateway session of the HTTPS binding
  v1 (see `INTERFACES.md`). A call is never posted twice: after an ambiguous failure the connector
  only polls its result. Polls, cancels and workspace replies, which are safe to repeat, are retried
  after a transient failure (up to three in a row), so one network blip does not end a relayed
  connection and every call on it. When the hello declared a workspace agent, server frames arrive through
  the `GET …/frames` long-poll and replies go out with `POST …/frames`. TLS uses the target's CA
  file, or its `sha256:` pin of the leaf certificate, checked right after the handshake and before
  any request byte. Only the connector reads the API key, and it rereads it after a refusal so a
  key rotated with `server login` takes effect without a restart.
- **Gateway** (`finishup.gateway`; `finishup service gateway run --listen H:P (--tls-cert F
  --tls-key F | --behind-proxy)` and `service gateway key create|list|revoke`, all `server_host`).
  A same-user process with no vault, storage or policy authority: it may import SHARED modules and
  `service.client` only, and `cli/gateway.py` is the one client module allowed to launch it. Keys
  are `fuk_<12 hex id>_<43 base64url secret>`, shown once on the trusted console or written to a
  new owner-only file, and kept only as a salted `sha256` in `<state>/gateway/keys.json`
  (`yoetz.gateway-keys/1`), compared in constant time; expiry and rotation are supported, and a
  revoked key fails its next request and its sessions close. Each session holds one control
  connection to the daemon (started on demand through `service.client.ensure_service_running()`,
  no handshake of its own) and forwards the client's hello byte for byte. It refuses `Origin`
  headers and locator hellos, enforces the key's scope (decision 9) by answering an out-of-scope
  call with a synthesized `method_forbidden` control-result that is never forwarded, keeps results
  per `(sid, rpc_id)` until fetched and readable for 60 seconds after (8 MiB per session), expires
  a session after 120 seconds idle, holds at most 64 per key, and stops with `gateway_stale` when
  the daemon answers with another release's manifest. `--behind-proxy` serves plain HTTP on a
  loopback address only. There is no access log; audit lines carry the key id, route, method,
  status, closed reason and correlation id only. v1 has one principal (`owner`): claims pass
  unchanged, so the owner's SSH and HTTPS clients reach the same tasks; per-principal claim
  namespaces wait for multi-key hosting.
- **Binding at the connect seam.** `service.client` binds every connection to a remote root:
  `connect_service` and `connect_service_on_demand` turn the caller's locator into the target's
  claim (`binding_for_active_root`), never send the path, mark the connection's transport
  `connector`, and start the connector when none answers (the plain connect too: it is
  client-owned and vault-less). Processes whose calls run workspace work while they are live
  pass `serve_workspace=True` and answer the server's workspace calls on their own connection:
  the CLI (`build_service_client`, which the menu and the terminal interface also use) and the
  MCP bridge. Hooks stay claim-only, so their observation ingest is attested and their `start`
  sends the handle. A workspace the shared root rule cannot resolve is not claimed, and a remote
  connection with no claim refuses an absolute `workspace_ref` instead of sending it.
- **Workspace agent location.** Per connection, the client process's own `ServiceClient` answers
  through the relay. For work that outlives the call, the connector keeps one long-lived agent
  connection per workspace whose claim it relayed, for 15 minutes after that workspace's last
  hello (`open_background_agent(root, claim, dial)`). It learns which local workspace a claim
  stands for from the root's owner-only claimed-workspace index (`<troot>/state/claimed-workspaces/
  <64 hex>.json`, `yoetz.claimed-workspace/1`), which the connecting process writes and which
  never leaves the machine; it derives the claim again from the recorded workspace with the
  target's salt and serves it only when the two match. The agent connection runs the real
  `WorkspaceAgentHandler`, is relayed by the connector itself over a socket pair (so it neither
  keeps the connector from idling out nor renews its own lease), and reconnects whenever the
  service ends it. Over the same connection the connector delivers what the client's hooks
  captured for that workspace (the observation outbox and spool, `ClientObservationDrain`, each
  row attested by the client's own store) every 30 seconds and once more as it stops; hooks
  still drain once per pass. Several connections may serve one claim (a CLI command, the MCP
  bridge, the connector); the service sends each call to the newest, and a workspace an agent
  opened for observation verification and another agent does not know (`handle_unknown`) is
  opened again on the answering agent and the call retried once.
- **Remote remedies on every surface.** A remote target's failure is named by its closed phase
  and its ADR-030 directive on the CLI, the menu, setup's next steps, the MCP bridge, the hook
  contexts and the terminal interface: every `service_unavailable` from a remote root carries a
  remote phase (the connector's recorded one, or `remote_unreachable` when it recorded none,
  including a connection lost mid-session), and a locked vault on the remote server is
  `remote_vault_unlock_required`. None of them names a local `service run` or `service unlock`,
  a host or a target name; a local root keeps its exact text.
- **Reverse states.** `server connect` / `server disconnect` (the stamped pid only, then `ssh -O
  exit` for a master that outlived it; never by pattern) and the 15-minute idle exit;
  `service gateway key create` / `key revoke`; `service gateway run` / Ctrl-C or the supervisor.
  `server status` and `server test` show the connector's state; `key list` shows the keys.
- **Modules.** `finishup.client.connector` (relay, leases, drain), `connector_status`,
  `connector_runtime`, `connector_agent` (the background agent), `claimed_workspaces` (the index),
  `ssh_upstream`, `https_upstream`; `finishup.gateway` and `finishup.protocol.rest_binding`;
  `finishup.cli.remote_remedy` (one place for every surface's remote remedy).
- **Why this shape.** The credential and the warm connection live in one process per target, so a
  short-lived hook pays a local Unix connect plus the round trips, never a TLS or SSH handshake,
  and `httpx` never enters the hook import path. The cost is one supervised client process per
  target and, for HTTPS, one gateway process on the server.


## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| `server add NAME …` | `server remove NAME [--select-local]` (disconnects, deletes the credential, disposes of the root; refuses the selected target unless `--select-local`) | `server list` |
| `server use NAME` | `server use local` (removes the selection file; ambient resolution returns with no residue) | `server status` (names the deciding source) |
| `server login NAME` | `server logout NAME` | `server status` (credential present or absent, never the value) |
| `server connect [NAME]` | `server disconnect [NAME]` (stops only what that root's runtime stamped; never by name or pattern) | `server status`, `server test` |
| Server-side key or edge setup | its revoke or teardown, named in the topology section | the server's own key listing |

Deleting a target's root removes every client-side artifact of that target. The ambient
installation is never touched by a target operation.

## Consequences

- With no selection file, local behaviour is unchanged. The only local deltas are the new commands
  and the control-schema version and digest, which every envelope bump already moves.
- Remote evidence is `client_attested`: the ADR-031 fences run on the client, inside the workspace
  agent, and the server cannot check them independently. Receipts say so in one fixed line.
- Remote round trips cost hook budget. No budget is relaxed; `server test` measures the round trip
  against the hook budgets and warns when a required startup gate would likely deny.
- Upgrades are lockstep: every refusal names both releases.
- A Linux server whose runtime directory belongs to the login session loses its sockets at the
  last logout; `service endpoint --json` reports this, and the server needs linger or its own
  isolated root.
- A human-passphrase vault on a server stays locked after a restart until the owner unlocks it on
  the server; auto-unlock custody (ADR-008, 2026-10-19) is the unattended path.
- Out of scope: multi-user or team hosting; a FinishUP-operated cloud; ledger sync or migration
  between targets; an offline write queue; a plain-TCP control channel; unlock, consent or the
  owner view over the network; MCP over HTTP to hosts; native launchd or systemd installers;
  native Windows (WSL 2 follows Linux); a per-repository server file, which would let a repository
  redirect its own ledger traffic.

## Alternatives considered

**The three ways of doing the separation.** Each is a complete pull request on top of the shared
decisions above; the maintainer chooses one. Its own topology section replaces the marker above.

| Approach | Shape | Strengths | Costs |
|---|---|---|---|
| A — edge relay | Clients keep dialling the target root's Unix endpoint. A vault-less per-target connector behind it relays to the server: OpenSSH stream-local forwarding for SSH, and an HTTPS binding of the control frames to a same-user gateway on the server for HTTPS and localhost ports. | Agent-facing processes and registrations are untouched; one process holds the credential; connections stay warm across short-lived hooks. | A client-side process to supervise; a gateway process on the server. |
| B — client SDK, direct dial | Each client process selects a transport from the target record — Unix, SSH (`ssh -W` over a persistent master) or HTTPS against the same gateway as A — in place of the hardcoded Unix connect. | No local relay process; transports are in-process. | The credential is read by each client process (an ADR-008 amendment); hooks load a transport lazily; each process opens its own channel. |
| C — server-native network API | The daemon gets an optional network listener with a resource-shaped REST API; a dedicated client-side agent process long-polls for workspace calls; SSH tunnels HTTP to that listener. | One network protocol for every remote kind; no gateway or connector process. | TLS and HTTP parsing move into the process that holds the vault, which amends ADR-008 invariant 6 at its root; a second, resource-shaped public API to keep. |

**Rejected.**

- *The local service forwards (#946).* It needs a full local vault and ledger just to proxy, and
  gives no real split.
- *The server offers MCP over HTTP to hosts.* It loses the bridge↔hook records, Cursor roots
  (ADR-010), the availability latch, the publish guard and timeout recovery, and host support for
  remote MCP with headers is undocumented.
- *Remote targets as a preview with closed coverage gaps for every workspace read.* The maintainer
  required full plug-and-play instead.
- *Ship workspace evidence ahead of the call.* Infeasible for reviewer reads, where the model picks
  the paths, and for work that runs after the call returns.
- *A sixth ADR-009 channel under service policy.* It does not fit a client machine that has no
  local service.
- *A new environment variable or argv token for the target.* It breaks the registration
  classifiers, the entry fast paths and the configuration allowlist, and misses bare-`PATH` Codex
  hooks and agent-shell CLI calls.
- *A sticky per-session target record for hooks.* Another store on the hook hot path, and it can
  drift from the bridge.
- *A per-repository server file.* A repository could redirect its own ledger traffic.

## Founder questions answered by the maintainer (2026-11-05)

1. **How complete must a remote target be?** Full plug and play: check-time change capture,
   reviewer file reads, task inputs, approved checks and observation work end to end through the
   workspace agent. Gaps appear only as honest, typed outcomes when no agent is reachable.
2. **What does "several local servers on different ports" mean?** Both named local roots, each
   with its own service, and HTTPS servers reached on localhost ports (the `local_port` kind).
3. **How is the separation delivered?** Three pull requests, one per way of doing the separation,
   each complete and mergeable on its own; every decision other than the topology is identical in
   all three.

The "REST API" question is answered by that comparison: approaches A and B bind the existing
control frames to HTTPS, and approach C offers a resource-shaped API. The remaining proposals of
this ADR — the classification of the network hop (decision 8), strict route on remote targets
(ADR-018 amendment), SSH as owner-equivalent (decision 9) and version lockstep (decision 10) —
stand as Proposed until the maintainer reviews the chosen pull request.
