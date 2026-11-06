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
`target_runtime`, `workspace_claim`, `workspace_agent`), `src/finishup/cli/server.py`,
`active_root()` and the `selection` binding in `src/finishup/config/paths.py`,
`src/finishup/ports/workspace_agent.py`, `src/finishup/adapters/workspace_root.py`,
`src/finishup/service/workspace_hub.py`, `src/finishup/service/workspace_routing.py`, the claim
path of `src/finishup/service/control_protocol.py` and `src/finishup/service/daemon.py`, the
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
  claim-bound connection. A server-side option lets a network edge refuse locators entirely.
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
- **Claim-bound start.** On a claim-bound connection `start.workspace_ref` must equal the
  connection's handle; an absolute path is refused with `workspace_ref_not_portable`. Without this
  rule the reviewer's workspace root would be a server directory that happens to share the path.
  The MCP bridge and the CLI rewrite an absolute `workspace_ref` to the handle before sending.
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
  agent refuses unknown operations and never runs a command that did not come from the
  repository's owner-approved `.finishup/checks.toml`. HOME decisions are made by the agent on the
  client, never by the server's own home directory. Failure reasons map to the existing
  `ChangeCaptureUnavailable` reasons where one exists.
- **The hub.** `service/workspace_hub.py` keeps live agent channels keyed by workspace handle; a
  connection that declared the agent registers at handshake and unregisters on close.
  `WorkspaceAgentHub.call(handle, operation, arguments, deadline)` sends a `workspace_call` under
  that session's write lock and awaits the correlated reply. With no channel it waits a bounded
  time for one — 5 seconds inside a live call, 30 seconds for background work — then raises the
  typed `WorkspaceAgentUnavailable`. A dropped channel fails its pending calls. Calls per channel
  and bytes per reply are bounded, and the hub logs closed tokens only.
- **Routing.** `service/workspace_routing.py` wraps every workspace port and callable the service
  composes. An absolute-path workspace goes to the existing local adapter unchanged; a
  `client:<16 hex>` handle goes to the hub. Callers that ran synchronously on the event loop move
  to a worker thread at their call sites, with no other behaviour change.
- **Observation over claims.** `observation_ingest` is allowed on a claim-bound connection; the
  server reads the locator as the handle and runs observation verification and approved checks
  through the hub. The client drains the outbox and spool it captured for a remote root, and the
  server's sweeper ignores roots it does not own.
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
  (`check_time_change_unavailable_workspace_agent_unavailable`). A missing reply is never a pass,
  and an unknown change state fails closed for no-material-work. A refused operation is
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
ceremonies, elevated bootstrap, observation store administration, backup, restore and migrate run
on the server host. Over SSH, `finishup service start|stop|restart|status|lock|unlock|diagnostics`
can run there through `ssh -t`, whose remote pseudo-terminal passes the trusted-console check.
On the client every `server_host` command is refused with `requires_server_host`, whose remedy
says to run it on the server host (through `ssh -t` for an SSH target; by the server's operator for
an HTTPS target).

## Topology (approach-specific)

<!-- APPROACH-TOPOLOGY -->

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
