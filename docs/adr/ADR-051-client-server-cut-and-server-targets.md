# ADR-051 — Client/server cut line, server targets and the workspace agent

**Status:** Proposed for [issue #1308](https://github.com/orgFinishUP/finishup/issues/1308), which
scopes the original request in [issue #903](https://github.com/orgFinishUP/finishup/issues/903).
Design gates: protocol (control envelopes 2.10.0 and the workspace frames), privacy/egress (the
FinishUP server hop), storage layout (target roots and the selection file), release/packaging
(client and edge processes, version lockstep) and the `OPEN_QUESTIONS` flip. Maintainer
acknowledgement: on 2026-11-05 the maintainer explicitly requested this scoped work — separate the
FinishUP client from the server inside this repository; let a client use the local server, several
local servers including ones reached on localhost ports, a server on another machine over SSH and
web-hosted servers over HTTPS with an address and an API key; deliver three complete pull requests,
one per way of doing the separation, each "full, plug and play". Under the intake rule in
`AGENTS.md`, that explicit request is the design-gate acknowledgement for this scope; it is
recorded on #1308 and in each pull request body. The acknowledgement grants no runtime,
credential, disclosure or destructive-action authority.
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
  remote target is active, with `requires_server_host`. It fails closed when the active root
  resolves but its `target.json` cannot be read (unsafe mode, or a record it cannot parse): the
  command is refused with the record's own reason (`target_root_unsafe`,
  `target_record_invalid`), because such a root may be a remote target's. A test walks the command
  tree and the interface's command registry and fails on an unlabelled command.
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
  path beneath the root inside the AF_UNIX limit even under `~/Library/Application Support/`.
  Creating a target refuses a root whose longest socket would not fit (`target_root_too_long`),
  against the platform's usable `sun_path` bytes (107 on Linux, 103 on Darwin), the one bound
  `instance_root_too_long` also uses: a `local` root against the service's
  `run/secret-ingress.sock`, a remote root against the longest socket a client binds there,
  OpenSSH's ControlMaster `run/m` under its 17-byte temporary suffix. A
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
- **A spawned service serves its spawner's root.** A client that starts its service on demand
  forwards the root it resolved: a resolved root in the isolation variable, as before, and the
  everyday installation as one hidden internal `service run --ambient-root` flag, which makes the
  service read no selection (`config.paths.ignore_server_selection`, applied while options are
  parsed, before the server-host guard). A bridge that resolved the everyday installation and
  later restarts its service therefore never starts a target that a newer selection names. The
  flag names no target and appears in no registration, launch line or classifier.
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
workspace agent, including `local_port`: a loopback port can forward anywhere. `server add NAME
https://127.0.0.1:<port>` and `https://[::1]:<port>` record `local_port`, as does `--port <port>`
(which records `127.0.0.1`); any other HTTPS address, `localhost` included, is `https`.

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
  "sha256:<64 hex>", worktree: "sha256:<64 hex>"}`. A hello carries either it or
  `workspace_locator`; both is `workspace_binding_conflict`. The client computes the digest as
  `HMAC-SHA256(claim_salt, "yoetz/workspace-claim/v1\0" ‖ kind ‖ 0x00 ‖ canonical root)`, where
  the canonical root comes from the one shared rule in `adapters/workspace_root.py` and
  `claim_salt` is 32 random bytes kept per target in `target.json`. Every linked worktree of one
  repository therefore claims the same digest. The `worktree` digest tells them apart:
  `HMAC-SHA256(claim_salt, "yoetz/workspace-worktree/v1\0" ‖ worktree top level)`, over the one
  directory the connection's agent serves (its locator). No path crosses the wire for a remote
  target. (Amended 2026-11-06, before 2.10.0 shipped: the first cut had no `worktree`, so linked
  worktrees shared one handle and one worktree's agent could answer another's task.)
- **The server derives, it does not trust.** The daemon commits the claim with the installation MAC
  under the new domain `yoetz/repository-claim/v1` over `kind ‖ digest`, producing
  `RepositoryPrivacyContext(identity_kind="client_claim", workspace_locator=None,
  workspace_handle=...)`. The repository fence, the privacy authority and the consent scope work
  on that commitment unchanged, so linked worktrees share a commitment, as they do locally. The server never resolves a filesystem path for a
  claim-bound connection. The composition flag `ServiceComposition.refuse_workspace_locators`
  (off by default) lets a network edge close any hello that names a locator. A claim on a locked
  service binds no handle and no agent. Because a claim-bound connection's handle is fixed by its
  hello, the claim hello re-opens a soft lock (idle, session lock, suspend) exactly as the
  connection's first request would; a hard lock stays locked, and a locator hello never unlocks
  (amended 2026-11-06 after the real-environment runs). A direct-dial client (approach B) never
  keeps a claim-bound connection the server answered without a handle: it closes it and reports
  the server's own state, `vault_locked` (retryable exactly when the service would call it so) for
  a locked vault, `remote_service_not_running` while it starts or stops, and `remote_incompatible`
  for a ready service that keyed nothing.
- **Agent declaration.** The hello gains an optional `workspace_agent` `{schema_version: "1.0.0",
  operations: [...], max_reply_bytes: <int>}`: this connection answers workspace calls for its
  claimed workspace.
- **Hello-result.** It gains a required `workspace_binding: "none" | "local_path" |
  "client_claim"` (absent only from the manifest-mismatch answer, which keeps the frozen pre-2.10
  shape) and an optional `workspace_handle`, carried only with `client_claim` (`client:<16 hex>`,
  the first 16 hex of `SHA-256("yoetz/workspace-handle/v1\0" ‖ claim commitment ‖ 0x00 ‖
  worktree digest)`). Worktrees
  share a commitment, not a handle: a task records its own worktree's handle as its
  `workspace_ref`, so every later read of that task, in a live call or in background work after a
  reconnect, reaches only that worktree's agent. Coverage decisions are derived from
  `workspace_binding`, never from the client's word.
- **New frames.** `workspace_call` (server→client, a new `oneOf` branch of the control result:
  `kind`, `protocol_version: "1.0"`, `call_id`, `service_instance_id`, `service_generation`,
  `operation`, `arguments`, `deadline_ms`) and `workspace_reply` (client→server, a new branch of
  the control request: `kind`, `protocol_version: "1.0"`, `call_id`, `outcome: "ok" |
  "unavailable" | "refused" | "failed"`, `result`, `reason`). The daemon sends server→client
  frames only to connections whose hello declared `workspace_agent`.
- **Claim-bound start.** On a claim-bound connection a `start` that names a workspace must name
  the connection's handle; an absolute path or any other value is refused with
  `workspace_ref_not_portable`, and a handle sent on a connection without a claim is
  `workspace_binding_conflict`. Without this rule the reviewer's workspace root would be a server
  directory that happens to share the path. The MCP bridge, the CLI and the SessionStart
  auto-attach rewrite an absolute `workspace_ref` to the handle before sending. A start may also
  name no workspace, in every mode where it may on one computer (there it reads the connection's
  own locator path; `workspace_ref` and `external_ref` are both or neither, so a client cannot add
  the handle alone). The claim names that same workspace, so any session such a start opens — a
  create, a parent-registered child, a child attached by its attach handle — records the
  connection's handle in its opening event only, and its receipts carry the client-attested block;
  the request's identity is unchanged. (Amended 2026-11-06, before release: the first cut refused
  such a start, and the real-environment runs of all three approaches failed on the first MCP
  `start`.) A claim-bound connection with no handle exists only because the server's vault was not
  ready at hello: it sends no start, whatever its `workspace_ref`, and no observation row (never a
  path) and answers the retryable `vault_locked`, so the client replaces the connection and the
  first call after the unlock gets a handle.
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
  confinements are added: an operation's workspace must be the agent's own claimed root, and an
  outside read goes only where this client's owner admitted it (next item) and never past the
  existing exclusions. The server names the claimed workspace by its handle, never by its path: a
  read root or an exclusion may be the handle, and a declared-test location may be
  `client:<16 hex>/<relative>`; the agent maps them to its own root and refuses any other handle
  (`workspace_not_claimed`). No agent and no claim is ever made for the filesystem root (`/`), as
  hooks and MCP roots never bind it: a CLI or bridge started there names no workspace. An outside
  read never enters the claimed workspace through an outside root, nor the client's protected
  directories — its own FinishUP directories and the everyday installation's under both
  application names — whatever the server excludes. Where a local service's own caller narrowed
  an operation, the agent narrows it itself: `inspect` excerpts only the workspace's own changed
  paths (never an ignored, unchanged, `.git` or credential-named file), and `lstat_candidates`
  answers only for a candidate the local outside-input rule would look at (no hidden,
  credential-named or system path, and beneath a path an owner may admit). The agent refuses unknown operations and
  never runs a command that did not come from the repository's owner-approved
  `.finishup/checks.toml` (`check_not_approved`): the policy must approve the exact argv, and the
  owner must have trusted that policy's raw digest in this client's own observation store, checked
  on every call, so a misbehaving server cannot run an untrusted or edited policy. HOME decisions are made by the agent on the
  client, never by the server's own home directory. Every non-`ok` reply carries one closed reason,
  and change capture's own reasons keep their exact `ChangeCaptureUnavailable` tokens.
- **Outside admission is the client's own fact** (amended 2026-11-06 by maintainer decision, after
  the review of the three pull requests found that the agent admitted any root the server named
  by its shape alone). Which folders outside the claimed worktree a server may read is recorded on
  the client, per server target, as approved-check trust is (decision 12). `finishup server
  folders add NAME FOLDER` needs the trusted foreground console and the owner typing the target
  name; it records FOLDER canonicalized by the local service's own input-root rule (an existing
  directory named by its absolute, normalized, link-free path; never hidden or a system tree),
  and never the home directory, a folder that holds it, or one in its private trees. `server
  folders remove NAME FOLDER|--all` is the way out and takes effect at the next call; `server
  folders list NAME` and `server status` show the folders. `add` checks the home rules before it
  asks, so the owner never consents to a folder that is then refused. The record is owner-only
  (`<target root>/config/folders.json`) and never sent to the server. Each agent is bound, when
  it is built, to the record of the target its connection's claim was made for (the target in use
  then, whose claim salt must be the claim's); a later change of the process's selection never
  switches it to another target's record. The agent reads that record off the event loop on every
  outside read; a record that cannot be read admits nothing. A read root the server names must
  have the shape an owner may admit, and what the read reaches must lie inside the claimed
  worktree or at or beneath an admitted folder; otherwise the read is `root_not_admitted`. For a
  single-root read (`read_text_beneath`, `list_beneath`) that is the root, or the path beneath it
  the read names. For a task-input read (`read_outside_inputs`, `snapshot_outside_inputs`) it is
  every path the task names beneath a named root: one the owner did not admit refuses the whole
  call, which the server records as the check's `workspace_agent_refused`, so an input is never
  passed over in silence, and a named root beneath which the task names nothing is left
  unopened. The server's own privacy policy still decides which roots it asks for: the client's
  record narrows it, never widens it, and a folder narrower than the server's root admits what
  lies beneath that folder alone. A declared test is read strictly beneath the claimed root, or
  beneath an admitted folder, so the local parity of #1220 holds within what the owner admitted;
  anywhere else it is `root_not_admitted`, never read on the server's word, and the reviewer is
  not offered it. One admitted through a folder is an outside read, which excludes the claimed
  workspace by identity and case-folded spelling, so another spelling of the workspace beneath
  that folder never skips Git's ignore rule. Both comparisons use the spelling the local read
  walks: a first component that is a link root owns (macOS `/tmp`, `/var`) counts as its target,
  so such a spelling never falsely refuses.
- **Ignore rules on the agent** (amended 2026-11-06, same review). The server's reviewer broker
  asks the agent whether Git ignores a workspace path before it reads it; a server that skipped
  that question received an ignored file's bytes. The agent now asks Git itself before a
  workspace file read (`read_text_beneath` on the handle) and before a declared-test read inside
  the claimed workspace, and returns bytes only when Git answers that the path is not ignored,
  the very answer the broker requires (`ignored is not False` refuses, locally and remotely).
  Where Git cannot answer for a path, the read is nothing too: a linked worktree, whose `.git`
  file the change capture refuses as `unsafe_root`; a path inside a submodule, which the
  repository's own Git does not answer for; no repository at all (`not_git`); a home-private
  path. An honest reviewer read costs nothing, since the broker refuses those reads itself. A
  declared test in such a place, or in a Git-ignored path, is therefore not offered on a remote
  target, though a local service reads it (#1220): a parity gap that closes only when the
  client's change capture can answer for linked worktrees and submodules. A listing
  (`list_beneath`) returns names only and is not asked about; the broker filters its entries.
- **Honest limit: what a server that breaks the protocol can still obtain.** The agent cannot tell
  an honest server's question from any other. Within the claimed worktree, such a server can
  obtain any file the adapters' fences pass and Git answers is not ignored, whether or not a task
  names it, and the names, never the bytes, of every entry the fences pass in a directory
  listing, ignored ones and those Git cannot answer for included. Beneath a folder the
  owner admitted for it, it can obtain any file that is not hidden, not credential-named and in no
  system or protected directory, and list the names in its directories. Anywhere on this machine,
  it can learn the metadata (existence, type, size and times, never content) of a path the local
  outside-input candidate rule would look at (`lstat_candidates`), which the server's
  outside-input hint needs. The owner admits only folders they would let that server see. A
  refused task-input read reaches the receipt as `workspace_agent_refused`, but a refused
  reviewer read or declared test reads as absent on the server, and nothing on the client tells
  the owner which folder was asked for; such a hint is later work.
- **The hub.** `service/workspace_hub.py` keeps live agent channels keyed by workspace handle; a
  connection that declared the agent registers at handshake and unregisters on close.
  `WorkspaceAgentHub.call(handle, operation, arguments, *, timeout_seconds)` sends a
  `workspace_call` under that session's write lock and awaits the correlated reply. With no channel
  it waits a bounded time for one — 5 seconds inside a live control call, 30 seconds for
  background work such as the detached review and recovered jobs — then raises the typed
  `WorkspaceAgentUnavailable`, whose reason is closed. Each call is bounded by the catalog's call
  deadline, and by the deadline of the control call it serves, whose cancellation or timeout
  cancels it at once (a call blocked in a worker thread included); the agent is told only the
  time left once the call holds a slot, and the reply is awaited that long after the frame is
  written. A frame is never cut off part-way: the write is shielded, and a connection whose write
  a timeout or cancellation interrupted is ended rather than written on again. A channel serves
  at most four calls at once, and pending argument bytes are bounded. A dropped channel fails its
  pending calls, except that a read whose channel dropped is sent once
  more to another live channel of the same handle (never an approved check, which may already have
  run); a pending call keeps its connection out of idle close; a reply on a connection that
  declared no agent closes it. The hub logs closed tokens only. Every channel under one handle
  serves the same worktree: a connection whose claim names another worktree is closed rather than
  admitted under a handle that already has a live channel (`workspace_agent_worktree_conflict`),
  and a live control call prefers the agent its own connection offered. With no channel for a
  task's handle the call fails `no_agent`; another worktree's agent never answers it.
- **Routing.** `service/workspace_routing.py` wraps every workspace port and callable the service
  composes. An absolute-path workspace goes to the existing local adapter unchanged; a
  `client:<16 hex>` handle goes to the hub, and no local adapter is ever handed it. Callers that
  ran synchronously on the event loop — the reviewer broker's file reads, declared-test pinning,
  the observation verification steps and the post-run hash — move to a worker thread at their call
  sites, with no other behaviour change. A composition built without the hub fails a claim-bound
  read as unavailable (`hub_unavailable`), never as a local read. A reviewer's agent reads and
  its ignored-path probes keep the reviewer's own per-read budget, and a listing's probes go in
  batches, so a remote review ends `deadline` exactly where a local one would. An approved check
  run by the agent ends within its call's deadline less a reply reserve; the transport caps a
  call at 300 s, so on a remote target an approval longer than about 285 s is cut there and
  records `timeout` rather than losing its result.
- **The client side.** A connection to a remote root sends a `ClientWorkspaceBinding` (the claim,
  and optionally the agent) in place of its locator. `binding_for_active_root(locator, *,
  serve_workspace)` builds it from the active target's `claim_salt` and returns none for a local
  root, so every approach decides the same way. A client that serves an agent answers at most four
  workspace calls at once in daemon worker threads, which never keep a finished process open; a
  client without one still rejects a `workspace_call` as a malformed frame, so a local connection
  is unchanged. Several agents of one client may serve the same worktree at once (one per
  connection); so the handle an agent answers `open_workspace` with is a keyed digest of its own
  root under a key derived from the target's `claim_salt` (a client secret the server never sees),
  and any agent of that client recomputes it and opens the workspace again when a later call
  names it. A handle the key never made is still `handle_unknown`.
- **Observation over claims.** Observation verification and approved checks for a `client:`
  locator route through the hub, and the client drains the outbox and spool it captured for a
  remote root over its own claim-bound connection (`ClientObservationDrain`; which long-lived
  client process holds it is the approach's choice). A hook pass's own drain and `finishup
  observe drain` claim their workspace the same way on a remote root, or on one whose record
  cannot be read: they name the workspace to the connect seam, which claims it, and never open
  an unbound connection there. A hook pass that knows no workspace, like `observe drain` for any
  workspace but the one it names (the current folder's by default), sends nothing there and leaves
  the rows pending for the background drain (amended 2026-11-06 after the real-environment runs,
  where an unbound drain was refused or its rows quarantined). `observation_ingest` is allowed on
  a claim-bound connection, and the server's sweeper reads only its own state directory, so it
  never touches a client root. Decision 12 says whose consent and keys govern such an ingest.
- **Local stays local.** Local targets never declare an agent, so the default path is unchanged.

### 6. Honest outcomes

- **Provenance.** Every piece of workspace evidence obtained through the hub is labelled
  `client_attested`. The fixed line is "Workspace evidence was read on the client machine by the
  FinishUP workspace agent and attested over the connection; the server did not read the
  repository itself." Two renderers carry it, and neither puts anything user-controlled beside it:
  - The service ends the text and markdown receipt of a claim-bound task (its session opened with
    a `client:` handle, a durable fact a replay reads alike; a session opened on a claim-bound
    connection by a start naming no workspace — a create, a parent-registered child, a delegated
    child attached by its attach handle — opens with that connection's handle too, recorded in the
    opening event only, never in the request's identity) with a "Workspace evidence" section:
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
  pass, and an unknown change state fails closed for no-material-work. A read the agent refused
  (or an operation it never offered) is named apart: the check-time change records
  `workspace_agent_refused` (`check_time_change_unavailable_workspace_agent_refused`, its own
  fixed sentence), while `workspace_agent_unavailable`'s sentence covers an agent that was not
  connected, too slow or failed; a refused reviewer read reads as nothing.
- **No silent fallback.** A remote root never spawns or supersedes a local service and never
  falls back to the ambient one; a service refuses to run in a root whose target is remote
  (`target_root_is_remote`). The daemon refuses at composition, before anything is created, when
  the root's `target.json` names a remote kind or cannot be read (it reads only the kind, through
  the shared `config.paths.server_target_kind`), and an on-demand start refuses to spawn a local
  service for such a root at once instead of waiting out its start budget. Writes fail closed and stay retryable through the existing
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
  `targets.require_current_authorization` enforces it at every hop decision
  (`is_remote_active_root`, `binding_for_active_root`, `server connect`), with or without a
  workspace, and refuses with `target_reauthorization_required`; `server status`, `list`, `test`,
  `remove` and `logout` stay usable so the owner can see and remove a stale target.
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
- The hop is refused in the zero-network state, for every remote kind (`local_port` included).
  This computer's own FinishUP decides: when its everyday installation was set up (its vault was
  initialized), its running service's effective machine-scope policy decides
  (`privacy_get_effective` for the installation's machine scope; the question names no
  repository), and a policy that does not permit network egress refuses the hop. When that
  policy cannot be read (the service is stopped, locked or does not answer, or the installation's
  identity cannot be read), the hop is refused with `network_policy_unreadable`, never allowed.
  (Amended 2026-11-06 again, from the real-environment run: the check first read
  `privacy_get_setup` on a connection that names no repository, which the service refuses, so
  every remote hop from a set-up computer was refused.) A
  computer whose everyday FinishUP was never set up has no policy of its own, so this check
  does not refuse it: the selected server's own policy governs the work sent to it. (Amended
  2026-11-06: the earlier text also read a never-written `[privacy]` table and exempted
  `local_port`, and said the client re-checks before each hop, which no code does.) The check
  runs when the owner adds or selects a remote target. **Honest limit:** client processes do not
  consult the local policy again before each connection, so tightening this computer's policy to
  zero-network does not by itself stop an already selected remote target; `finishup server use
  local`, then a restart of open agent sessions (a running MCP bridge keeps the target it started
  with), does.
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
  records them keyed to the claimed worktree in a separate claim store, `<state
  dir>/observation-claims/<16 hex of the handle>/` (an ordinary observation store and
  lifecycle-mapping directory holding only that worktree's workspace, under a key the server
  generates), and runs the unchanged observation coordinator over it with the handle as the
  workspace. The handle names one worktree, so linked worktrees of one repository keep separate
  consent, revocation, content fence and approved-check trust, as the client keeps them: consent
  for one worktree never covers another. Its own observation store, mappings and consent are
  never read or written for a claim.
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

This pull request implements **approach B — client SDK, direct dial**.

```
LOCAL and NAMED LOCAL (unchanged)
  hook / MCP / CLI / TUI ──AF_UNIX, peer-UID check──► <root>/run/control.sock ──► service

SSH (owner-equivalent)
  client host                                                    server host (same owner)
  hook / MCP / CLI / TUI
    └─ in-process SshTransport: ssh -S <troot>/run/m … -W <remote control.sock> [user@]host
       stdio = the control stream ═══ one channel of the persistent master ═══►
                                                   sshd child (as owner) ─AF_UNIX─► control.sock ─► service

HTTPS and LOCALHOST PORT
  hook / MCP / CLI / TUI
    └─ in-process HttpsTransport (key read here): HTTPS binding v1 as a byte stream ═══►
                                 finishup service gateway (same UID; key + scope) ─AF_UNIX─► service

  workspace_call ◄══ the calling process's own connection (and the MCP bridge's, for background work)
  human-control and secret channels: never leave the server host
```

- **One seam, no relay.** `finishup.client.transports.transport_for_active_root()` replaces the
  hardcoded Unix connect in `service.client._connect_service_attempt`. It reads the active root's
  `target.json`: every local root dials its owner-only endpoint exactly as before (through
  `service.client.connect_control`, byte for byte); a remote root dials its own transport.
  `ServiceClient` runs the unchanged control protocol above the stream, so the MCP bridge, hooks,
  the CLI and the terminal interface need no change. No process runs on the client machine besides
  the client surfaces themselves.
- **SSH.** Each stream is one `ssh -S <troot>/run/m -o ControlMaster=auto -o ControlPersist=15m
  -o BatchMode=yes -o StrictHostKeyChecking=yes -o ServerAliveInterval=15 -o
  ServerAliveCountMax=3 -p <port> -W <remote control.sock> [user@]host`, whose standard input and
  output carry the frames. OpenSSH's `-W` forwards to a Unix socket path, so no `attach-stdio`
  helper runs on the server (verified against a real `sshd` by
  `tests/capability/test_openssh_direct_dial.py`). The first stream leaves a master that persists
  for 15 idle minutes, so a later hook pays one channel open: on loopback a cold hello plus status
  took 234 ms and a warm one 16 ms p50 and 22.5 ms p95, inside the 0.65 s startup gate and the
  1.0 s hook connect. `server add ssh://…` asks the server's own `finishup service endpoint
  --json` once the owner has authorized the target, through `--remote-launcher` or a launcher
  found at a fixed list of install paths (never a bare `finishup` on the remote `PATH`), records
  the endpoint and refuses another release. A stopped remote service is started once through the
  recorded launcher (`<launcher> service start`, pinned to `--remote-root`) inside the caller's
  on-demand budget. `server connect` starts the master (`ssh -fN`); `server disconnect` exits it
  by its control path (`ssh -O exit`).
- **HTTPS and localhost ports.** `finishup.client.https_binding` speaks HTTPS binding v1 to the
  real gateway, `finishup service gateway`, which this pull request carries from approach A with
  the same code on both branches (the gateway, its key store and `key create|list|revoke`, the
  `rest-error` and `server-info` 1.0.0 contracts, and every fix either branch made to it), and
  re-frames it as the length-prefixed byte
  stream: the hello becomes `POST /v1/sessions` (the gateway's 43-character session id comes back
  in `Location`); a call `POST …/calls` that waits up to 2 s for its result, after which a `202`
  continues with the 25 s results long-poll (a call is never posted twice, and after a lost
  response only its result is asked for); a cancel `POST …/cancel`, sent once the gateway has
  answered the call it names, so it never overtakes that call and waits at most those 2 s, and
  dropped when that answer was the call's result (the daemon closes a connection whose cancel
  names a call it is not running; the gateway likewise forwards a cancel only while its call
  runs there, and holds one that overtook its call until that call is sent); a
  `workspace_reply` `POST …/frames`; `workspace_call`s arrive through the `GET …/frames`
  long-poll, run only for a session whose hello declared the agent, which also keeps that session
  out of the gateway's 120 s idle expiry; the gateway closes an agent session in which no such
  long-poll began for 40 s, so a client process that died without its `DELETE` stops being the
  agent the daemon routes workspace calls to, and a closing agent connection sends its `DELETE`
  before it stops polling and waits up to 1.5 s for it. A session idle past 90 s is checked
  before a call, so an expired session fails the write and the caller's reconnect-once replays
  the same `request_id`. On the server the gateway counts sessions still being opened against a
  key's 64-session bound, names a scope refusal in its audit line, bounds its audit (one rotation
  at 8 MiB; refusals of requests no key authenticated written once per reason per minute, with a
  count of the rest), shows an expired key as expired in `key list`, and when stopped ends every
  session first (answering each open long-poll) and drops idle TLS connections instead of waiting
  out its graceful bound.
  TLS trusts the recorded CA file or the `sha256:` pin of the leaf certificate, checked inside the
  handshake before any request (and so the key) is sent; environment proxies and `.netrc` are
  ignored. `server login` checks the key against `GET /v1/server`, which must list binding `1.0`
  and this release's schema-manifest digest, before storing it. The binding's names and bounds are
  checked against the gateway's own (`tests/unit/client/test_https_binding_gateway.py`).
- **Failures.** Every remote failure is a retryable `service_unavailable` whose `phase` is one of
  the five remote phases, classified from OpenSSH's fixed diagnostics or the binding's status and
  never shown. A connection that ends while a call is in flight (a dropped network, a session the
  gateway expired, a revoked key, a closed SSH master) fails that call the same way, with the phase
  the stream names, never as `frame_invalid`: the call may have reached the server, so the remedy
  never says that nothing was recorded, and the caller's reconnect-once replays the same
  `request_id`. The HTTPS gateway starts an idle-stopped service while it holds the hello, so an
  on-demand HTTPS hello may take the caller's whole remaining budget, not one 5 s handshake; a
  hello the gateway received but did not answer within the budget is `remote_service_not_running`,
  never a network fault, and the gateway closes a session whose client left during its hello. A
  remote root never spawns or supersedes a local service and never falls back to one; a damaged
  target record refuses before any dial (`isolation_root_invalid`). A workspace
  this computer's Git cannot resolve is never sent: the claim fails before any dial, as a local
  service's own resolution failure does (`service_unavailable`, phase `handshake` or
  `handshake_git_version`).
- **Remedies.** Every surface asks `finishup.client.remote_remedy` on a remote root: a failed
  connection names its remote phase with that phase's ADR-030 directive; any other
  `service_unavailable` there is `remote_unreachable` (a service never answers one: the
  control-result error codes exclude it, so it is always the connection's own); a workspace that
  could not be claimed is this folder's; a locked server vault is its owner's to unlock on the
  server host; a server that answered `service_draining` is waited for, never restarted. The CLI
  (errors, the menu, setup's next steps), the MCP bridge, the SessionStart hook contexts and
  auto-attach, and the terminal interface use it; none of them names a local `service run` or
  `service unlock`, a host or a target name, and a local root's output is unchanged.
- **Where the workspace agent runs.**
  - *Per connection, in the calling process.* The CLI and the terminal interface (through
    `build_service_client`) and the MCP bridge connect with
    `service.client.serving_workspace_binding`: the hello claims the workspace and offers the
    agent, and `ServiceClient` answers the server's calls on that connection, so a CLI `check`
    serves its own change capture. Every other connection that names a workspace to a remote
    root — a hook, the startup-gate probe, a hook drain, `observe drain` — is claim-bound without
    an agent (`service.client`'s seam), so it never becomes the agent a server calls after the
    process exits; its observation rows still go out attested (decision 12).
  - *Background work: the MCP bridge.* The bridge holds a background agent connection
    (`finishup.client.agent_session.BridgeBackgroundWork`) while the session is active: each
    service call the bridge makes, and each row it delivers, renews a 15-minute lease, and the
    connection is released when the lease has run out and nothing waits, so the server's idle
    relock and idle stop still apply. It dials with a back-off and without the on-demand start, so
    over SSH it never starts a stopped service (an HTTPS gateway starts its own service for any
    session it opens, for this connection as for every other). Over the same connection it
    delivers what hooks captured and could not deliver themselves (`ClientObservationDrain`),
    after a read-only probe of the client's store, so an idle bridge opens no connection to
    deliver nothing.
  - *CLI-only use.* `finishup server connect NAME --agent` serves that target's workspace calls
    in the foreground (the target resolved as the root whatever is selected) until interrupted,
    and reconnects after the server closes the connection; while it runs the server counts it as
    a connected client, so the server's idle lock waits, and the command says so.
  - *Limit.* Hook rows delivered more than 15 minutes after the bridge's last activity are
    verified only if an agent is connected then (a CLI command, a foreground agent); otherwise the
    verification waits the hub's 30 s and is recorded unavailable, never a pass.
- **Credential.** Each client process that dials an HTTPS target reads the key from its
  `CredentialSource`: the ADR-008 amendment of this approach, disclosed in ADR-008. The read runs
  in a daemon thread bounded at 3 s, so a keyring waiting on an unlock or permission prompt never
  blocks a hook's or the bridge's event loop, nor its exit; a key not read in time is
  `remote_auth_failed`. The HTTP
  client and the credential store load only inside an HTTPS dial; a hook for a local or SSH target
  never imports them (`tests/packaging/test_hook_import_diet.py`).
- **Evidence.** `tests/integration/service/test_direct_dial_end_to_end.py` runs a real daemon,
  vault and ready composition behind the real gateway (HTTPS) and behind the production SSH argv
  with a stand-in for `ssh` (SSH), with the production client above the transport: the whole
  workflow with client-attested evidence and the client's attribution, a decoy at the claimed
  path never read, the reviewer's `read_file` answered by the agent, the agent lost mid-review
  (`workspace_agent_unavailable`, never a pass), a hook's row delivered by the bridge's background
  drain and verified through its agent, a hook's claim-only connection, two real linked worktrees
  of one repository on one target (one commitment, two handles, and every workspace call of each
  task answered by its own worktree's agent), and remote loss as a typed remote phase with no
  local fallback. `tests/unit/client/test_direct_transport_parity.py` and
  `tests/capability/test_openssh_direct_dial.py` show the frames byte-identical over every
  transport, against the real gateway and a real `sshd`.
- **Compared with A.** No relay process to supervise and no per-target status file; the costs are
  the credential in client processes, a handshake per client process (one SSH channel on a warm
  master, or one binding session), a transport each hook loads lazily, and several agents per
  workspace (one per serving connection) instead of one.

## Reverse states

| Way in | Way out | Way to see it |
|---|---|---|
| `server add NAME …` | `server remove NAME [--select-local]` (disconnects, deletes the credential, disposes of the root; refuses the selected target unless `--select-local`) | `server list` |
| `server use NAME` | `server use local` (removes the selection file; ambient resolution returns with no residue) | `server status` (names the deciding source) |
| `server login NAME` | `server logout NAME` | `server status` (credential present or absent, never the value) |
| `server folders add NAME FOLDER` (trusted console) | `server folders remove NAME FOLDER` or `--all` (also clears a damaged record; takes effect at the next workspace call) | `server folders list NAME`, `server status` |
| `server connect [NAME]` | `server disconnect [NAME]` (stops only what that root's runtime stamped; never by name or pattern) | `server status`, `server test` |
| `server connect NAME --agent` (foreground workspace agent) | Ctrl-C; the connection closes | the terminal it runs in |
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
- The zero-network refusal (decision 8) is checked when the owner adds or selects a remote
  target, not before each connection. Tightening this computer's policy to zero-network later
  does not stop an already selected target; the way out is `finishup server use local`, then
  restarting open agent sessions. The maintainer chose to disclose this limit in `PRIVACY.md`, the
  servers guide and the ADR-009 amendment rather than add a per-connection policy check
  (2026-11-06).
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
