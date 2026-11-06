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
  (amended 2026-11-06 after the real-environment runs).
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
  by its shape alone; amended again the same day by maintainer decision D2, which made it a
  per-target mode, and by D2b, which gave every remote kind the same choice, asked at `server
  add`). What a server may read outside the claimed worktree is recorded on the client, per
  server target, as approved-check trust is (decision 12), and is the owner's to set. Each remote
  target has an **outside-read mode**, and every remote kind (`local_port`, `ssh`, `https`)
  offers the same two, with the same behaviour:
  - **`local`**: the agent answers the server's outside reads exactly as a local FinishUP service
    would answer them. The server's own admitted-root policy decides which roots it reads; the
    adapters' fences and the agent's own exclusions below still hold, and there is no client
    folder check, so an input beneath a root the server's policy names is never refused on the
    client. A refusal happens only where a local service would refuse too (a root of a shape no
    owner could admit). A read rooted in FinishUP's own directories is not refused but answers
    nothing, as a local service's read, which excludes those directories, answers nothing there.
  - **`listed`**: the server reads outside the worktree only beneath folders the owner listed
    for that target, as described below; anything else is refused.

  There is no default per kind. `finishup server add` asks the owner which mode a new remote
  target gets, on the trusted foreground console as part of its typed confirmation: after the
  disclosure it asks what the server may read outside the owner's projects, with one plain line
  for each mode, and requires an explicit answer (`local` or `listed`; Enter alone or another
  word asks again, a few times, and then, or at end of input or an interrupt, nothing is added,
  `outside_reads_not_chosen`); the typed target name then authorizes both. `--outside-reads
  local|listed` answers the question up front, and still needs the trusted console and the typed
  name, as every remote `add` does; the console shows the mode it authorizes. When the owner
  chooses `local`, answered or by the flag, the console shows, before the typed name, the same
  notice `server folders mode NAME local` shows of what that mode lets the server read, a
  rule-breaking server included; it adds no prompt. The answer is
  recorded in the client record. Where it cannot be written, the target is still added, in
  `listed` mode, and `add` says so and how to choose again. The one exception is an official
  FinishUP endpoint: an HTTPS target whose exact hostname is in the reviewed constant
  `client.server_folders.OFFICIAL_ENDPOINT_HOSTS` is not asked and is `local` (source
  `official_endpoint`), so the official trusted service reads as much as a local one. The match
  is by exact hostname only, and applies only while the target trusts the system certificate
  store: a target added with `--ca-file` or `--tls-pin` never counts as official by its hostname
  alone, and is asked. Its `local` is not recorded, so it follows the reviewed list; an explicit
  `--outside-reads` is recorded as the owner's own. The constant is empty, because no official
  hosted endpoint exists yet; the maintainer fills it in when one does. A record with no mode (no
  release wrote one; a record whose mode could not be written) reads as `listed`, the fail-closed
  value (source `not_chosen`), and `server status`, `server folders list` and the terminal's
  `/server` status say how to choose. Once chosen, nothing asks again: hooks, agent tools (MCP),
  the CLI and the terminal interface read the record, and the agent reads it at every call.

  `finishup server folders mode NAME local|listed` changes the mode later. `local` widens what
  the server reads, so it needs the trusted foreground console and the owner typing the target
  name after a notice of what that mode lets the server read, a rule-breaking server included;
  `listed` narrows it and is the way back, needing neither. A recorded `local` is the owner's own
  choice, kept whatever the reviewed list of official endpoints later says, so recording it
  always takes the console and the typed name, an official endpoint's included; where no trusted
  console can ask (an agent's shell), `mode NAME local` on an official endpoint records nothing,
  says that it is already `local` as an official server, and leaves it following the list.
  `server add` prints the mode it recorded and the one command that changes it, and `server
  folders list`, `server status` and the terminal's `/server` status show the mode and where it
  came from (`owner`, `official_endpoint`, `not_chosen`, or `unreadable`); `server status --json`
  carries the same, with the listed folders, as `target.outside_reads` of `server-target-status`
  1.0.0 (null for a target that is not remote). The terminal interface's `/server` add flow asks
  the same question in the same words and prints the `server add` command with
  `--outside-reads` set to the answer. It keeps the same exception: while
  `OFFICIAL_ENDPOINT_HOSTS` names a host, it offers an official FinishUP service as its own
  choice, asks it nothing, and prints `server add NAME https://HOST` without `--outside-reads`,
  so that service's `local` stays unrecorded and follows the reviewed list instead of becoming
  the owner's own recorded choice.

  In `listed` mode the folders are the owner's: `finishup server folders add NAME FOLDER` needs the
  trusted foreground console and the owner typing the target name; it records FOLDER canonicalized
  by the local service's own input-root rule (an existing directory named by its absolute,
  normalized, link-free path; never hidden or a system tree), and never the home directory, a
  folder that holds it, or one in its private trees. `server folders remove NAME FOLDER|--all` is
  the way out; like a change of mode, it applies from the workspace agent's next read, and a read
  already in progress may still return files from that folder. Listing or removing a folder
  keeps the mode; a folder listed in `local` mode is kept for `listed` mode and said to be so.
  `add` checks the home
  rules before it asks, so the owner never consents to a folder that is then refused. The record
  is owner-only (`<target root>/config/folders.json`, `yoetz.server-folders/1`, with an optional
  `mode`) and never sent to the server. Each agent is bound, when it is built, to the record of
  the target its connection's claim was made for (the target in use then, whose claim salt must
  be the claim's, or a target root its caller names); a later change of the process's selection
  never switches it to another target's record, and an agent built without a record is `listed`
  with no folder rather than guess a target, or take the mode of the target in use, from the
  selection, which may name another server. The agent reads that record off the event loop on
  every outside read, so a change of mode or folders applies from its next read (one already in
  progress finishes under the record it started with). A record that cannot be read fails closed
  to `listed` with no folder, whatever mode it held; `remove NAME --all` replaces it with an
  empty record in `listed` mode, the state it already stood for, so clearing it never widens
  what the server reads. `server status`, `server folders list` and the terminal's `/server`
  status say that the record is damaged or not private, what the server reads meanwhile, and
  that one repair with the target's own name and where to run it (this computer); `list` shows
  that state rather than refusing, and a change (`add`, `remove FOLDER`, `mode`) refuses with
  the same repair and says to run the command again (amended 2026-11-07). In both modes a read root the server names must have the shape an
  owner may admit, and nothing in FinishUP's own directories is ever read: every outside read
  excludes them. In `local` mode that exclusion is all, as for a local service, so a read rooted
  there answers nothing and is not refused. In `listed` mode a reviewer read or listing rooted
  there is `root_not_admitted` even beneath a listed folder, a deliberate stricter-than-local rule
  for reviewer reads alone that changes nothing the server sees, since a refused reviewer read
  reads as absent there (below); a task-input root there is excluded, not refused, once the
  listed-folder rule admits its paths. In `listed` mode what the read
  reaches must also lie inside the claimed worktree or at or beneath a listed folder. For a
  single-root read (`read_text_beneath`, `list_beneath`) that is the root, or the path beneath it
  the read names; anything else that exists is `root_not_admitted`. For a task-input read
  (`read_outside_inputs`, `snapshot_outside_inputs`) it is each path the task names beneath a
  named root, judged one at a time (amended 2026-11-07, refusal-guide review): a path the owner
  did not list is left unread and the rest of the read goes on, and the answer carries, beside
  the files, the indices of the server's own values it left unread (`unlisted`; indices only,
  never a path the server did not send). The values judged are first narrowed to those the local
  read would look for: its window of 16, less the words the spaces of a quoted spaced value cut
  out when that whole value names something beneath a named root (issue #1102), decided before
  any value is left out, so leaving a spaced value unread never lets one of its words be read
  under the task's name. The server freezes how many inputs were left out as the check-time
  change's `outside_inputs_not_listed` count and discloses the closed code
  `outside_reads_not_listed`, whose fixed sentence names both ways out and where to run them
  (the count reaches the `semantic_case_built` diagnostic, not the receipt line: open question
  2); so a listed-mode input costs
  only that input, never the whole check-time change, and is never passed over in silence. A
  kept copy (#1118) whose folder the owner no longer lists is not sent, as a copy whose root the
  owner no longer admits is not: the current read that compares it names it `unlisted` too.
  Listed mode refuses or skips only what exists (same amendment): a path the read reaches that
  does not exist reads as nothing, as it does locally, and is never counted, so a stray path in a
  task statement costs nothing. Whether a path exists is answered only for one the local
  outside-input candidate rule would look at (no hidden component, not credential-named, in no
  system or protected directory), so the server learns no more than `lstat_candidates` already
  tells it. A named root beneath which the task names nothing is left unopened, and one that
  holds a listed folder is walked only to the values beneath that folder. The server's own
  privacy policy still decides which roots it asks for: in `listed` mode the client's record
  narrows it, never widens it, and a folder narrower than the server's root admits what lies
  beneath that folder alone. Both ways out are the owner's, on the client: list the folder, or,
  for a server they trust, switch it to `local` mode. Listing covers files outside the worktree
  only: a declared test inside it that Git ignores or cannot answer for is read in `listed` mode
  under no listing, the worktree's own folder included, so the fixed sentence names `local` mode,
  or no longer ignoring the test, as the only ways to have it read. A declared test is read in `local` mode
  exactly as a local service reads the test its own agent declared (#1220): inside the claimed
  worktree or outside it, whether or not Git ignores it or can answer for it, with FinishUP's
  own directories excluded and no other rule (same amendment). In `listed` mode a declared test
  inside the claimed worktree is read under Git's ignore rule (next item), and one outside it
  only beneath a listed folder; an existing one beyond that is `root_not_admitted`, never read on
  the server's word, the reviewer is not offered it, and the server discloses
  `outside_reads_not_listed` for it (frozen into the job's case object as the count
  `declared_tests_not_listed`, so a recovered job builds the same case). One read outside the
  worktree in `listed` mode is an outside read, which excludes the claimed workspace by identity
  and case-folded spelling, so another spelling of the workspace beneath that folder never skips
  Git's ignore rule. Both comparisons use the spelling the local read walks: a first component
  that is a link root owns (macOS `/tmp`, `/var`) counts as its target, so such a spelling never
  falsely refuses.
- **Ignore rules on the agent** (amended 2026-11-06, same review; narrowed 2026-11-07). The
  server's reviewer broker asks the agent whether Git ignores a workspace path before it reads
  it; a server that skipped that question received an ignored file's bytes. The agent now asks
  Git itself before a workspace file read (`read_text_beneath` on the handle), and returns bytes
  only when Git answers that the path is not ignored, the very answer the broker requires
  (`ignored is not False` refuses, locally and remotely), so a local service has the same rule.
  Where Git cannot answer for a path, the read is nothing too: a linked worktree, whose `.git`
  file the change capture refuses as `unsafe_root`; a path inside a submodule, which the
  repository's own Git does not answer for; no repository at all (`not_git`); a home-private
  path. An honest reviewer read costs nothing, since the broker refuses those reads itself. A
  declared test is held to the rule only in `listed` mode: a local service reads a declared test
  whether or not Git ignores it (#1220), so `local` mode does too, and there no declared test is
  skipped that a local service would offer. In `listed` mode a declared test that is
  Git-ignored, or that Git cannot answer for, is refused and disclosed as above. A listing
  (`list_beneath`) returns names only and is not asked about; the broker filters its entries.
- **Honest limit: what a server that breaks the protocol can still obtain.** The agent cannot tell
  an honest server's question from any other. Within the claimed worktree, such a server can
  obtain any file the adapters' fences pass and Git answers is not ignored, whether or not a task
  names it, and the names, never the bytes, of every entry the fences pass in a directory
  listing, ignored ones and those Git cannot answer for included; in `local` mode it can also
  obtain, as a declared test, a file the fences pass that Git ignores or cannot answer for, as a
  local service's declared-test read could. In `listed` mode, beneath a folder the owner listed
  for it, it can obtain any file that is not hidden, not credential-named and in no system or
  protected directory, and list the names in its directories. In `local` mode it can do so
  beneath any root of a shape an owner could admit, anywhere on this machine, within the same
  fences (the home directory's private trees included), as a local service's reads could; that is
  why `local` is the owner's typed choice, at `server add` or later, for a server they trust as
  they trust FinishUP on this computer, and never a default for any kind (an official FinishUP
  endpoint alone is `local` without the question). Anywhere on this machine, it can learn the
  metadata (existence, type, size and times, never content) of a path the local outside-input
  candidate rule would look at (`lstat_candidates`), which the server's outside-input hint needs,
  and in `listed` mode whether such a path exists from whether a read of it is refused or left
  unread. The owner lists only folders they would let that server see. A task input or declared
  test that listed mode kept from the server reaches the receipt as `outside_reads_not_listed`;
  a refused reviewer read reads as absent on the server, which in practice names the same
  task-named path the check-time read already disclosed. Nothing on the client tells the owner
  which folder was asked for; such a hint is later work.
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
  client without one still rejects a `workspace_call`
  as a malformed frame, so a local connection is unchanged.
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
    client_claim).` The stored receipt document and JSON receipts are unchanged. The service
    finds the opening event by its schema name and reads it before the receipt stages or appends
    anything. Owner decision D4: a receipt never refuses because of this lookup; it says clearly
    what happened, why, and that a retry may help. When the read fails, whatever the failure (an
    environmental fault, a malformed record, the ledger's own classified refusal; each is
    recorded as one bounded diagnostic an operator can find), or the opening event cannot say
    whether the task is claim-bound (it is redacted, its key is unavailable, its version the
    service cannot read, or its payload object the ledger could not read when it recovered the
    task: the object is missing, fails verification, or hit an environmental fault, and the
    recovered ledger keeps the event as present with no payload, does not say which, and keeps
    that gap for as long as it holds the task), the receipt is built and its "Workspace
    evidence" section holds three fixed lines instead: "Provenance unknown: the record of how
    this task's session was opened could not be read from the server's ledger." (what
    happened), "Why it matters: FinishUP cannot confirm whether this task's workspace evidence
    was read on the client machine." (why), and "What to do: run receipt again. If this
    persists, restart the server's FinishUP service (`finishup service restart` on the server
    host), then run receipt again." The section is never dropped and never says the evidence was
    read on the client. A refusal would shut a task out of receipts — a task that is not
    claim-bound got a correct one before — for as long as the fault lasts, and for good when the
    object is gone. Every receipt and every replay reads the opening event again, so once the
    read succeeds (a transient fault clears, or the service reopens the task after it drops an
    idle task or restarts, and the object reads) the same receipt renders the binding the event
    records.
  - The client ends every human status and receipt rendering of a claim-bound connection — CLI
    text, the MCP status and receipt text, the terminal interface's task views and receipt — with
    the fixed line (unless the rendered text already carries it) and `This client reached FinishUP
    service <service_instance_id> (transport: <token>).` A receipt whose service text carries the
    provenance-unknown line keeps only the second: the client's line is a fact about its
    connection, the service's is about the task's own opening event, and the client does not
    overrule the service by saying the evidence was read on its machine. Every delivery page of a
    receipt the service paged for an agent (the first from `receipt`, the rest from `status`
    continuations) keeps only the second too: the receipt's section is cut into fragments with
    the rest of its text and lands on at most one page, so no page can show which statement it
    holds, and the agent reads it whole before the set is actionable-complete. The client reads
    the receipt's provenance only from the text it renders: a JSON receipt, or one whose text the
    service withheld, has no section to read, so its human rendering keeps both lines even when
    the service could not establish the task's provenance, and only a text or markdown receipt
    says so. (A provenance field on the receipt result would carry it to every page and format;
    it would change the receipt result body, which this cut leaves unchanged.) The id is the one
    the hello-result named.
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
  connected, too slow or failed; a refused reviewer read reads as nothing. Since listed mode
  leaves an unlisted input unread instead of refusing the read (decision 5, amended 2026-11-07),
  a check-time refusal is now a request the agent does not answer (a handle it did not claim, an
  unknown operation or argument, a root no owner could admit), in practice two releases that do
  not match; its sentence says so and names `finishup server connect NAME` on the client. The
  unavailable sentence names `finishup server status NAME` and `finishup server connect NAME`
  on the client and that checking again can help. Files listed mode kept from review are the
  disclosure `outside_reads_not_listed` (decision 5), never a check-time change gap: the rest of
  the change still reaches review.
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
  disclosure and the owner typing the target name. At `server add` the same confirmation first
  asks what the server may read outside the owner's projects (decision 5), unless
  `--outside-reads` answered it or the target is an official endpoint; `server use` does not ask
  it again. `target.json` records `authorized_at` and `disclosure_version`; a new disclosure
  version requires a fresh confirmation before use.
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
  runs when the owner adds or selects a remote target; client processes do not consult the local
  policy again before each connection. `server status --json` (`server-target-status` 1.0.0)
  reserves `zero_network_selection` for telling the owner of that state: null, or the item's
  `reason` (`zero_network_remote_selected` or `zero_network_selection_unreadable`), `target_id`,
  `kind` and `detail`, generated ids and closed tokens only. It is null while nothing on the
  client reports the state.
- **Zero-network set while a remote target is selected: surfaced, and the owner decides**
  (maintainer decision, 2026-11-06). FinishUP never switches servers on its own.
  `cli/zero_network_selection.py` reads the selection file afresh (never the process memo) and,
  only when it names a remote kind, the everyday installation's effective machine-scope policy;
  a process whose root an isolation variable or pin decides is left alone. After every committed
  policy change (a tightening applied on propose or tighten, or a policy decision that commits:
  the privacy setup ceremony and its credential-heuristic, conversation and input-root changes,
  `privacy propose|tighten|decide-policy`, `finishup setup`, `finishup ai`, the menu's wizard, the
  terminal interface's privacy flows, and the relayed elevated grant), in that state:
  - on the trusted foreground console it names the target by id and kind, says the setting does
    not stop traffic to it, and offers `1` switch to this computer's everyday FinishUP now
    (`finishup server use local`) or `2` keep using the target. Enter, end of input, an interrupt
    or any other answer keeps it: switching is never chosen for the owner, and under zero-network
    it cannot be undone without relaxing the policy. The choice is read on the calling event
    loop's thread, never in a worker, with Python's default SIGINT handler in place of the loop
    runner's for the read, so Ctrl-C answers it at once;
  - without that console, for a machine-readable answer (`--json`, including the setting
    commands, which set `machine_readable_answer()` around the change), or for a grant relayed
    from an agent chat, nothing switches: the facts, the command and the reminder to restart open
    agent sessions go to stderr as `zero_network_remote_selected: …`.

  **Where it can arise.** While a remote target is selected, a fresh process does not set this
  computer's policy: every `server_host` privacy command (the privacy ceremonies, `decide-policy`,
  the credential-heuristic, conversation and input-root commands, `ai`, `elevated-bootstrap`, the
  terminal interface's `/privacy`) is refused with `requires_server_host`, and the `any`-scoped
  `privacy tighten|propose` and `setup run` act on the selected target. The paths above
  therefore surface the choice when the process committing the change resolved this computer's
  server before the selection changed (the selection memo is per process): an open terminal
  interface or menu, or a privacy step or setup run already under way when `server use` ran
  elsewhere. Adding or selecting the target after the policy is zero-network is refused, as above.

  The item stays visible while the state lasts and can be read (below): `server status` (stderr
  beside `--json`, whose 1.0.0 contract is unchanged) and `server list`, `setup status` (stderr),
  `setup status --next` (a `server_selection` fact with its pinned continuation), the setup wizard's
  next steps, the menu home, and the terminal interface's header and `/server` (read at start, after
  a privacy ceremony, and on `/server`; the header drops it once the selection file changes). A
  selection that cannot be read is reported as `zero_network_selection_unreadable` with its closed
  reason (`selection_invalid`, `target_root_unsafe`, `target_record_invalid`) and `finishup server
  use local` as the way back, never as "no server". While this computer's policy cannot be read,
  nothing claims the zero-network state either way, so the displays show the item only while this
  computer's service is running and unlocked, the one source of that policy. **Honest limits:**
  while the owner keeps the target, and after switching until open agent sessions restart (a running
  MCP bridge keeps the target it started with), traffic to it continues; and usually nothing on this
  computer uses its own service while a remote target is selected, so once that service relocks or
  stops when idle the displays can no longer tell the state and say nothing, although work still
  goes to the target. Agents cannot change the policy or the selection, so no MCP tool surfaces or
  answers the choice.
- **Which server's policy a command changes is said before and after** (maintainer principle "be
  clear on what happened", 2026-11-06). While a remote target is selected, `privacy tighten`,
  `privacy propose` and the privacy step of `setup run` (the trusted questionnaire, which the
  menu's setup and the terminal interface's first run also run) change the target's policy, not
  this computer's everyday one. `cli/policy_server.py` names the target of the process's resolved
  root (`active_target_record()`, not the selection read afresh: a process on this computer's
  server changes this computer's policy and says nothing here), for the remote kinds only, by
  `target_id` and `kind`, never the name the owner typed. Each path prints a fixed line before
  anything is sent (`Privacy policy changes here apply to the selected FinishUP server t_… (kind),
  not to this computer's everyday FinishUP.`) and one in its result: the change applied
  (`tightening_applied`, or a configured questionnaire), waits for a decision on the server host
  (`decision_required`), was not changed, or was not confirmed (the command failed after it may
  have reached the server; `privacy show` shows the policy). The lines are the same with and
  without `--json`: the `tighten|propose` result document is the released control result body,
  so it keeps its shape and the lines go to stderr; the questionnaire prints them with its own
  output, the setup summary's privacy lines end with `(on the FinishUP server t_… (kind))`, and
  the terminal interface repeats the result line once the handed-over terminal returns. No output
  schema involved is unreleased, so no field was added. `privacy decide-policy` stays
  `server_host`: on this computer it is refused with `requires_server_host`, whose line names the
  target, because a trusted decision runs only on the server host (decisions 7 and 11). For the
  same reason the questionnaire on a remote target no longer opens the local decision ceremony
  for a widening (it could only fail, the human-control channel never leaving the server host): it
  reports the waiting proposal (`outcome` `cancelled`, its `proposal_id` and the server's
  `expires_at`, `reason` `requires_server_host`). A named local target is this computer's own
  server host and is not named; a target record that cannot be read is left to the connection,
  which refuses it.

  *Amended 2026-11-06 (review):* a waiting proposal must be one the owner can act on, following
  "be clear on what happened, why, and that a retry can help". Every surface that reports one
  (the `privacy propose` stderr line, the questionnaire, the setup summary, the terminal
  interface) prints the same sentence: the change waits and the policy has not changed, because a
  trusted decision runs only on the server host; run `finishup privacy decide-policy <proposal
  id>` there before `<expiry, rounded down to the minute> UTC`; after that it expires unchanged
  and making the change again here proposes it anew. The id and the expiry come from the
  server's `decision_required` answer and are printed only in their closed shapes (`ppr_<uuid>`,
  `YYYY-MM-DDTHH:MM:SS.mmmZ`); anything else is left out and the line says to make the change
  again. The proposal lives `PrivacyPolicyApplication.proposal_ttl_seconds` (300 s); nothing on
  the server host lists policy proposals (`privacy_pending_list` carries disclosures only, a
  released body), so the printed id is how the owner finds it. On a remote target setup's next
  steps never name `finishup --privacy` or `finishup --set` (both `server_host`): the privacy step
  is that decide-policy continuation for a waiting proposal, otherwise "rerun `finishup setup
  run` here", and the API-key step says both run only on that server's host. Every caller that
  prints a result after the questionnaire (setup run, the provider step `setup run --host` runs,
  the terminal interface's four hand-overs) reads the server once before it and keeps that value:
  the zero-network choice inside the questionnaire may switch the selection to this computer, and
  the change stays the remote server's.
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
  closed reads that status and raises `service_unavailable` with the remote phase as `phase` (the
  connector records a phase before it closes any connection it could not relay). A connection
  accepted but not yet answered is waited for, never named; when the wait runs out, only a phase
  recorded during it names the outage, and otherwise it is `remote_unreachable`. The
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
  a session after 120 seconds idle (an agent session also once no frames long-poll began for 40
  seconds, so a client that died without `DELETE` stops being the agent workspace calls go to),
  closes a session whose client left while its hello was held (a slow on-demand service start),
  holds at most 64 per key, and stops with `gateway_stale` when
  the daemon answers with another release's manifest. `--behind-proxy` serves plain HTTP on a
  loopback address only. There is no access log; audit lines carry the key id, route, method,
  status, closed reason and correlation id only, and the audit is bounded (one rotation at 8 MiB;
  unauthenticated refusals written once per reason per minute, with a count of the rest). v1 has one principal (`owner`): claims pass
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
  sends the handle. The claimed locator is first normalized to its worktree's top level by the
  hooks' own rule (`canonical_workspace_locator`), so a bridge started in a subfolder and a hook
  in the same worktree claim it alike and reach one handle. A workspace the shared root rule
  cannot resolve is not claimed, and a remote
  connection with no claim refuses an absolute `workspace_ref` instead of sending it. A target the
  owner confirmed under an older disclosure is refused before any dial, with or without a
  workspace to claim, as the retryable `service_unavailable` with phase
  `target_reauthorization_required` (a record that can no longer be read: `target_root_is_remote`);
  no connector is started and nothing is sent until `finishup server use NAME` renews it.
- **Workspace agent location.** Per connection, the client process's own `ServiceClient` answers
  through the relay. For work that outlives the call, the connector keeps one long-lived agent
  connection per workspace whose claim it relayed, for 15 minutes after that workspace's last hello
  (`open_background_agent(root, claim, dial)`); each linked worktree of one repository is its own
  workspace here, with its own lease and agent, although the worktrees share the repository's claim
  digest. It learns which local workspace a claim stands for from the root's owner-only
  claimed-workspace index (`<troot>/state/claimed-workspaces/<64 hex>-<64 hex>.json`, named by the
  claim's repository and worktree digests, `yoetz.claimed-workspace/1`), which the connecting
  process writes and which never leaves the machine; it derives the claim again from the recorded
  workspace with the target's salt and serves it only when the two match. The agent connection runs
  the real `WorkspaceAgentHandler`, is relayed by the connector itself over a socket pair (so it
  neither keeps the connector from idling out nor renews its own lease), and reconnects whenever the
  service ends it. Over the same connection the connector delivers what the client's hooks captured
  for that workspace (the observation outbox and spool, `ClientObservationDrain`, each row attested
  by the client's own store) every 30 seconds and once more as it stops; hooks still drain once per
  pass. Several connections may serve one worktree's handle (a CLI command, the MCP bridge, the
  connector): a live call goes first to the agent its own connection offered, otherwise to the
  newest, and a workspace an agent opened for observation verification and another agent does not
  know (`handle_unknown`) is opened again on the answering agent and the call retried once. Every
  answer comes from the task's own worktree; a linked worktree's change capture is refused
  `unsafe_root` by the client's own adapter (its `.git` is a file), exactly as a service on that
  machine refuses it.
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
| `server add NAME …` for a remote kind records the outside-read mode the owner answered (or `--outside-reads`; an official endpoint is `local` unrecorded) | `server folders mode NAME local` or `listed` changes it; `server remove NAME` removes it with the target | `server add` output, `server folders list NAME`, `server status [--json]`, `/server` status |
| `server folders mode NAME local` (trusted console and typed name whenever it records `local`, an official endpoint's included; without the console an official endpoint's `local` is left unrecorded) | `server folders mode NAME listed` (applies from the workspace agent's next read; a read already in progress may finish) | `server folders list NAME`, `server status [--json]`, `/server` status |
| `server folders add NAME FOLDER` (trusted console) | `server folders remove NAME FOLDER` or `--all` (also clears a damaged record, to an empty one in `listed` mode; applies from the workspace agent's next read, and a read already in progress may still return files) | `server folders list NAME`, `server status [--json]`, `/server` status |
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
- The zero-network refusal (decision 8) is checked when the owner adds or selects a remote
  target, not before each connection. When this computer's policy is set to zero-network while
  a remote target is selected, FinishUP surfaces it and the owner decides, on the trusted console
  or from the printed command, whether to switch to the everyday FinishUP; it never switches on
  its own (maintainer decision, 2026-11-06, replacing the earlier choice to only disclose the
  limit). That change can only come from a process that resolved this computer's server before
  the selection changed, because fresh server-host commands are refused while a remote target is
  selected. While the owner keeps the target, and after switching until open agent sessions
  restart, traffic to it continues, and the displays show the state only while this computer's
  service is running and unlocked.
- Every path on this computer that changes a remote target's privacy policy names the target
  (id and kind) before and after (decision 8). A widening proposed there waits on the server host
  for its decision; setup's privacy step reports it as waiting instead of failing on a local
  ceremony it cannot reach, names the proposal id and its expiry (about five minutes) with the
  exact `privacy decide-policy` command for that host, and setup's next steps say the same rather
  than naming `--privacy` or `--set`. The server host offers no list of policy proposals, so a
  proposal whose id was lost is retried by making the change again once it expires.
- A Linux server whose runtime directory belongs to the login session loses its sockets at the
  last logout; `service endpoint --json` reports this, and the server needs linger or its own
  isolated root.
- A human-passphrase vault on a server stays locked after a restart until the owner unlocks it on
  the server; auto-unlock custody (ADR-008, 2026-10-19) is the unattended path.
- That custody also re-opens a soft lock (idle, session lock, suspend) when a request arrives,
  a claim hello included (decision 4). The re-open is one service-owned attempt: a hello at its
  5-second handshake deadline stops waiting for it but never interrupts it. A lock outranks it:
  an explicit or session lock cancels the attempt first and records its own reason. The attempt's
  own 30-second deadline, the on-demand cold-start budget for the same unlock and activation,
  returns a stalled one to the soft lock for a later request to retry. The staged-slot reconcile
  after the vault opens is hygiene: it runs beside activation, outside that deadline and a
  lock's cancel, so it never relocks the open vault, and the next attempt waits for it before
  reading. A passphrase rotation does not open while it runs, because it discards a staged
  rotation entry it finds and the helper stages its replacement once the rotation opened: the
  open waits up to the 5-second handshake budget for it, and only a store that does not answer
  by then gets a refusal, which the helper reports as a credential-store check still running,
  safe to retry. The generated rotation, which stages before it opens, stays a known limit
  (INTERFACES; issue #1319). While a
  credential-store call an attempt gave up on (the scoped-entry read or that
  reconcile) is still blocked in its worker thread, no attempt starts another, so a credential
  store that never answers holds one thread. The deadline bounds only what the attempt awaits: an
  `os_keyring` root-key read on the event loop, or an activation step that joins its worker
  thread, still runs to its end (2026-11-06, after review).
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

## Open questions for the maintainer

1. **Task-input folders that exist only on the client** (recorded 2026-11-07, refusal-guide
   review). A server's task-input roots come from its own privacy policy, set with `finishup
   privacy input-roots add <folder>`, a `server_host` command: on a remote target it is refused
   on the client (`requires_server_host`), and on the server host it runs for the repository in
   the current folder there and needs the folder to exist there, at a link-free real path. So a
   folder that exists only on the owner's computer cannot be admitted for a server on another
   machine, in either outside-read mode, and an input there stays out of review
   (`task_input_outside_not_admitted`), where FinishUP on one computer lets its owner admit it.
   Nothing about this was redesigned; every message about it now says where the command runs
   and what that means for a remote server (the receipt sentence and its MCP short form, the
   terminal interface's privacy line, the command's help, and the `requires_server_host` line
   for `privacy input-roots`). Ways the maintainer could close it: in `local` mode, let the
   server ask the client's agent for task inputs beneath a root the client's own local policy
   admits; let `privacy input-roots` record, from the client through an owner ceremony on the
   trusted console, a root that exists only on the client for that claim; or keep the limit as
   documented. Undecided.
2. **How many files listed mode kept back, on the receipt** (recorded 2026-11-07, refusal-guide
   review). The refusal-guide fixes asked for a fixed receipt line with counts and no paths.
   The count is frozen (the check change's `outside_inputs_not_listed`, the case object's
   `declared_tests_not_listed`) and reaches the `semantic_case_built` diagnostic as
   `semantic_task_inputs_outside_not_listed`, which `finishup service diagnostics` shows. The
   receipt line itself, `outside_reads_not_listed`, carries no number: a receipt's disclosures
   are closed codes, and every receipt-document schema (1.0.0 to 1.3.0) was released at
   v0.3.0, so a number there needs a new receipt-document version, a design-gated protocol
   change outside this review. Ways the maintainer could close it: accept the line without a
   number; or add an optional disclosure-count field in a receipt-document 1.4.0 that every
   rendering (text, markdown, JSON, the MCP summary, the CLI check output) prints beside the
   sentence. Undecided.

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
