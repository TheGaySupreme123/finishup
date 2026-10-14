# Auto-approving an MCP route

Auto-approval should be based on the exact process a host launches, not on an assumption about the
current provider or privacy configuration.

For a FinishUP MCP process that must never request external AI-powered review, register:

```text
finishup mcp serve --semantic off
```

This starts the **strict** route profile. For that process lifetime:

- local checks and all six FinishUP workflow operations remain available;
- `check` never requests AI-powered review runtime capability and never dispatches an AI-powered
  evaluator;
- an AI-powered review request is recorded as `blocked_by_policy` / `route_semantic_ceiling`;
- `semantic_required` is incomplete and the result and receipt retain the coverage gap;
- `check.openWorldHint` is `false`, and initialize plus `status(view=versions)` disclose `strict`.

The route profile is not an agent request field and cannot be changed over MCP. The descriptor is
an inspectable hint; the application route constraint is the enforcement.

## What strict does not claim

Strict is an egress ceiling for external AI-powered review, not a general-purpose sandbox and not a
promise that the process opens no communication channels. The MCP bridge still uses the approved
local FinishUP service IPC. It does not constrain the host agent, the operating system, separately
running local models, or unrelated processes.

The ordinary command remains:

```text
finishup mcp serve
```

That starts the **policy** route. AI-powered review can occur only when the durable privacy policy,
provider readiness, classification, minimization, and authorization gates all allow it. Its
`check.openWorldHint` is therefore `true`.

## Host auto-review is a separate gate

An auto-review host can hold or refuse a policy-route `check` before FinishUP receives it. That is host
tool-call authorization, not a FinishUP AI-powered review result: no review status, provider attempt,
or dispatch can be inferred from it.

For an explicitly requested AI-powered review or `semantic_required` check, the agent must pause and
present manual approval for that exact proposed request. Approval permits the host to invoke the
check only; it cannot alter FinishUP's provider, repository, privacy, disclosure, credential, or
dispatch authority. Once approved, the agent uses the same body and `request_id`. If the host
denies or the approval expires, the agent may use a local-only fallback only after the user
explicitly chooses it after seeing the AI-powered review limitation. A later FinishUP
`awaiting_human` result remains a separate FinishUP decision flow.

## Local workflow calls and host holds

`start`, `publish_work`, `respond`, and `receipt` append records to the local FinishUP ledger. They do
not publish to GitHub or invoke an AI-powered review provider. `status` and `read_guidance` read
local or packaged state. These effects describe what FinishUP does after it receives a call; the host
still decides whether to invoke an MCP tool.

If an auto-review host holds one of these calls, treat the hold as a host authorization event, not
as a FinishUP result. Use the host's visible approval control for that exact call when you want to
continue, then let the host execute that held call and continue from its returned result. If the
host requires resubmission or the response is unavailable, resend the same request body and
`request_id`. If a call may have started but its result is unclear, recover the operation through
`status view=operation` or replay the same `request_id` according to the operation's recovery
instructions; do not mint replacement requests or duplicate event identities. A host refusal
before invocation creates no FinishUP operation, review status, provider attempt, or receipt.

## Letting an auto-review host admit the authorized check

Claude Code auto mode, Codex `approvals_reviewer = "auto_review"`, and Cursor Auto-review each
put a second model in front of tool calls. All three refuse the same shape — data leaving the
machine to a destination the user did not name — and FinishUP's policy-route `check` is, by
design, exactly that shape. The privacy ceremony where you named that destination is invisible
to the host's reviewer, so without help every `semantic_required` check is held or refused.

Host admission is the way to hand the host your decision. It is one previewed, digest-bound step
per host and per repository that writes the host's *own* rule admitting exactly `check`:

```text
finishup integrate claude admission preview --project-root . --claude-path ... --claude-config-root ... --cache-root ... --marketplace-root ...
finishup integrate codex  admission preview --project-root .
finishup integrate cursor admission preview --project-root . --cursor-config-root ...
finishup integrate <host> admission grant --project-root . --accept --preview-digest <digest>
```

The preview shows the exact file and entry, the observed route, and whether the repository's
privacy grant permits external review. A grant is written only when all of these hold:

- the host's registered FinishUP route is `policy` (a strict route is never admitted; `check` on
  it still returns `blocked_by_policy` / `route_semantic_ceiling`);
- the repository grant permits external review;
- the host file carries no wider or conflicting rule for the same tool. A server-wide allow, a
  wildcard, a deny rule, or a Codex server-level default is reported as `foreign` and never
  edited or written beside;
- the file could be read. An unreadable file is `unknown`, never treated as empty.

Host admission currently covers only `check`, which includes `check` with `mode: inspect`: hosts
approve tools, not modes, so an inspection is admitted or held exactly like any check even though
it records nothing and sends nothing. If a host holds an inspection, nothing is waiting in FinishUP and
the agent reads `status` instead. The other operations remain local or read-only, but an
auto-review host may still hold a non-allowlisted MCP call. FinishUP cannot guarantee that a host
will admit any call, and no host hold should be described as a FinishUP privacy denial or AI-powered
review result.

What each host receives:

- **Claude Code** — `permissions.allow: ["mcp__finishup__check"]` for an external registration named
  `finishup`, or
  `permissions.allow: ["mcp__plugin_finishup_finishup__check"]` for the plugin-owned route in the
  repository's `.claude/settings.local.json`, which Claude Code resolves before its auto-mode
  classifier. Pass `--checkpoint` to write `permissions.ask` instead, which keeps a human prompt
  on every check that the classifier can never auto-approve. Granting the other mode later moves
  the existing entry between `allow` and `ask`; only granting the mode already set is a no-op.
  Claude Code holds the rules in this file until you trust the folder if the file is tracked in git.
- **Codex** — `[mcp_servers.finishup.tools.check] approval_mode = "approve"` (or the
  `plugins."finishup@finishup".mcp_servers.finishup` form for a plugin-managed route) in the project's
  `.codex/config.toml`, which Codex loads only for a project you have trusted. The reviewer is
  not invoked for that one tool; every other tool keeps its approval mode.
- **Cursor** — `mcpAllowlist: ["finishup:check"]` in the workspace's `.cursor/permissions.json`
  for Auto-review, and `Mcp(finishup:check)` (or `Mcp(plugin-finishup-finishup:check)` for a
  plugin-bundled server) in `.cursor/cli.json` for the Agent CLI.

The preview warns `host_config_not_compare_and_swap` for a mutation. Quit or pause settings
editors and other processes that may rewrite these host files while applying the accepted preview.
FinishUP rechecks the exact bytes immediately before each atomic replacement or deletion and verifies
the result, but an ordinary host configuration file has no portable compare-and-swap operation
that can exclude a non-cooperating process in the final filesystem syscall window.

At session start, FinishUP may show a short notice when a fresh read confirms your repository grant
allows external AI review but the host has no project admission entry for `check`. The notice names
the admission command for your host. It describes the grant at startup; it does not confirm the
active connection can dispatch review or approve a held tool call. If the read cannot finish in the
available time, or other task context fills the message, the notice is omitted. Its absence does
not mean you revoked consent. The existing host approval flow and FinishUP's current gates still apply.

### The way out

Every way in has a way out, and each is reported rather than silent:

- `finishup integrate <host> admission preview --action revoke --project-root .` then `revoke`
  removes exactly the entry FinishUP wrote and nothing else in the file.
- Committing a privacy policy that no longer permits external review removes the entries for
  that repository in the same trusted ceremony.
- Removing the host plugin, unregistering the Codex route, or re-registering a route as strict
  removes the entry for the project named in that command.
- A leftover entry — one whose grant no longer permits review, or whose Codex route is now
  strict — is reported as `host_admission_drift` by `finishup provider status`. That report reads
  each host's project-scoped admission file at the repository root even when you launch the
  command from a subdirectory.

Tightening the machine-wide ceiling does not reach into every repository's host files; the drift
report and the revoke command are how those are found and cleared.

### What admission does not do

Admission is host tool-call authorization. It does not prove a check dispatched, does not widen
what FinishUP may disclose, and does not skip any privacy, provider, credential, or human-review
gate; `check` still cannot widen policy and still stops at `awaiting_human` when FinishUP decides
it should. FinishUP never ships a hook that approves its own tool calls, and never softens the
`openWorldHint` a reviewer reads. When Claude Code auto mode denies a scoped `check` anyway,
`finishup observe status` records one payload-free `host_auto_review_denied` diagnostic so the hold
is visible as what it is, not as an AI-powered review result.

### When Claude Code holds a check you already authorized

In Claude Code, FinishUP can show you whether this repository's privacy grant permits external
AI-powered review. When it confirms the grant and Claude's classifier returned a verdict, the
hook may offer one retry in the session. Claude shows the notice to you and gives the agent a
retry cue. The agent must preserve the exact request and ask you after another hold. A missing
or unreadable grant, unknown verdict, or unavailable retry record produces no retry.

The notice does not approve a tool call or change settings. Higher-priority host instructions,
your explicit denial, the MCP route and FinishUP's disclosure gates still apply. The durable owner
choice is `finishup integrate claude admission grant`, with `admission revoke` as its reverse.
Codex and Cursor retain the pause-and-ask workflow. Live acceptance of the new Claude notice and
retry cue is still pending; it is not proof that a provider received or reviewed anything.

## Codex registration

`finishup setup run` and `finishup integrate codex mcp preview` show the exact command, route profile, and
digest before registration. A zero-egress setup selects the strict command. If provider/privacy
posture later changes, preview again: a FinishUP-owned registration with the other route profile is a
re-registration, not a silent mutation. A foreign entry named `finishup` is never overwritten.

Inspect the active route through MCP initialize instructions or `status(view=versions)`. Registration
proves only the configured command; it does not prove that a host has launched it or that a provider
is ready. On the policy route the initialize instructions also name the AI-powered review
destination FinishUP read when the bridge started — the provider, endpoint profile, and host, or the
Codex runtime class — together with the payload bound; that passage is a disclosure for the host's
reviewer, not an approval, and it changes only when the host restarts the bridge.
