# Required startup for native Claude Code and Cursor

Issue [#692](https://github.com/TheGaySupreme123/finishup/issues/692) adds an owner-selected tool gate.
Optional cooperative startup remains the default for new installations. This is a workflow
constraint, not a security sandbox or evidence that a plan is correct.

## Enable, inspect, disable

Use the existing [Claude](claude-code-integration.md) or [Cursor](cursor-integration.md) plugin
lifecycle, retaining its explicit roots and digest-bound approval. Add `--startup-mode required`
to preview and apply: Claude uses `install`/`update`; Cursor uses `install`/`replace`.
The mode changes the artifact digest. An approval for optional bytes cannot install required bytes.

`integrate <host> plugin status --json` reports the selected `startup_mode` and
`installed_startup_mode`. Omitting the option preserves a marker-verified installed mode, including
the common setup connection flow. New installations default to optional. Foreign or modified
trees remain protected; an unverified installed mode is null.

To disable, preview and apply an update/replace with `--startup-mode optional`, then reload the
host plugin or start a fresh session. Existing disable/remove/disconnect controls also remove its
effect. Do not edit generated hooks. Inert private gate records do not delete tasks, findings,
receipts or pending writes. Claude's `plugin export --development-enabled --startup-mode required`
renders a development carrier without installing it; this is not marketplace activation.
Codex and the portable Cursor Agent Plugins format refuse required mode.

## Agent behavior

Every native plugin carries a separate startup-context command. It reads packaged guidance without
reading stdin, host configuration, observation state, vault or ledger. Disabled, paused, contended
or unavailable observation therefore cannot suppress the static instruction. The observation
hook still owns mapping, observation and dynamic advice.

In required mode, a new host session calls cooperative `start` or `start mode=attach`, then
publishes an accepted plan with effective obligations before reads, edits, shell work or delegation.
Each user-prompt boundary starts a new scope generation: keep the task and route, then publish a
fresh plan revision or exact next-version restatement. Resume/compaction also requires fresh scope.
Empty plans do not admit tools. Text-only trivial answers need no bootstrap; even a small edit
uses tools and needs a plan in required mode. Optional mode keeps its usual trivial-work exception.

Tool/schema discovery, the FinishUP skill, registered guidance, clarification and FinishUP workflow calls
remain possible. Direct commands through the current runtime's exact FinishUP launcher for service
status/diagnostics/restart, consent catalog/prepare/status/review/authorize and vault unlock reach
normal host admission. Pipelines, substitutions, compound commands and other launchers do not
qualify. This grants no repair, consent, credential or disclosure authority: the typed continuation,
current user instruction and existing owner ceremony still apply.

Cursor's ordinary pre-tool observer remains installed and retains attempt capture. It emits a
valid pass-through permission response even when observation is disabled or fails; an empty JSON
object at that boundary can block the tool under Cursor's contract. The required gate's denial
and the separate native MCP admission boundary remain independent.

Delegation is substantive. A delegate sharing the same host session uses its parent's current
accepted scope; a separate host session must bootstrap. This does not transfer evidence or prove
delegated work correct. Claude emits denial while unready and no permission decision when ready.
Cursor uses generic `preToolUse` plus server-qualified `beforeMCPExecution`; unqualified `MCP:start`
cannot identify its server. Admitted MCP calls return `ask`, never `allow`, including `check`.
Required mode may therefore add native approval prompts; ADR-018's admission boundary is preserved.

## Readiness and recovery

A private per-host-session/workspace sidecar retains generated scope epochs, protocol ids, effective
plan/obligation ids and bounded pending request identities. It stores no prompt, tool or plan prose,
transcript, credential, or model-authored readiness flag. Before start/publication, the gate records
the request identity. Only matching accepted output can nominate a route and plan. Newly accepted
obligations must be in that plan. Failed/dry-run writes, old accepted timestamps, wrong routes and
earlier-scope responses cannot create current readiness. Hook auto-mapping alone is insufficient.

Before every substantive call, a deadline-limited child reads live `status view=compact` through
the normal repository-bound service connection. It validates the exact task/session/writer,
current plan event, declared count and readable current projection. It never auto-starts a service,
reads SQLite directly, or trusts a cached ready bit. A second sidecar read fences concurrent changes.

Unknown writes keep their request identities across scope boundaries. Operation-status recovery
remains available: absent permits the documented same-request retry; complete releases its gate
ticket and requires a fresh accepted scope restatement without replaying a complete write.
Pending/quarantined remain blocked for substantive tools. Findings are not discarded and no sibling
is created. Completion still uses check/respond/receipt with actual coverage.

The sidecar tracks host calls it receives. External participants must publish a new effective plan
for new scope; a replacement live plan invalidates the nominated plan. Missing-obligation checks
are bounded to accepted publications tracked in this host scope. This gate cannot judge whether
plan prose matches the user's intent.

## Outages and capability limits

Gate locks are nonblocking and independent of observation locks, capture, spool, drain and advice.
The service probe has a 650 ms asynchronous budget inside a 1.25 s subprocess deadline; gate hooks
have a 3 s host timeout. Controlled failures at a block-capable boundary deny substantive tools.
Bootstrap still reaches normal host admission even when gate state is unreadable. Errors expose only
closed reasons, never payloads.

Tracked bootstrap `start` and `publish_work` calls are admitted only after their request identity is
persisted under the sidecar lock. Lock contention or a state-write failure therefore denies that
tracked call; read-only workflow/status recovery remains available and no unrecorded write is
treated as admitted.

A user-prompt reset writes a new scope before clearing the prior invalidation marker. If that write
fails, the marker makes ordinary readers fail closed; the next reset reads the old sidecar only while
holding the reset lock, so its route and every pending request identity survive recovery. If the
marker is present, tracked bootstrap writes receive `scope_reset_required` and teardown does not
replace the sidecar, while status and operation recovery remain available. The
marker itself cannot be created because the state directory is unavailable, Claude
`UserPromptSubmit` returns its native `decision: block` result and Cursor `beforeSubmitPrompt`
returns `continue: false`. Claude `SessionStart` and Cursor `sessionStart` are context-only events;
they report the bounded storage error but cannot block the first prompt or tool. A storage fault at
that boundary therefore remains an explicit limit on fail-closed coverage until the host reaches a
block-capable prompt or tool hook, and this feature does not claim universal fail-closed behavior.

These budgets do not guarantee OS scheduling before the host kills a command.
[Claude's contract](https://code.claude.com/docs/en/hooks#timeouts) lets command-hook timeouts proceed
through normal permissions; a missing executable or disabled hook cannot enforce the gate.
Do not call this universally fail-closed. [Cursor documents](https://cursor.com/docs/hooks)
`failClosed`; required permission hooks set it, but the exact version still needs native proof.
Ordinary observation retains its separate fail-open policy.

## Acceptance evidence

Source tests cover both payloads, denied reads/delegation, accepted bootstrap, scope renewal,
stale/wrong/dry-run/failed publication, missing effective obligations, lost-response recovery,
concurrent invalidation, real status projection, and install/inspect/reverse controls.

On 2026-09-21, an isolated, pinned 0.2.4 development wheel was loaded through `claude-testing`'s
Claude Code 2.1.261 executable in interactive auto mode on macOS arm64. A controlled pre-bootstrap
`Read` returned an actual native tool error `current_plan_required`, without file content.
That establishes this denial only, not successful bootstrap or native delegation.

Still owed on #692: native success after real accepted bootstrap, native delegation denial and
pending recovery, regular Cursor desktop execution/approval behavior, and Linux/WSL 2 host runs.
Test-vault initialization and host installation retain their own consent requirements. Codex,
portable Cursor CLI, native Windows, mobile and cloud enforcement are not claimed.
