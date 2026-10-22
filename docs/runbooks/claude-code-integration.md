# Claude Code native integration

Reviewer robustness (#1134–#1137, #1141) applies to Claude Code through the shared service:
oversized native reads are withheld, sampled listings disclose inspection exhaustion, and read
capacity is distinct from invalid replies. Codex session cleanup and notification bounds also
apply when the configured review provider is Codex; they do not depend on the agent host. This is
shared behavior on macOS, Linux and WSL 2, without claiming new native acceptance. See
[the reviewer contract](../INTERFACES.md#reviewer-loop-issue-1118-unit-2).

MCP input advertisements use the same compact schema as Codex and Cursor, targeting 4,800 bytes
per tool. Required fields, enums and event envelopes remain inline; payload variants, conditional
field rules and full examples are available through `read_guidance` at
`finishup://guidance/request-templates.md`. Read the matching template before authoring a payload.
Deferred tool discovery uses this same advertisement. Full server validation, repair hints and
output schemas remain unchanged; the smaller advertisement does not expand accepted requests.
Descriptions remain when they fit, with priority field rules restored first for larger tools.
If the description-free form exceeds the CI budget, the bridge emits
`mcp_advertised_input_schema_over_budget` and still serves that minimal form; CI rejects the drift.

Codex's external MCP removal reconciliation (issue #860) does not apply to Claude Code:
Claude's plugin-managed MCP follows the plugin lifecycle below. No Claude mutation or outcome
contract changes are required for that Codex-specific host command.

For setup prerequisites, use `finishup setup status --next --host claude` with the same
executable, configuration root and project. `--operation connection` inspects installation without
provider sign-in; `local` and `review` inspect their respective vault/privacy prerequisites.
Storage-only continuation is `finishup setup vault` in a trusted terminal. This shared #737 path adds
no new native-session capability; Linux/WSL first-use and storage acceptance remain bounded by
[the platform runbook](linux-and-wsl.md#setup-and-vault-acceptance-still-owned-by-737).

AI-review setup decision (#1119, 2026-10-19): use the shared `finishup ai setup` / `/provider`
question and `finishup ai key` in the owner's terminal; ChatGPT review is a separate Codex-owned
login regardless of the connected agent. Agent opt-in remains recommended, Not now records
local-only review, and `ai off` reverses it. Privacy widening and confidential entry retain their
existing ceremonies on macOS, Linux and WSL 2; native host/platform parity is not inferred from
these shared-flow tests. Individual stored-key removal remains a #1119 follow-up; revocation at
the provider invalidates the key.

## Guided desktop connection (issue #767)

Prefer `finishup setup run --host claude` for ordinary setup. It discovers the executable and
configuration root, derives the cache and private marketplace paths, and previews installation
plus enablement in one exact connection plan. Override the executable/configuration or project
with `--host-path`, `--host-config-root`, and `--project`. Agent-driven setup uses
`--non-interactive --json`, then repeats the preview's request ID and digest with `--accept`.
The existing OS-authenticated artifact review still applies. Status and disconnect use
`finishup setup status|disconnect --host claude` with the same target options. Standalone `plugin
install` below retains its disabled-by-default behavior.

**Several projects in one config root (issue #1058).** The marketplace source under
`<config root>/plugins/marketplaces/finishup-local` and its `known_marketplaces.json` entry are shared
by every project; each project has its own project-scope install, enable flag and
`.claude/settings.json` `extraKnownMarketplaces` declaration. Verified with Claude Code 2.1.299
against a scratch `CLAUDE_CONFIG_DIR`: `claude plugin list --json` lists one `finishup@finishup-local`
row per project, each with its `projectPath`, from any working directory, and the unscoped
`claude plugin marketplace remove finishup-local` removes every project's install. FinishUP therefore
reads its own project's row only (other rows are not a conflict), and a disconnect while another
project still has its row plans `uninstall_plugin` alone: the other projects keep the shared
source and marketplace, the disconnected project's own exact `extraKnownMarketplaces`
declaration is removed (Claude's project-scope uninstall keeps it; an edited declaration stays
yours), and the preview's `status.shared_with` names them. A project detached before this fix
still declares a source that the last disconnect removed; setup treats that exact declaration
as repairable prior setup and connects over it. The last project's disconnect
removes the marketplace and its source as before. Status reports `connected_projects`. Claude
Code's own rows name the projects, so no FinishUP record is kept for this host. A second path to an
already connected directory is refused as `project_connected_via_other_path`. Because the shared
source carries the launcher and route, connecting a project with another route or launcher
re-renders it for every project. `setup disconnect --remove-shared` is the explicit home-wide disconnect:
it runs the marketplace removal even while other projects keep their rows, so they stop using
FinishUP too. A disconnect whose approval file (`.claude/settings.local.json`) cannot be read safely,
such as a symlink, stops before any change as `connection_admission_cleanup_failed`.
Because Claude Code's rows are the membership, this host has no unknown membership (a Codex and
Cursor state), no possible users or `membership_unverified` refusal (Codex only), and no
connected-projects record (so no `connection_projects_record_invalid`). Claude Code keeps the row
of a project whose directory was deleted; FinishUP counts only live projects, in the preview and in
apply alike, so such a row holds nothing open and the last live project's disconnect (an unscoped
`marketplace remove`) clears it too. A disconnect whose own project-scope install is already gone
(Claude Code refuses to uninstall it again) plans only `remove_marketplace` and
`remove_plugin_mcp`. Known gap (recorded 2026-10-15, #1058 review round 3; follow-up on #1058):
such a project, or one that never had an install, can still remove the shared marketplace and
source while the only other project's directory is missing for now (an unmounted volume, a
moved checkout), because a missing directory counts as not live. Codex keeps the shared pieces
in that case (its binding still names the missing project, and only a connected project may
remove such a binding); Claude Code has no equivalent anchor yet. The unscoped marketplace
removal also removes that project's install, so when its directory returns it needs connecting
again. The preview names `remove_marketplace` before approval. The shared source carries the plugin MCP server's review mode for every
project's install: connecting a project on another review mode re-renders it for all of them, and
the preview names them (`status.route_profile_before`, `status.route_changes_for`, and a summary
sentence with both modes). `integrate claude plugin preview` reports the same keys and sentence
for an install or update on another review mode; its preview digest already binds every
project's install row (`installed_plugins.json`), and its apply needs that digest and the OS
password prompt. `integrate claude plugin remove` removes this project's install and, like
`setup disconnect`, keeps the shared marketplace while another live project has its row. `--remove-shared` previews and the interactive consent say the
disconnect is home-wide and name the projects that stop using FinishUP. The TUI has no
`--remove-shared`; use `finishup setup disconnect --host claude --remove-shared`. Like every
host, each setup apply holds FinishUP's per-configuration lock from revalidation through the last
change: an exclusive `flock` on a 0600 file under FinishUP's own state directory
(`host-config-locks/`), keyed by the config root's resolved path, NFC, case-folded, never inside
the Claude config root. A lock that cannot be taken stops as `connection_lock_unavailable` before
any change, naming the lock folder. It does not serialise a setup run by another FinishUP
installation. Untested: a state directory on NFS, SMB/CIFS, WSL DrvFS (`/mnt/c`) or another
network or FUSE filesystem (ADR-012 amendment item 7).

Native evidence, Linux x86_64 (ext4), Claude Code 2.1.300, scratch `HOME`, `CLAUDE_CONFIG_DIR`,
XDG and isolation root (2026-10-14 and, for the review fixes, 2026-10-15, #1058; these runs predate
the FinishUP rename (ADR-048) and used the Yoetz names, shown below as their FinishUP equivalents,
and were not re-run on the renamed build). Plans were
prepared and applied through the same
`prepare_selected`/`apply_connection` composition `setup run|disconnect --host claude` uses; the
one substitution is the OS-presence review (the trusted PAM console prompt), which the container
cannot provide, so a test stub consumed the exact plan digest. `setup status` and the disconnect
preview were also read through the real CLI and agreed.

| Scenario | Result |
| --- | --- |
| Connect A and B; disconnect A, then B; reconnect A | A's disconnect plans `uninstall_plugin` alone with `shared_with` B; B keeps its enabled row and `finishup-local` stays in `claude plugin marketplace list`; B's disconnect removes the marketplace; reconnecting A succeeds (no `destination_conflict`) and its row is enabled |
| Connect A and B; disconnect B, then A; reconnect B, then A | Same in reverse: each step leaves the remaining project's row enabled; both reconnect, and the second reconnect lists the first in `shared_with` |
| First setup with `CLAUDE_CONFIG_DIR` under parents that do not exist yet | Connects; the plugin row is listed |
| Connect A and B; `rm -rf A`; disconnect B (2026-10-15) | the plan is `uninstall_plugin`, `remove_marketplace`, `remove_plugin_mcp`; apply removes the marketplace, and `claude plugin list` no longer shows A's dead row |
| Connect A and B; `rm -rf A`; `claude plugin uninstall --scope project` in B; disconnect B | a second uninstall fails in Claude Code 2.1.300 (`not installed in project scope`); the plan is `remove_marketplace`, `remove_plugin_mcp` and completes with no marketplace left |
| Connect A on `strict`; connect B on `policy` | B's plan discloses `route_profile_before: strict`, `route_changes_for: [A]`; the shared source's `.mcp.json` then runs the policy route |
| Then `integrate claude plugin preview --claude-path ... --claude-config-root ... --cache-root ... --marketplace-root ... --project-root A --mcp-ownership plugin-managed --route-profile strict --action update` (round 2) | `route_profile_before: policy`, `route_changes_for: [B]`. A route profile needs `--mcp-ownership plugin-managed`; without it the command refuses as `claude_code_mcp_route_forbidden` |

On macOS the presence step uses LocalAuthentication; Linux and WSL 2 use the trusted PAM console
path. A missing mechanism is a reported local continuation, not permission to bypass it. The
common connection code does not establish native acceptance on any OS. Track current exact-head
macOS/Linux/WSL installation, status, repeat setup, disconnect and reconnect evidence
in #767. Provider authentication and model sessions are outside that installation acceptance. Existing capability records below remain bounded to their recorded cells. Ownership,
configuration, enablement, session activation, observation and review remain separate proof layers.
Claude may delete its private marketplace source during native removal; FinishUP accepts that
already-absent source and still verifies the final registration and installation state.
The command sequence follows the [official marketplace CLI reference](https://code.claude.com/docs/en/plugin-marketplaces#manage-marketplaces-from-the-cli).

## Conditional agent guidance

The skill keeps its activation boundary, core workflow, and safety floor in the entrypoint.
Before `start` read the core, `agent-instructions.md`: it is the operating card and is enough for
ordinary work. Workflow, publication policy, and coverage and receipts are read only when a result,
error or continuation names them, or when unsure; no status read or dry run is required before a
write, and `check` with `mode: inspect` gives the picture in one read (ADR-047). Setup/consent, vault/credential operations, transcript import, and
recommendation decisions route to the corresponding sections of request templates only when
needed. Already-read guidance need not be fetched again while present in context.

When Claude's model-visible tool result could clip a large guidance document, use the
`read_guidance/1.1.0` page route with a bounded UTF-8 `page_size`. Keep the begin/end markers from
each page, carry its revision/digest continuation, and pass the exact marked text to
`GuidancePageAssembler` before treating the document as loaded. The URI-only request remains
unchanged for callers that explicitly request the full source; native fresh/resumed/compacted
Claude acceptance for the page route remains a pending dogfood lane.

Use `semantic_if_configured` only when AI-powered review is known to be optional; omit `mode` when
relying on the configured default. Select `semantic_required` for an explicit user requirement,
effective policy, or named acceptance criterion requiring independent AI-powered judgment. Preserve
required review and all host/disclosure approval boundaries. Installed guidance bytes alone prove
neither activation nor AI-powered review dispatch.

The native plugin selects `skills/claude-code/finishup/SKILL.md`. Its entrypoint names
`/finishup:finishup`, uses the declared MCP namespace, reads installed references on demand, and refreshes
FinishUP status after Claude resume or compaction. `SessionStart` additional context is a bounded cue;
replayed session context does not establish the current ledger frontier. Plugin replacement uses
Claude's documented `/reload-plugins` or a new session, followed by loaded-root and digest checks.

A new Claude session reads guidance and discovers tool schemas before calling MCP `start` as
its first workflow operation, before substantive research, commands, edits, or delegation.
Guidance reads (including `read_guidance`), discovery commands, and necessary bootstrap clarification
remain permitted. Hook auto-attachment is a cue, not proof of a current-scope plan: mapped
SessionStart context directs cooperative `start mode=attach` before `status` with the returned
ids; unmapped context directs `start` before material work. Same-session compaction uses held
current ids for `status`. Both startup messages route failures through exact continuations,
same-request recovery, and a named one-time repair before a blocked-startup user handoff.
A first non-retryable failure alone does not permit continuing without FinishUP; see
[startup failure precedence](../../guidance/coverage-and-receipts.md#startup-failure-precedence).
Native plugins can select `--startup-mode required` through the owner-reviewed lifecycle.
See [required startup](required-startup.md) for current-plan gating, opt-out, recovery and native
acceptance limits. Optional instruction delivery alone remains non-enforcing.

### Instruction delivery on Claude Code (issue #789)

Observed host facts, not documented Claude limits. Measured 2026-09-21 in Claude Code desktop
sessions on the maintainer's machine against the installed 0.2.1 bridge, by comparing the
rendered system-prompt attachment with the packaged text:

- Claude Code renders MCP initialize `instructions` as a per-server block and keeps exactly the
  first **2,048 characters**, then appends a literal `… [truncated]` marker. In the historical
  session, the installed 0.2.1 bridge supplied a 7,325-character `agent-instructions.md` block;
  it was the only server block cut on that machine and ended mid-sentence before the `start` rule.
  The current source candidate is 7,791 bytes before rendering, so that source measurement is not
  presented as a re-measurement of the historical desktop session. Other servers' blocks (about
  1.1–1.3 KB) were intact.
- The same cap applies to each tool description once Claude loads it. Current source measurements
  are `start` (2,140 chars), `publish_work` (3,065) and `check` (4,192); each exceeds the cap and
  remains a separate, host-independent follow-up recorded on the issue.
- With about 200 registered tools, Claude Code defers MCP tool schemas: only names appear until the
  agent runs `ToolSearch` for them. The initialize block is therefore the only unsolicited cue.
- The FinishUP server is often still connecting when the agent takes its first action; its tools
  and instructions then arrive one message later.

The bridge therefore serves a Claude-specific initialize body: `finishup mcp serve --host claude`
renders `CLAUDE_CODE_INITIALIZE_INSTRUCTIONS` (at most `packaged_max_chars` = 964 characters),
whose first two sentences are the trigger and the late-start rule, followed by the same route tail
and startup-read destination disclosure (#479) as every other host. The bound is derived so that
the text, the policy tail and the 1,000-byte disclosure ceiling fit under 2,048 together: the
privacy disclosure is never the part that gets cut. The `generic` host keeps the full document
byte for byte; since #918 `codex` and `cursor` receive their own compact body (see the Codex and
Cursor runbooks), and the Claude body and Claude `read_guidance` results are unchanged by it.
`tests/packaging/test_claude_code_instructions_cap.py` fails when the Claude text outgrows the
recorded cap; `tests/unit/mcp/test_claude_code_instructions.py` locks the sentence order, the
arithmetic and the generic host's identity, and `tests/unit/mcp/test_compact_host_instructions.py`
pins the Claude body's digest. Everything the compact
body omits is one `read_guidance` call away. Claude renders the same block into native
subagents, which receive no hook cue saying they are children, so the trigger paragraph exempts a
subagent whose assignment names neither an attach handle nor a parent session (#509). The parent
still says so in the assignment in plain words, as the workflow's child-assignment rules require.

Activation cues by connection mode:

| Mode | How it is registered | Initialize instructions | SessionStart cue | Skill |
| --- | --- | --- | --- | --- |
| Plugin-managed | `finishup setup run --host claude` (or `finishup integrate claude plugin install`) renders the marketplace, hooks and plugin-owned `.mcp.json` | yes (compact body) | yes, once the plugin is enabled | `/finishup:finishup` |
| Bare MCP | An owner-written `finishup mcp serve --host claude` entry in Claude's own MCP configuration | yes (compact body when `--host claude` is present; generic body for a legacy bare `mcp serve` entry) | **no** | none |

A bare entry delivers only the initialize block; it has no `SessionStart` context, no
auto-attach, no hooks and no skill catalog entry. `finishup setup status --json` names the mode
per discovered Claude installation under `hosts[].activation_cues`: `mcp_mode`
(`plugin_managed`, `bare_mcp`, `dual`, `absent`, `foreign`, `ambiguous`), `mcp_source`,
`route_profile`, `host_profile` (`claude` for the compact initialize body, `generic` for a legacy
bare `mcp serve` entry), `session_start_cue` (`installed`, `absent`, `unobserved`) and `cue_sources`
(`plugin_hooks`, `user_settings`, `project_settings`, `project_local_settings`). The
observation is file-only: it reads Claude's user configuration where Claude keeps it
(`~/.claude.json` beside the default `~/.claude` root, or inside `CLAUDE_CONFIG_DIR`), the
project `.mcp.json`, the managed marketplace and the settings hook files. It does not prove that
the plugin is enabled, that a hook ran, or that a session called `start`. Shipping a
`SessionStart` cue for bare registrations (issue #789 item 3a) is a host-registration change
that remains open with the maintainer as owner; until then the documented remedy for a bare entry
is the guided connection. The repository's own `AGENTS.md` states the `start`/receipt expectation
for material work in this checkout, since the highest-priority instruction layer was silent.

Design basis, checked 2026-09-09: Claude's [skills guidance](https://code.claude.com/docs/en/skills)
recommends a use-case-first description and concise instructions with supporting references.
FinishUP keeps this workflow in the conversation because a forked skill lacks that conversation's
history. The [plugin guide](https://code.claude.com/docs/en/plugins) supplies the namespaced
invocation; [hooks](https://code.claude.com/docs/en/hooks) and
[sessions](https://code.claude.com/docs/en/sessions) explain the reload/resume context. FinishUP does
not add `allowed-tools` or an automatic fork. The independent startup cue and optional required
gate are described in the required-startup runbook. The five shared
references still own evidence, consent, and receipt semantics. These sources justify instruction
design, not a new tested Claude version or native behavioral acceptance result.

Anthropic's own [example skill](https://github.com/anthropics/claude-plugins-official/blob/main/plugins/example-plugin/skills/example-skill/SKILL.md)
and [skill-development skill](https://github.com/anthropics/claude-code/blob/main/plugins/plugin-dev/skills/skill-development/SKILL.md)
use focused activation descriptions, imperative procedures, and links to supporting files. The
Claude FinishUP entrypoint follows those patterns and addresses Claude directly; it does not ask the
agent to identify which host is reading it or carry another host's restart instructions.


This runbook covers exactly one cell: Claude Code CLI `2.1.241` as a local process, project scope,
native marketplace-installed plugin, and an explicit private directory marketplace. It does not
claim that Claude Code consumes Agent Plugins. It also does not transfer proof to Claude Desktop,
remote/web/cloud, synced/managed/user/local scopes, Agent SDK, or headless sessions.

## Linux and WSL

Installation evidence (2026-09-20, issue #767): the installed 0.2.4 wheel passed preview,
connect, status, repeat/no-op, disconnect and reconnect with Claude Code `2.1.261` on Ubuntu
24.04 x86-64 and Ubuntu 24.04 inside actual WSL 2. Real PAM approval succeeded with disposable
local accounts. The [acceptance record](https://github.com/TheGaySupreme123/finishup/issues/767#issuecomment-5750168131)
binds the source, wheel digest and outcomes. Provider login and model runs were outside that
installation acceptance.

Decision (issue #722): native-session capability on Linux and WSL 2 remains **unproven**.
The separate Linux PAM approval work (#719) supplies the plugin mutation ceremony; builds
without that cell refuse `human_authority_unavailable` on non-macOS hosts. Check the installed
preview's `authorization.human_presence` before proceeding. A supported presence mechanism is
not native host evidence: Linux CLI activation and observation still need their own evidence.
`preview` and `status` are read-only, and the rendered artifact is host-neutral. Claude Code
inside WSL 2 can use FinishUP over MCP with its own `finishup mcp serve` entry; that alone establishes
neither hook observation nor a proven cell. The reviewed evidence case stays `claude-code-cli-native-project-2.1.241-macos-arm64`;
a Linux x86-64 evidence case for the CLI cell is outstanding and will be admitted alongside the
macOS case, not in place of it. Windows-native Claude Code against a WSL FinishUP is untested and not
claimed. Host facts shared with the other hosts (state location, keyring, sandbox, platform cells)
are in [`linux-and-wsl.md`](linux-and-wsl.md).

## What FinishUP generates

Claude Code keeps the native carrier's marker-bound launcher identity described below. The
installed-RECORD proof added for Codex external registration in #654 does not classify Claude
sources or establish Claude activation; use this host's source-precedence and native-plugin checks.

The managed marketplace source contains:

```text
.claude-plugin/marketplace.json
.yoetz-claude-marketplace-install.json
plugins/finishup/.claude-plugin/plugin.json
plugins/finishup/skills/finishup/SKILL.md
plugins/finishup/skills/finishup/references/...
plugins/finishup/hooks/hooks.json
plugins/finishup/.mcp.json                 # plugin-managed mode only
```

The marketplace entry is `strict:true`, declares only relative source `./plugins/finishup`, and does
not redefine plugin components. The plugin manifest is authoritative and sets
`defaultEnabled:false`. Every hook command and the plugin-owned `.mcp.json` entry launch the exact
`finishup` that rendered the plugin (absolute executable, or `<interpreter> -m finishup`), recorded in the
source marker; a bare PATH `finishup` is never written, so the bridge, hooks, and service cannot come
from different installations. Re-render (`update`) after moving or reinstalling FinishUP. The native
entrypoint and five shared references come from their canonical packaged sources; the references
are byte-identical across host projections. FinishUP writes no credentials, endpoints, user config, ledger,
vault, receipt, or provider state into the plugin, `${CLAUDE_PLUGIN_ROOT}`, or
`${CLAUDE_PLUGIN_DATA}`.

The plugin-owned `.mcp.json` starts the bridge with the explicit `--host claude` identity (and
`--semantic off` for the strict route). This identifies the serving carrier for diagnostics; it
does not grant host admission or agent-chat attestation.

## Explicit roots

Choose an exact trusted project, exact resolved Claude executable, isolated Claude config/cache,
and private marketplace source. The cache must be exactly
`<claude-config-root>/plugins/cache`. The examples use placeholders intentionally; do not infer
them from ambient `$HOME` or a running session.

```text
CLAUDE_PATH=/absolute/path/to/resolved/claude
PROJECT_ROOT=/absolute/path/to/project
CLAUDE_CONFIG_ROOT=/absolute/path/to/claude-config
CACHE_ROOT=/absolute/path/to/claude-config/plugins/cache
MARKETPLACE_ROOT=/absolute/path/to/private/finishup-marketplace
```

## Preview and install disabled

For plugin-owned strict MCP, preview the exact operation:

```text
finishup integrate claude plugin preview \
  --claude-path "$CLAUDE_PATH" \
  --claude-config-root "$CLAUDE_CONFIG_ROOT" \
  --cache-root "$CACHE_ROOT" \
  --marketplace-root "$MARKETPLACE_ROOT" \
  --project-root "$PROJECT_ROOT" \
  --mcp-ownership plugin-managed \
  --route-profile strict \
  --action install --json
```

Prepare the returned exact digest through the trusted review lane, then replay the returned request
ID and digest with `plugin install --accept`. `--accept` is not authority by itself; the mutation
also consumes a matching `plugin_artifact_apply` pending and fresh OS-authenticated user presence.
The presence cell is chosen per platform and named in the preview under
`authorization.human_presence`: macOS uses Apple LocalAuthentication; Linux, including WSL 2,
re-verifies the invoking account's password through PAM at your own foreground terminal, so run
install, update, enable, disable, and remove from that terminal rather than from a Claude Code
Bash tool, which has no trusted console; any other platform fails closed with
`human_authority_unavailable`. The [Cursor runbook](cursor-integration.md) records each cell,
its failure paths, and the coverage actually proven.
Install admits any Claude version at or above `2.1.233`, where the plugin and hook surfaces exist,
and reports `host.version_provenance` on the preview (`host_version_provenance` on status):
`tested` for the exactly proven `2.1.241` cell, `untested` for any other admitted version
(issue #656). An `untested` host runs the same artifact but earns no proven cell; a version below
the floor is refused as `format_unsupported`. Hook ingress keeps the same distinction: an unknown
`claude_code_version` is admitted as `untested` under the conservative paired contract, never as
the proven profile. It also refuses foreign/dual/ambiguous MCP ownership, unsafe roots, modified
sources, leftover stage/rollback recovery material, or stale previews.

After install, `status` must show `native_managed`, `marketplace_registered:true`,
`discovered:true`, exact version/cache digest, and `enabled:false`. These prove no loaded session.

## Development activation without the marketplace

For dogfooding or CI, export the exact plugin root and load it for one session; nothing under the
Claude config, marketplace, or cache changes, and no review authority is consumed:

```text
finishup integrate claude plugin export \
  --output-root "$DEV_ROOT" \
  --mcp-ownership plugin-managed --route-profile strict \
  --development-enabled --json
CLAUDE_CONFIG_DIR="$CLAUDE_CONFIG_ROOT" "$CLAUDE_PATH" --plugin-dir "$DEV_ROOT" ...
```

`--development-enabled` renders `defaultEnabled:true` (a disabled carrier does not load under
`--plugin-dir`); the tree carries a `.yoetz-claude-plugin-export.json` marker naming that flag, so
status never mistakes it for the marketplace-installed cell, and `preview` refuses it. A development
session proves skill delivery, MCP binding/runtime, hooks, model use, AI-powered review dispatch,
and receipts for the exact bytes, but never marketplace installation, discovery, enablement, or host
activation.

An isolated `CLAUDE_CONFIG_DIR` isolates only Claude Code. When the session's FinishUP must not touch
the live install, also export `FINISHUP_ISOLATED_ROOT` (ADR-026) into the session environment so the
plugin's MCP bridge, hook commands, and any service they spawn derive config, storage, state, and
endpoints from the isolated root; prove it beforehand with `finishup service isolation --json` run
under the same environment.

Issue #561 does not add an external-registration mutation path for Claude Code. The supported
Claude development/plugin route continues to inherit the explicitly exported root from the exact
session environment, and its MCP bridge and hooks must be tested under that same environment. No
Codex registration status or `--env` behavior is inferred for Claude Code.

Issue #604 (ADR-028) adds the executable-bound guard and, again, no mutation path. When the plugin's
hook and MCP commands name the absolute launcher of a pinned test instance (one provisioned with
`finishup instance create --bind-runtime`, which `scripts/provision_test_instance.py` always does),
that launcher resolves the instance's own root even if Claude Code launches it without the exported
variable, and refuses a conflicting variable (`isolation_root_conflict`). The everyday plugin
installation must name the everyday launcher by absolute path, never a bare `finishup` resolved
through `PATH`, so that a test runtime earlier on `PATH` cannot become the host's FinishUP. Verify with
`finishup instance status --json` from the exact launcher the plugin names: `binding` must be
`runtime_pin` or `environment_and_pin` for a test instance and `ambient` for the everyday install.
See [`test-instances.md`](test-instances.md).

Issue #1076 (the Codex plugin cache launching `finishup` through `PATH`) is not this host's
defect. Claude's plugin `.mcp.json` and hooks already name the exact launcher that rendered them
(an absolute executable, or `<interpreter> -m finishup`); a bare PATH command is not written
(ADR-023, 2026-08-27). The plugin MCP entry does not itself stamp `FINISHUP_ISOLATED_ROOT` or
`YOETZ_ISOLATED_ROOT`: the child isolates only when the launching session already exported the
root, which is the #561 contract above. A render asked to discover a launcher with no explicit
path still resolves a name through `PATH` (`resolve_finishup_launcher`); the supported connect
path passes the invoking launcher and does not take that branch. No Claude carrier change is made
for #1076. Follow-up, if a later change wants the bridge to isolate without inheriting the
session environment: stamp both isolation-root spellings into the Claude plugin `.mcp.json` the
way Cursor already does, and keep a no-launcher render from baking a foreign PATH binary.

## Upgrading FinishUP under a running service

The local-control handshake pins the exact schema-manifest digest, so after installing a new FinishUP
build the previous build's service still owning the endpoint refuses the new bridge and CLI. The
first plugin tool call (on-demand startup) replaces that service automatically: it asks the stale
holder to shut down through its ordinary bounded path and starts this installation's service inside
the same 30-second budget. If that cannot complete, the tool returns `SERVICE_UNAVAILABLE` with
`reason_code: service_incompatible` (or `protocol_mismatch` when the refusal is a protocol
generation mismatch) and the repair command; run it on a local terminal:

```text
finishup service restart
```

`finishup service status` names the incompatible holder's pid, version, and manifest digest. Other
hosts' sessions still running the previous build's bridge are refused after the switch until they
restart; that is the intended outcome of an upgrade, not a defect. The cooperative MCP bridge
latches that availability failure for the process and serializes the first on-demand attempt so
concurrent tool calls share one diagnostic (issues #469, #476); that behaviour is shared across
hosts that use this bridge, not Claude-Code-specific.

## Legacy Yoetz registrations

FinishUP was named Yoetz through 0.2.5 (ADR-048). A project connected by Yoetz carries the
`yoetz-local` marketplace (a private source tree at `<config>/plugins/marketplaces/yoetz-local` with
the frozen marker `.yoetz-claude-marketplace-install.json`), the plugin `yoetz@yoetz-local`, the
skill `/yoetz:yoetz`, and possibly owner-written MCP entries under the `yoetz` key. FinishUP reads
these; it writes only `finishup-local`, `finishup@finishup-local` and the `finishup` server name.
Until migration the old plugin keeps working: hooks, start binding, the startup gate and tool
classification accept `mcp__yoetz__*`, `mcp__plugin_yoetz_yoetz__*` and the `yoetz` skill ids.

**Status.** `finishup integrate claude plugin status --json`, its previews and `finishup setup
status --host claude` report `legacy_installation` for the plugin and marketplace, and the MCP block
reports `legacy_registration` for the `yoetz` key:

| Value | Meaning |
|---|---|
| `none` | Nothing under the legacy name for this project. |
| `legacy_only` | The only FinishUP install still uses the legacy name: owned but outdated. |
| `duplicate` | Owned installs under both names. |
| `foreign` | Something under the legacy name FinishUP cannot prove is its own; reported, never touched. |

A legacy install is this project's and FinishUP's only when the project's settings register
`yoetz-local` or Claude lists `yoetz@yoetz-local` for this project, and the marketplace tree at the
accepted location (beside the managed root) carries a valid marker naming `yoetz-local`. The preview
binds that tree's digest. When the project's `.claude` directory is a symlink, status reads the
legacy install as `foreign` and it is never uninstalled or edited, because FinishUP does not rewrite
settings through a symlinked `.claude`: a plugin preview (and so connect, update or remove) refuses
that `.claude` as `target_unsafe` before any command runs, the same project-settings ownership rule
that refuses a `.claude` another account made or others can write. Before the rename is migrated,
setup's activation cues read the plugin in `yoetz-local`.

**Migration.** The guided connection (`finishup setup run --host claude`) and `finishup integrate
claude plugin install|update|remove` (and disconnect) migrate an owned legacy install in the same
reviewed preview (warning `legacy_installation_owned`; connection plan change
`migrate_legacy_plugin`, or `remove_legacy_plugin` on disconnect). Before writing the new source,
FinishUP retires this project's legacy install only, doing what the preview observed. When Claude
lists the legacy plugin for this project, it runs:

```text
claude plugin uninstall yoetz@yoetz-local --scope project --keep-data
```

FinishUP then removes exactly `extraKnownMarketplaces["yoetz-local"]` and
`enabledPlugins["yoetz@yoetz-local"]` from this project's `.claude/settings.json` (warning
`legacy_project_registration_removed`) and leaves every other setting, its order and the file mode
as they are; the file is rewritten with 2-space indentation, as Claude writes it. The preview binds
each of those entries' digests: if either changed after the preview, the file is left untouched and
the result is `outcome_unknown`, so preview again.

The migration never runs Claude's unscoped `claude plugin marketplace remove yoetz-local`, which
would delete the shared `<config>/plugins/marketplaces/yoetz-local` tree, Claude's user-level
`known_marketplaces.json` entry and every other project's `yoetz@yoetz-local` install. That tree and
that user-level registration stay for the other projects of the same Claude configuration root;
status and previews note them as `legacy_marketplace_retained`, and each project migrates on its own
connect. Update keeps the legacy plugin's enabled state, connect enables the renamed plugin, and
install leaves it disabled as install always does.

**Several projects in one configuration root (#1058).** The same per-project rule holds for the
renamed marketplace: a disconnect retires this project's own legacy install (its `yoetz@yoetz-local`
row and its declaration) whether or not other projects keep the shared `finishup-local` source, and
the shared-source decision counts only `finishup@finishup-local` rows, so another project's legacy
install neither keeps nor loses the renamed source. When other projects keep the renamed source,
the disconnect also drops this project's own `finishup-local` declaration; the operation reaches
`completed` only once the legacy install reads `absent` as well. A project whose only install is
its Yoetz-era one (it reads `duplicate` beside another project's renamed install, with nothing of
its own discovered) plans only `remove_legacy_plugin`: there is no FinishUP install of its own to
uninstall, and apply skips that uninstall too.

Decisions from the 0.3 port review (2026-10-15), per host: Claude Code lists every project-scope
install itself (`claude plugin list`), so there is no Yoetz-era membership to infer here. The
other hosts need it: Cursor keeps an owned `plugins/local/yoetz` found without a record until
`--remove-shared`; Codex counts the project its Yoetz-era marketplace table names as a member,
and Yoetz-era pieces found without a record only make trusted FinishUP checkouts possible users.
The transport-less `mcp_servers.yoetz` leftover diagnosis, and keeping an owned `yoetz`
registration while a project's Codex configuration still needs it (#1073), are Codex-only: a
stale Claude approval entry does not stop Claude Code from loading its configuration, and Claude
Code's MCP server comes with the plugin, not a user-level entry FinishUP moves. The step that
names the `--remove-shared` preview after a completed or repeated disconnect appears on Codex and
Cursor, when the shared pieces stay only for a project whose directory is missing or because
membership is unknown; Claude Code lists its projects itself, so a Claude Code disconnect never
needs it and never shows it. The rule that a disconnect never claims the admission sweep for a
surface it does not edit (exact legacy entries count only on an otherwise absent surface, never on
a foreign one) applies to Claude Code's `.claude/settings.local.json` as to every host.

The one exception is an in-place update: `plugin update --marketplace-root <.../yoetz-local>` (the
upgrade plan's form for an old install) names the old folder itself, which the renamed tree then
replaces. Only there does FinishUP also run `claude plugin marketplace remove yoetz-local`, so
Claude's registration does not point at a folder that now holds `finishup-local`; the preview warns
`legacy_marketplace_replaced`. It runs and announces that remove only while this project's
`.claude/settings.json` or Claude's user-level `known_marketplaces.json` still registers the old
folder; with no registration left it neither runs nor announces it. While Claude lists the legacy plugin for another project or scope,
that update is refused as `destination_conflict` with detail `legacy_marketplace_shared`: migrate
those projects first, or prefer the default `finishup-local` root.

**MCP.** FinishUP never edits Claude's own MCP configuration. Owner-written `yoetz` entries are
recognized and reported (`legacy_only`, `duplicate`); rename them yourself. A legacy-only entry maps
to no host-admission rule, and a plugin-managed connect over it is refused with
`mcp_ownership_conflict` (detail `legacy_registration`), as before the rename.

**Hooks and admission.** The rendered `PermissionDenied` matcher is
`^mcp__(finishup|yoetz|plugin_finishup_finishup)__check$`. Claude hooks carry no isolation
environment. Admission grant writes only the `finishup` forms; the exact legacy entries
`mcp__yoetz__check` and `mcp__plugin_yoetz_yoetz__check` are reported as `legacy_entries`, removed
by `admission revoke` and the removal sweeps, and retired by a grant once nothing FinishUP owns uses
the `yoetz` name. A grant is refused with `legacy_registration_active` while Claude serves FinishUP
only under `yoetz`.

**Manual steps for state FinishUP cannot prove.** A `yoetz-local` registration or a listed
`yoetz@yoetz-local` plugin without a marker-valid legacy tree (deleted or modified) is `foreign` and
is never touched. Remove it yourself, for that project only:

```text
claude plugin uninstall yoetz@yoetz-local --scope project
```

then remove `yoetz-local` from `extraKnownMarketplaces` and `yoetz@yoetz-local` from
`enabledPlugins` in that project's `.claude/settings.json` (or run `claude plugin marketplace remove
yoetz-local --scope project` on a Claude version that supports `--scope` there). Do not run the bare
`claude plugin marketplace remove yoetz-local` while another project still uses it: it removes the
shared tree, the user-level registration and every project's legacy install. Once no project lists
`yoetz@yoetz-local` any more (`claude plugin list`), the retained
`<config>/plugins/marketplaces/yoetz-local` tree and its user-level registration can be removed by
hand; FinishUP never deletes them.

## Static and host validation

Run Claude's validator against the exact generated marketplace root:

```text
CLAUDE_CONFIG_DIR="$CLAUDE_CONFIG_ROOT" "$CLAUDE_PATH" \
  plugin validate "$MARKETPLACE_ROOT" --strict
CLAUDE_CONFIG_DIR="$CLAUDE_CONFIG_ROOT" "$CLAUDE_PATH" plugin list --json
CLAUDE_CONFIG_DIR="$CLAUDE_CONFIG_ROOT" "$CLAUDE_PATH" \
  plugin details finishup@finishup-local
```

The validator covers the default manifest/hooks/skill paths. FinishUP separately validates exact
`.mcp.json` structure and cache bytes; neither static validator proves MCP connection or model use.
`plugin details` should report one skill, five hooks, and one MCP server in plugin-managed mode.

## Applied-route drift decision (issue #537)

Decision for Claude Code: no Codex applied-route record is used here. The explicit `--host claude`
identity prevents the Codex-only drift comparison from being applied to this host. The
plugin-managed `.mcp.json` still binds the route profile and artifact digest in its in-tree marker,
and live file reads remain the authority for which route this host serves; activation and ownership
read-backs cover stale plugin processes. A generic legacy `.mcp.json` remains readable during
upgrade/remove but is unproven until the plugin is re-rendered.

## Enable, trust, reload, and activation

Preview `--action enable`, consume a new exact review, then run `plugin enable` with the same
request/digest/roots/options. Project trust, installed state, enabled setting, reload/new session,
loaded plugin root, skill delivery, and model use are different facts. A directory marketplace may
report its source plugin root in session init even though list/cache evidence identifies the copied
install; either root must independently match the rendered bytes. Activation proof additionally
requires the exact installed/discovered/registered/enabled facts alongside the session observation —
a session init alone (for example a development `--plugin-dir` run) proves nothing about the
marketplace-installed delivery profile. Open or restart an exact
Claude project session only after the enable read-back. If updating a running session, use
`/reload-plugins` (and `--force` only when Claude explicitly requires cache invalidation), then prove
the loaded root/digest in that session. Old concurrent sessions may retain the old plugin.

The skill name is `/finishup:finishup`. The MCP server is `plugin:finishup:finishup`, and callable names are
`mcp__plugin_finishup_finishup__<operation>`. A live proof needs a fresh session and correlated
`start`/`status` call through that scoped name; a list/details/MCP handshake alone is insufficient.

Claude Code's native MCP profile (`finishup mcp serve --host claude`) delivers
`structuredContent` for successful tools but only the bounded text `content` for `isError`
results. Cooperative `EVENT_INVALID` therefore cannot rely on `safe_details` reaching the model.
Decision for Claude Code (issue #579): supported here — the text summary names frozen
`reason_code` and JSON-pointer `field` (for example `unsorted_set_field at
/event_drafts/4/payload/obligation_refs`) within the bounded text channel (4,096 bytes), with no caller prose. The
public message for `unsorted_set_field`/`duplicate_set_member` states the ascending-ASCII rule.
This is the same token class as the `Repair:` clause (issue #266).

Claim correction uses the shared `publish_work` descriptor and
`publish-work-request/1.1.0`; Claude hooks do not author or infer claim supersession. A session still
bound to the older descriptor/control manifest must be reloaded through the normal plugin/service
upgrade path before that capability is claimed; manifest mismatch stops the stale service before
the new pair can fall through its legacy opaque branch.

## Hooks and observation

Claude Code remains structural-only for issue #302: the scoped hook path discards raw prompt,
result, transcript, path, and error content before storage and therefore cannot mint
`observation_captured` evidence. Content-bearing profiles are separate capability and privacy
decisions with their own fixture and consent proof; the explicitly opted-in profile below is the
ordinary-work decision for this release.

The default structural artifact keeps that boundary. An explicitly rendered ordinary-work
artifact uses the neutral profile id `claude-code-ordinary-observation-v1` and subscribes to
Claude's generic `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` events plus lifecycle and
permission/API-failure signals. It does not subscribe to `FileChanged` or `PostToolBatch` until a
deduplication contract proves those signals add distinct work. The hook command carries the exact
profile id with `--observation-profile`; the id is a mapping contract, not a claim about the
installed Claude version.

The [Claude hook contract](https://code.claude.com/docs/en/hooks) keeps permission
requests separate from tool execution. `PermissionRequest` has no tool-call identifier, so FinishUP
retains an uncorrelated permission event without inventing a tool action. `PermissionDenied`
reports auto-mode refusals; it does not cover manual dialog denial, deny rules, or a pre-tool hook
blocking execution. `StopFailure` records an API-failed turn without ending the observed session,
and emits no advice output. The ordinary Claude mapping is
`claude-code-hooks-ordinary-v2`: Claude's `PostToolUse` event is an explicit host-tool success
fact, so a successful `Read`, `Bash`, or other tool result is recorded as success even when the
native result has no exit field. FinishUP never fabricates `exit_status: 0`; an exit status is retained
only when Claude supplies one. `PostToolUseFailure`, denial, interruption, error, invalid or
unknown host status, and conflicting host fields override that event-level success. MCP result
content is domain data: only its outer `isError`/`is_error` signal is an execution outcome; nested
`status`, `outcome`, `success`, and exit-like fields cannot override Claude's host event.
A background Bash launch
is recorded as partial until the host supplies completion evidence. These decisions do not add
filesystem or batch observation.

**Failure supersession (#909).** On the ordinary profile, only a later qualifying hook-observed
run of the same keyed command identity supersedes a failed run's disclosure duty: a pass makes it
history, while a later failure or partial result replaces it as the live limitation. A successful
`Edit`/`Write`/`MultiEdit` does not supersede a failed command, and a failure with no command identity
cannot use same-command supersession. A later passing planned verifier can instead retire the
failed-command finding under the separate
[failed-command finding rules](#failed-command-findings-issue-1104). That does not prove the failed
command passed: its still-live result remains required in a completion claim's `limitation_refs`.
The hook computes an installation-keyed `command_commitment` from `tool_input.command` on
`PreToolUse`, `PostToolUse`, and `PostToolUseFailure`; only the keyed identity enters the structural
record. Decision: supported on the ordinary profile; the
default structural profile observes no generic `Bash` calls, so it records no command identity.
Native dogfood acceptance of this path on macOS, Linux and WSL 2 is not yet recorded
(owner: #909).

**Shell outcome contract (issue #910).** On the ordinary profile a `Bash` `PostToolUse` is recorded
as `success`. Claude's Bash result (`stdout`, `stderr`, `interrupted`, `isImage`) has no exit field,
so the result has no `exit_status`. A `Bash` `PostToolUseFailure` is recorded as `failure`, with
the closed status `interrupted` when `is_interrupt` is true and `error` otherwise. Its `error` text
is never parsed for an exit code, so it too carries no `exit_status`. An exit status is kept only
from a closed `exit_code`/`exitCode` field that Claude supplies. An ordinary-profile shell call is
therefore `unknown`, with `host_outcome_unavailable`, only when Claude supplies an invalid or
unrecognized outcome field; a background launch stays partial.
The default structural profile observes no generic tool calls, so it records no shell outcomes.
The shapes are pinned by `fixtures/observations/claude-code-bash-outcomes.case.json`, which is
derived from the documented hook payloads. A raw hook stdin capture from an installed Claude Code
is still owed, owned by issue #910. Native acceptance on macOS, Linux and Windows through WSL 2 is
not established by source tests.

Stale-verification advice is scoped to the logical tool call, not to the observed phase. On this
profile one edit is observed twice — a `PreToolUse` attempt and a `PostToolUse` result sharing the
normalized `tool_call_id` (Claude's `tool_use_id`) — and the pair reports one
`edit_after_successful_check` finding whose evidence refs name each observed phase (issue #680).
Where only the result is observed, that single phase is the whole condition; no pre-event is
fabricated.

A successful `Bash` result on this profile is an explicit host-tool success fact and nothing more.
Local advice never promotes it to a verification check: only a current `passed`
approved-check fact, or an explicit success from a dedicated verification tool, establishes or
advances the verification baseline, and a routine read never does. A Claude session that edits and
claims completion after successful `Bash` commands alone therefore keeps
`completion_without_verification` rather than silently counting those commands as a check
(issue #681). Failed-command advice is unchanged and still reads every `Bash` outcome.

Select these hooks with `--observation-profile ordinary` on the existing Claude plugin
preview/install/update/status commands, or on `finishup integrate claude plugin export` for a
development directory. Repeat the same profile when applying an exact preview. To return to
scoped structural hooks, preview and apply an update with `--observation-profile structural`.
Artifact selection does not grant content capture.
Preview names the selected profile. Status reports the requested profile and confirms an installed
profile only when its verified marker and artifact digest match; otherwise that installed value is
unknown rather than inferred from the request.

Native content remains a second, per-host consent arm. After granting structural observation, an
operator can enable and later revoke it with the user-facing commands below:

```text
finishup observe content-enable --workspace /exact/project \
  --profile claude-code-ordinary-observation-v1
finishup observe content-status --workspace /exact/project --json
finishup observe content-disable --workspace /exact/project \
  --profile claude-code-ordinary-observation-v1
```

This arm persists through later structural grants in the same workspace: connecting Codex,
rerunning Codex setup, or repeating `finishup observe grant` keeps it and does not advance its content
fence, so a capture in flight stays authorized (#835). Only `content-disable` or `observe revoke`
removes it; after a revoke, enable it again explicitly.

The service accepts Claude chunks only when that exact profile is active in local consent and in the
mapped task grant. A missing or mismatched profile drops plaintext chunks and records
`content_capture_unavailable`; chunks are never retained in the structural outbox for later replay.
An authorized native hook reserves the workspace drain before enqueueing its structural row, keeping
a background sweep from consuming that row before the foreground content attempt. The reservation is
nonblocking and is released on cancellation or after the bounded drain; a busy owner can still leave
an explicit content gap. The hook commits its structural envelope, pairing, mapping, and outbox
intent locally before attempting the bounded service drain. Teardown `SessionEnd` has no service
drain: its local lifecycle and outbox intent are durable before the hook returns, and a later hook
or the service sweeper retries delivery. With no later hook, a ready service polls for undelivered
rows every 5 seconds while idle and sweeps as soon as one is waiting; a row that already failed an
attempt retries at the 60-second idle interval. Content-bearing ordinary-profile events retain a one-second drain window; contentless
structural rows defer service delivery. When chunks exist, the pass prioritizes the current row
after its same-session FIFO prefix, within that one-second drain and sixteen-row bound. Teardown
keeps its host-clamped three-second hook and skips local advice construction because the closing
host cannot receive it. A healthy accepted drain forwards the transient chunks and exact profile to
the service; a bounded service failure or completed cancellation path leaves the structural record
plus an explicit content gap. A hard process kill or service failure before authenticated
service-side staging completes may lose transient content without a durable gap marker; there is no
plaintext local spool or offline acceptance guarantee. For this ordinary Claude profile, the
capture-only service request can commit encrypted objects, manifests, and a metadata-only capture
ticket before the structural FIFO ingest. After that boundary, a retry revalidates the original
host/source and content-authority generations, requires the complete expected group/part set, and
reuses the ticket rather than reminting content. The bounded staging handoff can therefore survive a
service restart, while a revoked or incomplete ticket remains an honest content gap. The current
installed Claude `2.1.261` probe is a candidate host fact only; it does not certify this ordinary
profile without an exact isolated fixture and a receipt that separately proves native hook delivery,
accepted content, AI-powered review selection, and any resulting influence. Native AI-powered review
selection uses the accepted tool event's durable session route and does not require an
approved-check policy. Local capture consent and repository disclosure permission remain separate
requirements.

A handoff that its structural row can no longer consume (the row was already acknowledged,
quarantined, or refused) is retired by that row's own delivery, by the READY maintenance sweep once
it is 30 seconds old, or by a new CHECK's preflight, instead of holding shared oldest-age pressure
at the hard limit (#836). Its payload-free retirement account and
`content_capture_unavailable` marker commit before the ticket is tombstoned or its reservation is
released; a failed or cancelled account leaves the handoff retryable, and a replay is idempotent by
ticket identity. `observe status --json` names each retirement under
`capture_handoff_retirements`. A handoff whose row is still queued keeps counting toward pending age.
This hook sends its Claude Code content profile only with
Claude Code rows; a queued Codex or Cursor row drained from the same workspace carries no profile, so
it is not refused as `content_capture_profile_mismatch`.

Claude Code has no `codex exec --json` import surface. Issue #301's bounded import authorization
therefore makes no Claude adapter change; Claude evidence continues through cooperative MCP and
the native hook/observation paths below.

Cursor's explicit-start repair (issue #661) leaves Claude's binder and hook subscription unchanged.
[Claude's hooks reference](https://code.claude.com/docs/en/hooks#posttooluse), checked 2026-09-08,
specifies `tool_response` for successful `PostToolUse`. Claude continues to pass that field from
its exact FinishUP-scoped tool to the shared binder; Cursor's `result_json` / `tool_output` and
server-key normalization are confined to the Cursor adapter. Cross-host regression checks cover
Claude's structured result, single JSON text block, live-characterized JSON string, and failed
start rejection.

The native hook profile emits `SessionStart`, scoped-FinishUP `PostToolUse`, scoped-FinishUP
`PostToolUseFailure`, `Stop`, `SessionEnd`, `SubagentStart`, and `SubagentStop`. A bare MCP matcher is
a negative control. Hooks call `finishup hooks claude-observe` and are best-effort; timeouts/nonzero
exits never authorize or block Claude work. The child hooks retain only the bounded child identity;
transcript, prompt, agent type, and path data stay outside the FinishUP envelope.

The renderer uses a lightweight entrypoint that avoids loading the full CLI application graph.
Ordinary events have a five-second budget, `SessionStart` and `Stop` ten seconds, and teardown
`SessionEnd` three seconds. Structural capture and pairing close before service drain, while
advice-bearing events remain synchronous so Claude receives `additionalContext` in the same hook
response. The conservative 0.2 profile used five lifecycle events; the 0.3 capability cell adds
`SubagentStart` and `SubagentStop` only where the exact installed cell and evidence below support
them.

### Task-tool subagents and attribution (#506)

The #499 lifecycle repair applies to cooperative Claude children: successful routed activity
renews session health, abandonment is a service-stamped ledger event, and an unused expired handle
leaves an abandoned reservation. The #507 native start-callback correlation bridge is Codex-only;
it does not establish new Claude host support. The #754 multi-agent v2 child identity source is
Codex-only for the same reason: it reads a Codex rollout `session_meta` header, a stream family
Claude Code does not have. Claude keeps its native `SubagentStart`/`SubagentStop` hook identity
unchanged, and no Claude capability cell moves. Existing Claude cooperative identity and native
evidence boundaries below remain in force.

### Parent liveness while native subagents run (#837)

In the 2026-09-25 dogfood, a Claude parent's last accepted hook was a `SubagentStart`. Its
native subagents then ran for about twelve minutes with no parent event. FinishUP abandoned the
parent while it kept working, and a later delegation was refused. Injected-clock conformance
reproduces the same sequence on the released source. The per-profile decisions are:

- **Structural profile (default).** These count as parent contact, each at its own receipt time:
  - workflow calls;
  - scoped-FinishUP `PostToolUse` and `PostToolUseFailure`;
  - `SessionStart`, `Stop`, `SubagentStart`, and `SubagentStop`.

  Only `SessionEnd` ends contact. A `SubagentStart` recorded without its `SubagentStop` holds the
  parent in contact until the stop, for at most 3,600 seconds.
- **Ordinary profile.** It registers no `SubagentStart` or `SubagentStop`, so it has no subagent
  hold:
  - Subagent `PreToolUse`, `PermissionRequest`, and `PermissionDenied` events route to the parent
    lane and count as parent contact at their receipt time, even when the sweeper delivers them
    late.
  - Subagent `PostToolUse` carries the child identity and never renews the parent.
  - Adding the lifecycle hooks to this profile needs its own installed-artifact evidence. It is
    not claimed here.
- **Remaining gap (both profiles).** Some quiet periods produce no qualifying evidence:
  - one native tool call that runs past the lease and recovery window;
  - a turn waiting on the user;
  - in the ordinary profile, a subagent that stays silent.

  Such periods still lose contact after the lease and abandon the work after
  `lineage.contact_lost_recovery_seconds`, which operators can raise.
- **After abandonment.** Refusals carry `lineage_resume_work_terminal` or
  `lineage_parent_work_terminal` with the `lineage_successor_task` continuation. Keep the held
  session for history and receipts, and start one successor task for new work and delegation.

No Claude capability cell moves. Native re-verification of this path is still owed on a pinned
instance.

The exact pinned capability cell remains `claude-code-cli-local-project-2.1.241`. The earlier
installed Claude Code `2.1.261` fixture proves native child-hook delivery in an evidence-only
plugin. The latest installed binary reported `2.1.263`; it was exercised in a fresh isolated
strict-plugin export with a bounded loopback Messages provider. Claude's real native `Agent` path
started and completed one child at `spawn_depth=1`; both `SubagentStart` and `SubagentStop` hooks
ran successfully. The observed start shape carried `agent_id`, `agent_type`, `session_id`, `cwd`,
and `transcript_path`; stop additionally carried `agent_transcript_path` and `permission_mode`.
Neither event carried a parent tool-call id, so child-only correlation is a required supported input
shape.

The final exact-wheel cell used `yoetz-0.1.0-py3-none-any.whl` at SHA256
`8d54a73c87e5e49b0b6179ad58f673d2b2f40b1a93c80c4393ce56ae36e82988` from source commit
`2e8b0b48`, with 216 packaged resources (`sha256:1e4cc667456c1cf9ac579d7bc1db186937c29abd9637025c42569ffc7701895c`)
and a strict plugin export (`sha256:f2f7249ef47e43cde1fb0004d2bb770125665c7fc15664c8c6d116242dec6fdb`) loaded
through Claude's development `--plugin-dir` carrier in a fresh mode-0700 isolated root; this is not
marketplace-installed activation. It completed a FinishUP parent `start`, `mode=delegate`, native
child `Agent`, child `mode=attach`, one `publish_work`, local `check`, and JSON `receipt`;
the child receipt was `rcp_f567225d-a34f-4a07-beda-2866649a3b57` with digest
`sha256:47a578bbdaedd7f93e3389ee7d212b84feb132dd44ff2f02a1c8d10e63ba3e3a` and the recorded
conclusion `insufficient_coverage` (`semantic_review_not_requested`). The parent and child ledgers
durably recorded delegation, the child action, check, and receipt. The provider remained a loopback
synthetic Messages server, Claude auth status was `loggedIn=false`/`authMethod=none`, and no normal
credentials or user vault material entered the root; only a throwaway synthetic passphrase vault was
initialized inside that isolated root. Workspace-level observation consent covered only the
synthetic workspace. Post-run status
recorded `claude_hook:true` but `mapping_present:false`, ten `mapping_missing` quarantines, and
`outbox_quarantined`/`unpaired_event` gaps, so this cell proves hook execution but does not claim
attributed host observation or accepted hook coverage. The first `SessionStart` hook was cancelled;
child and operation hooks returned success. The parent's advice/frontier remained independent and
recommended `refresh_observation`. This proves the bounded host and FinishUP workflow under the
recorded limits; it does not promote either installed version to the pinned `2.1.241` capability
cell or prove production model use.

For a validated child signal, the service normalizes `agent_id` to a bounded
subagent identity and retains only structural correlation. `origin=host_observed` and
`acceptance=pending` stay service-stamped until an accepted `mode=delegate` handle or cooperative
self-registration binds the same correlation. A hook carrying only the parent's `session_id`, or a
PostToolUse row fired inside a child without a validated child identity, is an attribution gap and
never parent work. The parent's advice and frontier lane remains independent. Transcript paths,
prompts, agent types, and summaries are never correlation proof.

Shared-session callbacks preserve the parent mapping when the child attaches. A successful child
start can establish a separate local route when Claude supplies a validated child agent ID. If the
callback omits that identity, names a foreign task or service session without a matching child
route, or supplies conflicting aliases, it remains an explicit attribution gap. Such a callback
cannot enqueue parent work or consume parent advice and frontier notices. A local delivery route
does not create or accept a cooperative child. Ordinary child callbacks with no safe identity
remain outside the attributed delivery contract.

This decision is based on installed native execution and the pinned profile boundary; a current
online Claude reference or a renderer fixture does not upgrade the pinned cell. The #509 host
matrix records the `2.1.261` child-hook fixture and the later installed `2.1.263` bounded
parent/delegate publication, check, and receipt run as separate evidence cells. Cooperative MCP
self-registration remains a separate, explicitly bounded path. Those historical cells are not
this qualification run. The current fixture names and native table are in
[multi-agent-conformance.md](multi-agent-conformance.md#host-qualification-rows). Supported
registration is still parent `mode=delegate` plus child `mode=attach`, or self-registration with
`parent_session_id` followed by parent `child_accepted`. A hook with only the parent session, a
text handoff, or an unregistered helper does not create child ownership. Linux/WSL native
qualification of these rows was not run here.

The historical 0.3 child-hook cell used control 2.5, which admits the `pairing_mode` and
`correlation_kind` metadata emitted by Claude ingress. Current main's control 2.6 successor retains
those fields and adds the bounded observation-selection projection; both peers must use the same
current manifest after integration. Earlier development artifacts omitted the pairing fields from
the closed schema: the client returned `frame_invalid` before sending the observation, and the hook
layer reported `ledger_rejected`. That refusal did not establish a service-stage failure or an
unsupported host signal. The frozen control 2.4 schema remains available for historical validation.
Verify admitted observations separately from successful cooperative tool calls and local queue
drainage.

The 2026-09-07 native cell used source `80d0d94c` and the development `0.1.0` wheel at SHA256
`18b0e5ecd9cc09acb06dd805d90c01dc506241a26e2405b152dec36a51ec6f9d`. All 475 installed package
files matched the wheel. Claude Code `2.1.263` ran with an isolated synthetic workspace and
passphrase vault, the development `--plugin-dir` carrier, a strict MCP route, and a synthetic
loopback Messages provider. The native host and driver exited `0` without timeout. Parent attach,
delegation, native `Agent`, child attach, publication, local check, and receipt completed;
request/result models, child identity, operation ordering, and receipt/check bindings validated.
`SessionStart`, `SubagentStart`, `SubagentStop`, and `Stop` hooks succeeded without cancellation.

Consented hook envelopes retained one validated child identity across `SubagentStart`, four child
`PostToolUse` callbacks, and `SubagentStop`. The four child callbacks used a separate scoped route;
five mapping snapshots preserved the parent identity. Child frontier delivery and advice state
remained separate from the parent, and the parent lineage contained an annotation. Native output
stream records omitted the child identity fields, so this attribution is supported by the installed
hook ingress and retained structural state, not independently attested by the output stream.

Final observation status showed Claude hook coverage, zero pending rows, zero quarantines, and a
completed drain. One bounded `drain_budget_exhausted` diagnostic remained; a historical parent
`mapping_missing` event did not recur in child callbacks. Public status retained
`content_capture_unavailable`. The check and receipt used local coverage with
`semantic_review_not_requested`; their validation allowed later observation-related frontiers but
did not independently prove the intervening digest chain. This cell proves the bounded native
workflow and lane separation. Production model behavior, semantic advice content, marketplace
activation, and support for the pinned `2.1.241` capability cell remain outside its coverage.

Advice uses Claude Code's documented output contract. `SessionStart`, `PostToolUse`, and
`PostToolUseFailure` may emit `hookSpecificOutput.additionalContext`; at `Stop` that channel
carries only the closure gate (#985). The failure event
keeps `hookEventName: PostToolUseFailure` even though FinishUP normalizes its internal advice cadence
to `PostToolUse`. At `Stop`, additional context is Claude Code's non-error feedback channel: it
continues through the same `stop_hook_active` loop guard as a blocking decision, but is labelled as
feedback rather than an error, so ordinary advice there would spend the continuation the gate
needs and is withheld until the next tool event or session start. Claude Code sets
`stop_hook_active` when it is already continuing because of a Stop hook and still honours a
further continuation; it has no fixed cap, so FinishUP's caps below bound it. FinishUP never emits
`decision: block` to Claude Code. **Stop-time
closure gate (host decision: supported).** When a mapped session stops while closure still requires
agent action, `Stop` carries the gate text in that same `additionalContext` channel, which continues
the conversation; after `stop_hook_active` is set only an announced re-check not yet asked, or a withdrawn
deliverable not yet voiced, may follow, so the
gate continues Claude Code at most twice per turn. The decision reads only the service's compact `status` for the mapped session (`closure_readiness`, read on the route the session's MCP server named on its last successful `status` or `check`, remembered across service restarts); it fires when `agent_actionable` holds open obligations, an unconfirmed blocker, an unrepaired receipt-blocking finding (agent work only), a finding the agent rejected that awaits a reviewer ruling (`finding_rejection_awaiting_ruling`), a planned verification that was not observed, failed, or ran before the latest edit, an edit to the work after the last verification run (`edited_after_last_verification`; temporary scratch and FinishUP-owned writes such as a saved receipt never count, ADR-042), a git-ignored requested output, or a declared deliverable deleted or renamed away (`declared_output_removed`, ADR-035), or a declared deliverable that held content and is now empty or truncated (`declared_output_emptied`, ADR-041 and ADR-045: keyed on the file, not the obligation, so acknowledging or republishing the obligation does not clear it; the gate text says why from the file's recorded history and names the one exit, a `finishup-assumption` decision that names the file; a standing `declared_output_content_moved` disclosure adds an informational note to gate text that fires anyway, never a token), or a delivered source file that may read a file the agent created and no requested item declares (`deliverable_references_undeclared_file`, #1044, ADR-035 amendments: a name the deliverable provably only writes does not count, and a bare file name a declared file shares, or that nothing ties to the file's directory, is counted on the receipt as `deliverable_references_ambiguous_name` instead; the text names each such file, quoted and bounded, from `closure_readiness.undeclared_references`, where a name the agent itself published in this session returns to it even when its privacy policy withholds repository excerpts, and tells the agent to embed it, rebuild it at run time or declare it, or the directory holding it, as a delivered output; when a name is withheld it says why and gives the agent's own shell command that lists the files its change created; disclosing the dependency does not clear it, and no path is remembered. Host decision for the tb4n5 naming: supported, same code path), at most once per ledger frontier and session (owner-only `observation/closure-gate.json`). Before that read the Stop pass drains this task's hook rows toward the current frontier (at most 2.5 s and 64 rows, keeping the gate's five-second reserve) and records `stop_drain_complete` or `stop_drain_incomplete`; rows of other tasks or unmapped sessions in the workspace do not hold the decision (#994). Verification items (planned verification and edits after the last verification run) are dropped only while this task's own hook rows are still draining after the Stop drain, and the text says so only then. The text pushes repair first: a receipt-blocking finding the agent repaired but FinishUP cannot prove (a FinishUP limit) is self-verified and answered with `respond` `self_verified`; `acknowledged_not_done` is the last resort; a FinishUP limit is never a `finishup-blocker`, and the blocker sentence appears only while obligations are open. An open obligation named by a `finishup-blocker:<kind>` decision is not listed as work, but each new `<obligation id>:<kind>` is re-asked once: the re-check names the obligation and claimed kind from the `blocker` entries of `closure_readiness.rechecks`, says recoverable data, a failing test, an infeasible-looking result or a FinishUP limit is not a blocker (finish the obligation and disclose the limit), and only there tells the agent how to confirm a genuine one: publish the same line again in a later decision whose rationale names what was re-checked, so the MCP bridge never refuses it as an unchanged id-less resend (the blocker offer never says so, and a confirmed row is never re-asked). Because blockers are usually published after the first gate, the re-check also runs on a Stop the host already continued: there it reads status, continues the agent only for a re-check key status announced that the gate has not asked, or a withdrawn deliverable not yet voiced (never for ordinary items), at most once per Stop and at most two gate continuations per turn (owner-only `observation/closure-gate-turns.json`, reset at every Stop the host did not continue; an unreadable counter counts as the cap), and lets the agent stop on any error, a short budget, or a memory write failure. Asked keys are remembered per session (owner-only `observation/closure-gate-blockers.json`, at most 64). Ordinary advice is never delivered at Stop; it waits for the next tool event or session start. Standing advice a Stop withheld rides the first later `PostToolUse`. Every outcome is a hook diagnostic (`closure_gate_continued`, `closure_gate_blocker_rechecked`, `closure_gate_active_stop_rechecked`, `closure_gate_memory_unwritten`, `closure_gate_not_required`, `closure_gate_repeat_suppressed`, `closure_gate_turn_end_after_continue` (an already-continued Stop that emitted nothing: the normal end of a continued turn, renamed from `closure_gate_loop_guard`), `closure_gate_budget_exhausted`, `closure_gate_unavailable`) in `finishup observe status`. The text also says an inherent verification limit or a best-effort choice is disclosed with a `finishup-assumption:` or `finishup-verification-limit:` decision line, never blocked, and names an obligation-level `acknowledged_not_done` as the last resort (#995, #997). Re-checks are not riders on other tokens (tb4n3 RC-8, #1031). Status announces them in `closure_readiness.rechecks` (acknowledgement, blocker, premise, each with a content key; the same list `status`, `closure_prepare`, the CLI and the TUI show, and the status directive names it: "At Stop you will be asked once to re-read: ..."), and the gate asks exactly the announced ones, each once per session and key (`ack:<obligation id>`, `<obligation id>:<kind>` for a blocker, `premise:<acknowledged count>`, all in the blocker-key file; closed items `acknowledgement_recheck`, `blocker_recheck`, `premise_recheck`). A readiness without the list (a service older than the gate) announces none, so the gate asks none. Acceptance provenance (ADR-033 amendment of 2026-10-18, owner decision D1): a resolved obligation the ledger flags (a requested item never attempted, evidence not linked to a declared item, or only self-asserted evidence) with neither an admissible observed verification link nor a recorded verification limit is never a Stop item. Status, `closure_prepare`, the CLI and the TUI name it once in the closure guidance (`closure_readiness.acceptance_risk`), and the receipt records it as the coverage limit `unresolved_verification_limitation` (the conclusion is at best `insufficient_coverage`). If an output does not meet its acceptance criteria, the agent republishes that obligation `acknowledged_not_done`; an acknowledgement that directly follows a `resolved` publication of the same obligation (an honest downgrade) is not challenged by the acknowledgement re-check. The gate drops an `acceptance` entry an earlier 0.3 service still announces and writes no `accept:` key and no `closure_gate_acceptance_rechecked` / `closure_gate_acceptance_covered` diagnostic (both names stay readable); `accept:` memory an earlier build wrote is still read, so an acknowledgement published after that invite is not challenged. Final message: Claude Code's Stop payload still carries `last_assistant_message`; the adapter no longer hands it to the gate, and a `finishup-acceptance:` or `finishup-verification-limit:` line in it is ignored (a `finishup-verification-limit:` decision published through `publish_work` is still recorded and lifts the coverage limit). Host decision: acceptance-provenance risk is never a Stop item on Claude Code, and the hook does not read the final message. The premise ask stays on Stops the host has not already continued; the acknowledgement re-check may continue an already-continued Stop within the same caps. A finding the agent rejected with a reason that awaits a reviewer ruling (`finding_rejection_awaiting_ruling`) sends the agent to `check` with `final_review: true` and never offers acknowledgement; `receipt_findings_unresolved` counts agent-work findings only, and `self_verified` is offered only while `finding_counts.self_verify_eligible` is positive. A deliverable that held content and is now empty or gone (`declared_output_emptied`, `declared_output_removed`) is voiced once per key (`emptied:<h8 of the declaring obligation items>`) even on an already-continued Stop, with the rule and obligation ids and never a path (every Stop after the first gate is an already-continued Stop in a single-turn run). The premise and acknowledgement texts say that if the agent cannot finish the work it keeps the working deliverable: acknowledgement never requires withdrawing or emptying it. Host decision: supported, same code path (the gate, its texts, its re-check list and its memory are shared by the Codex, Claude Code and Cursor Stop handlers; the only difference is how an already-continued Stop is detected, `stop_hook_active`). See ADR-033 and issues #977, #984, #985, #1031. `SessionEnd`
emits `{}`. Provider-repair advice is standing advice (#844). Claude Code delivers it only on
`SessionStart`, or on the first `PostToolUse` after a `Stop` that withheld it, as
`additionalContext` and never as `decision: block`; `Stop` no longer carries it (#985).
Any other `PostToolUse` does not carry it. A private or no-egress install, an install with no provider
endpoint, and an install whose verification is disabled do not emit `connect_provider` or another
provider-repair request. The service emits it only when verification is not disabled, a provider
endpoint is bound, network egress is permitted, and an LLM inference channel is enabled, and the
provider is still structurally unusable, including when no factory id is available.

Mid-session, the agent can ask `check` to wait for this task's hook rows instead of polling `status`: `await_observations: true` (MCP) or `finishup check --await-observations` wakes the service sweeper and waits at most about 3 s (and a tenth of the request deadline) for the rows already pending, then reports `observations_awaited` (`complete`, `bounded_timeout` with the pending count, or `unavailable`). The decision is the same for Claude Code: the wait reads the shared local outbox and lifecycle mappings, so it needs no host-specific hook; it never fails the check (ADR-029 amendment, #1012). The tb4n5 extension to rollout rows held for their hook post is Codex-only: Claude Code has no rollout stream, so there is nothing held to release.

Observation-health advice follows the same boundary: `refresh_observation` for source lag, a stale
cursor, a drain backlog, service unavailability, or a locked vault stays in operator status and
structured advice, and is excluded from every hook `additionalContext` response. Hook context is
reserved for work advice.

The rendered hook commands bind `--workspace "${CLAUDE_PROJECT_DIR}"`. When a hook ingests
nothing it still exits 0 with `{}`, but records one payload-free `hook_diagnostics` reason that
`finishup observe status --workspace <project>` reports: `workspace_unresolvable` (the variable was
unset or named a missing, symlinked, or unsafe path), `workspace_unconsented` (the canonical Git
root of that path carries no active consent — note that a `git worktree` is its own Git root, so
consent on the main checkout does not cover it), or `paused`. A successful ingest records no
diagnostic, so read `recent_count` together with the envelopes: no new `claude_hook` envelopes and a
zero `recent_count` after a session that ran FinishUP tools means the hooks never reached the ingress
or the runtime gate is disabled — not that they were dropped for binding.

A consented `SessionStart` auto-attaches a ledger task without an explicit MCP `start`: the hook
sends `start mode=create_or_attach` with the canonical project root as `workspace_ref` and
`claude-session:<session_id>` as `external_ref` (both persisted only as HMAC commitments). Success
shows as `mapping_present: true` in `observe status` and the session's queued rows drain in the
same pass. Before admitting a new pair, the shared hook path checks private persisted mappings
from eligible ended Claude sessions. Eligibility requires a received `SessionEnd`, every other bound
session ended, and a candidate bound only to this consented workspace. A unique eligible mapping is
selected before automatic new-pair admission: the hook holds the workspace and lifecycle locks,
revalidates ownership and state, and sends one `mode=attach` request carrying that selector plus the
new pair. The catalog requires the selected root task to be active and non-quarantined, its
canonical workspace and repository-privacy binding to match, and no start already pending for that
selected route. Other independent tasks in the same workspace do not block this recovery (#814); a
pair already bound to another task remains a conflict. Delegated child routes require an
authenticated attach handle or target selector. Recovery revalidates unmapped sessions,
cross-workspace ownership, mapping identity, and mapping recency; a busy workspace reservation
defers with `auto_attach_recovery_busy`, while candidate-lock contention or changed state returns
the closed `auto_attach_recovery_busy` boundary rather than creating work from an unstable selector.
A successful recovery
rewrites every ended same-host predecessor mapping for that task to the rotated session and writer.
With no usable persisted selector, automatic `create_or_attach` admits the new pair as independent
work, including beside a dormant task. Pending predecessor rows then drain on that successor route
(`session_superseded` is followed, not quarantined as `ledger_rejected`). `workspace_task_exists`
identifies only explicit `mode=create` colliding with an identical pair; workspace membership never
selects a task. Age alone never proves a host session ended. A failed attempt records its cause as a
payload-free `hook_diagnostics` reason
(`auto_attach_workspace_unbound`, `auto_attach_request_invalid`, `auto_attach_binding_ambiguous`,
`auto_attach_conflict`,
`auto_attach_refused`, `auto_attach_result_invalid`, `auto_attach_mapping_write_failed`,
`privacy_authority_required`, `service_unavailable`, `service_incompatible`, `vault_locked`, `timeout`, `storage_unsafe`,
or `storage_corrupt`) and the session keeps an observation-only binding; `UserPromptSubmit` and
`Stop` retry under the bounded budget, while teardown `SessionEnd` records its lifecycle intent and
defers service delivery without spending an auto-attach retry. An explicit cooperative MCP `start`
bound from its exact `PostToolUse` result remains a recovery path, not a substitute proof that
natural auto-attach works. An explicit `mode=create` collision remains `SESSION_CONFLICT` and is
not a recovery selector. For
`vault_locked` on a never-initialized install, that explicit `start` returns the typed
`vault_initialization_required` continuation (see the proof checklist) rather than a dead end.

If a scoped attach returns `SESSION_CONFLICT`, inspect `safe_details.reason_code`:
`repository_identity_required` means the trusted repository context was omitted, while
`repository_identity_mismatch` means it resolved to a different repository than the selected
route. Resolve the canonical repository root and retry the same attach with the held session/writer
selector; the existing task may receive a rotated session/writer under the 0.3 recovery contract,
but a sibling must not be created from this refusal. Never infer a selector or copy a commitment
from a public workspace string.

Busy host lifecycle changes are durable local work. State schema `/11` adds bounded pending
session-lifecycle intents, and a READY or hook drain reconciles them under the workspace and
session reservations before routing their rows; busy mapping writes use an atomic per-session
handoff. Upgrade this state quiescently: stop the older FinishUP service and Claude Code hooks,
install the new runtime, then restart the service and all Claude Code integrations before writing
`/11` state. Mixed old and new writers are unsupported because a `/10` writer ignores the new
pairing fields and can erase a deferred intent when it saves.

The shared `observe status` CLI maps an unsafe state/lock path to `storage_unsafe`, bounded
open/permission/read-only/missing-parent/lock-acquisition failures to `storage_unavailable`, and
invalid stored data to `storage_corrupt`; other defects retain the internal-error boundary. Its
fixed remediation never prints the absolute state path. A result obtained from a sandboxed Claude
carrier proves only that sandbox cell; unrestricted-terminal behavior needs its own run.

Shared drain terminalization is host-neutral: `ledger_rejected` means the ready service rejected
one envelope non-retryably, so that row is retained in quarantine and later rows proceed. A task
bundle at schema 9 (bundle migration `0009`) stores `claude_hook` rows; schema 8's source CHECK
refused them. The SQLite store now classifies deterministic constraint failures as `ledger_rejected`
(issue #576). During a compatible 0.2-to-0.3 package update, after old writers are stopped, the
fresh service runs its backup-first bundle migration before READY; no per-task migration ceremony
is required. The ordinary writer still refuses an unmigrated bundle before observation ingestion,
and an unsupported or ambiguous startup result remains fail-closed with the [migration and rollback
procedure](migration-rollback.md). Migration allows valid pending envelopes to store unchanged, but
delivery still requires a usable session mapping; it does not itself repair a retired session route
or replay quarantined rows. An
idempotent repeat of a committed envelope (lost acknowledgement, service restart, or a workflow
reattach that rotates the mapped FinishUP session) is resolved task-wide and acknowledged, never
quarantined. A pending row from an ended host session whose task was recovered by a successor
session is delivered on the successor route (`session_superseded` is followed). A successor
binding that cannot be followed quarantines that row as `session_superseded`, not
`ledger_rejected` or `mapping_missing`.
A non-retryable `SESSION_CONFLICT` while acquiring the task runtime reports `mapping_missing`,
keeping the envelope pending for a later drain after its lifecycle mapping is repaired. The route must still
pass its ownership checks. Non-retryable conflicts after runtime acquisition remain
`ledger_rejected` and enter quarantine. Retryable route conflicts report `service_unavailable`
and stay pending.
A row
also enters quarantine after 128 consecutive rejections with the same retryable reason, except for
designed back-pressure and workspace-global pause/vault/disabled gates. Both cases remain visible
in `quarantine_causes`, aggregate `delivery_causes`, and gaps;
`pending_delivery_causes` names only pending rows. A hook-driven drain also writes
`hook_diagnostics`, while manual and supervisor drains remain visible through status. Neither case
is repaired by restarting a service that already reports ready.

Claude Code's hooks are scoped to FinishUP's own tools, so every `PostToolUse` it observes is FinishUP
observing itself (issue #564). The shared self-observation policy applies: a `PostToolUse` of
`mcp__plugin_finishup_finishup__status`, `_receipt`, or `_read_guidance` is ingested into the bounded
local store but not enqueued for delivery; a `PostToolUse` of `_start`, `_publish_work`, `_check`,
or `_respond` enqueues one row; every `PostToolUseFailure` enqueues one row. Claude sends no
`PreToolUse` on this profile, so its reviewed pairing contract is post-only and there is no
pre-event to hold back. The tb4 n5 self-observation gap (a Codex rollout's completed MCP item, and
Cursor's server-less `MCP:<tool>`) does not exist here: every Claude Code spelling of a FinishUP tool
names its server and arrives in an explicit hook phase. Its `tool_use_id`, when present, identifies the observed result; no
missing-pre gap is created for a legacy post-only hook. The `PostToolUse` advice
guard recognizes Claude's plugin spelling together with the other host spellings, so a self-owned
hook without an explicit failure does not lease pending recommendation context for the call being
observed. No hook delivers a frontier-motion notice (issue #915): every such notice described
observation-authored motion, which leaves a held frontier admissible. Explicit self-call failures
remain retained, enqueued, and eligible for pending advice. The manual
`finishup observe drain --json` reports `terminal: drained` once nothing is pending.

Grant observation separately for the exact project. Exercise every advertised event and inspect
`finishup observe status`. Only consented accepted `claude_hook` envelopes earn coverage. Raw
transcript/prompt/assistant/path/cwd/tool input/tool output/result/error values are discarded before
storage. The exact successful scoped `start` post-hook is the sole routing exception: it validates
the returned task/session/writer identifiers and frontier to bind the Claude session, while storing
none of the response bytes or prose. Confirm `mapping_present: true`, then drain and require accepted
rows before claiming hook coverage. Pause, resume, revoke, deduplication, restart, and gap behavior
require their own evidence.

### Hook cost and timing (issue #915)

Every `hooks claude-observe` pass folds one sample into the bounded aggregate that
`finishup observe status --json` reports as `hook_diagnostics.pass_timings` (text: `hook_pass_timing`).
Entries are keyed by host `claude`, the raw Claude event (`PreToolUse`, `PostToolUse`,
`PostToolUseFailure`, `SessionStart`, ...) and the rendered profile path (`structural` or
`ordinary`), with `count`, `p50_ms_at_most`, `p95_ms_at_most` (histogram bucket bounds), `max_ms`,
an `outcomes` tally and a `recent` view. A sample runs from the console entry to the end of the
pass; Python interpreter start and process exit are excluded, so add that term, measured on the same
machine, before comparing with host-visible latency. A structural `PostToolUse` for a generic tool
is filtered at ingress and counts as `not_ingested`; it still cost a process. The
`hooks startup-gate` and `hooks startup-context` commands are not in the aggregate, although each
is its own synchronous process: `startup-context` on every `SessionStart`, and in required startup
mode `startup-gate` on session, prompt and every tool event. The aggregate is therefore the cost of
the observation hook only, not of every FinishUP hook Claude Code runs.

Registration decision on Claude Code (issue #915, recorded 2026-09-30): unchanged, and no latency
improvement is claimed. Claude Code runs every hook as a synchronous command (5 s for tool events,
10 s for `SessionStart`/`Stop`, 3 s for `SessionEnd`). The structural default subscribes
`PostToolUse`/`PostToolUseFailure` only for the FinishUP workflow tools, so ordinary tool calls pay no
FinishUP hook process. The ordinary profile subscribes `PreToolUse`, `PostToolUse` and
`PostToolUseFailure` on `.*`, which is two synchronous FinishUP processes per tool call; required
startup mode adds a `startup-gate` process to each of those events. Whether those hooks can be made
cheaper (a minimal-import fast path or a narrower matcher) without losing ingress is decided from
the aggregate of a Claude Code dogfood run in both profiles on macOS, Linux and WSL 2. Those
measurements are not recorded yet; the gap is owned by issue #915. The frontier-motion notice
change applies here unchanged: an ordinary-profile `PostToolUse` with no pending advice returns
`{}`.

### Oversized hook payloads (issue #667, tb4n1 B5)

The Claude Code hook ingress cap is 1 MiB (`MAX_HOOK_STDIN_BYTES`, shared by every host); a body
at or under it is parsed in full and its captured content stays bounded by the content budget. It
was 256 KiB until tb4n1 (B5), when FinishUP's own `closure_prepare` replies, image reads, and large
outputs outgrew it and lost their PostToolUse rows, leaving the pre-events unpaired.

`finishup hooks claude-observe` now skims a complete body up to 8 MiB (`MAX_HOOK_SKIM_BYTES`) with the
same safety rules as the full parse:

- Image, audio, and video bytes (a `Read` of an image returns `type: image` with base64 under
  `file`; MCP tools return `image` blocks) are replaced with a fixed placeholder. If the body then
  fits the 1 MiB cap it is admitted whole and records no gap.
- A FinishUP MCP tool (`mcp__plugin_finishup_finishup__*` or `mcp__finishup__*`, `closure_prepare` included)
  keeps a closed identity row: session, tool, call id, lineage ids, and outcome flags. Its content
  is never captured in any case, so the row is complete, pairs with its pre-event, and records no
  gap.
- Any other body still over the cap keeps the same identity row with the
  `payload_content_omitted` gap and the `claude_payload_content_omitted` hook diagnostic. Command
  text, file contents, and output are not retained.

A body over the skim cap, or a complete oversized body that fails the parse, is still refused
before any row exists. The hook stays fail-open and the host continues. FinishUP records the bounded
`claude_payload_too_large` reason against that event in `finishup observe status` hook diagnostics,
and notes the `payload_too_large` coverage gap on the consented workspace, where
`finishup observe status` shows it. That workspace gap does not yet reach task receipts: no row
exists, so a receipt simply has no evidence for the dropped event rather than naming the loss.
The caps are fixed; raising them is not an operator control. A reader consumes at most
cap-plus-one bytes, so the true size of a refused body is never measured and never recorded. The
refusal costs exactly that one event; the next ordinary event still ingests.

Matcher decision (tb4n1 B5): the ordinary profile keeps its `.*` tool matchers, and the structural
profile keeps its FinishUP-scoped matcher. Excluding FinishUP tools from PostToolUse alone would leave
their pre-events unpaired, excluding them from both would drop the delivered record of FinishUP
mutations and failures, and the structural profile exists only to observe FinishUP's own tools. The
size problem is fixed in the reader instead.

Observed images (P3-2, issue #1013): A Claude Code `Read` of an image returns `type: image` with base64 under `file`, and MCP tools
return `image` blocks. Before the bytes are
dropped, the hook records up to 8 images per call as digest-only facts: SHA-256 and byte count of
the decoded image, a media type sniffed from its bytes (PNG, JPEG, GIF, WebP, else
`image/unknown`), and pixel width and height read from the header only. The service records one
`evidence_recorded` row per image (`artifact`, `content_digest`, `digest_only`), listed in the
call's result `evidence_refs`, with the description `Observed image tool result <type> <w>x<h>
(<n> bytes); pixels were not captured or sent`. No pixel is captured, stored, or sent; the agent
can cite the evidence id as its own inspection of the output. This holds at every body size up to
the 8 MiB skim cap.

### Failed-command findings (issue #1104)

A failed `Bash` call becomes an observation finding (`failed_command_unresolved`, kind
`failed_work_omitted`) seconds after it is recorded. Decisions for Claude Code:

Repeated observations that name the same accepted action/result event pair reuse the readable
finding ID and original reason that receipts, status and check report for that pair (#1160,
ADR-022 decision 7). The shared coordinator updates the advice snapshot; responses,
`duplicate_of` links and retirement proofs keep their recorded identities. Copies an older build
already recorded stay in the ledger; where they share an issue key, advice and the receipt both
name the newest. A distinct failed invocation remains distinct. This does not change the host
outcome requirements below.

- **Retire on pass: supported.** `PostToolUse` states success and `PostToolUseFailure` states
  failure (`fixtures/observations/claude-code-bash-outcomes.case.json`), so a later passing run of
  the same command, alone or as a segment of a passing `&&` chain run as is (no leading
  assignment, `env`, `nohup`, `exec`, `time` or input redirection, ADR-025), retires the finding
  (closure basis `retired_by_passing_run`). A chain whose earlier segment may not hand control
  back (`exec CMD`, `exit`, `eval`, `source`/`.`, an unsafe `set` or `shopt -o`, an unresolvable
  command word such as `$RUN`, `exec>log` or `{exit,0}`) is recorded `masked` and retires
  nothing. Pinned end to end, from the real hook handler through
  the coordinator's own finding to status and the receipt, by
  `tests/integration/application/test_failed_command_retirement_e2e.py`, and per host by
  `tests/integration/observation/test_failure_supersession_hosts.py`. An edit never retires it, and no check resolves it
  (`observed_failure_not_rerun`).
- **Retire on a passing planned verification: supported** (owner decision 2026-10-18, ADR-025).
  A later `PostToolUse` success of a command an effective obligation requests (the ADR-033 keyed
  commitment, or as a segment of a passing `single` run or `&&` chain) retires every earlier
  failed-command finding, even one for another command (closure basis
  `retired_by_planned_verification`). Pinned with the real Claude Code hook handler by
  `test_claude_passing_planned_verification_retires_an_unrelated_failure` in
  `tests/integration/observation/test_failure_supersession_hosts.py`, and through status and the
  receipt by `test_failed_install_then_planned_verification_pass_retires_it` in
  `tests/integration/application/test_failed_command_retirement_e2e.py`. A parallel call whose
  `PreToolUse` was recorded before the other call's failure began before it and retires nothing.
  A planned segment must have run as is (a leading assignment, `env`, `exec`, `nohup`, `time` or an
  input redirection passes nothing), a planned command that masks its own exit (`| tail`, `!`,
  `|| true`, `&`, `;`) never counts, and the passing call must have begun after the failed call
  finished. A failure it retires must still be named in a completion claim's `limitation_refs`.
  The passing run must be a verifier (the hook's runner class `test`, `build`, `lint` or
  `typecheck`; a planned `true` or `ls` retires nothing), and the obligation must have been
  effective when its `PostToolUse` landed: a plan published after the pass retires nothing, one
  published while the call ran counts (`test_claude_plan_published_after_the_pass_retires_nothing`
  and `test_claude_planned_command_that_is_no_verifier_retires_nothing` in
  `tests/integration/observation/test_failure_supersession_hosts.py`; owner decision 2026-10-18,
  #1104 comment 6252094173).
  The coordinator filters the hook-local advice mirror with the same current ledger retirement
  rule as `status view=advice`, Stop, check and receipts, after materializing findings. Retired
  findings also leave status's unanswered count and action-required work. Each advice rebuild
  re-evaluates the raw candidates: waiving the planned obligation or redacting its proof restores
  the finding and its hook advice at the next mirror refresh. Hooks consume that latest mirror;
  they do not synchronously read the ledger. A different planned verifier never removes the
  completion claim's duty to disclose the failed command. The shared integration regression
  covers normalized Codex, Claude Code and Cursor payloads; this is not native-runtime proof.
- **`acknowledged`** settles it as a disclosed failed command (`failed_run_disclosed`, never
  clean); `acknowledged_not_done` settles it as bookkeeping. A later pass still retires it.
- **Read-only chains and FinishUP's own CLI: supported**, as on every host (`cd`, banners,
  chains of reads, a here-document fed to `cat`, `| jq`, the installed launcher path).
- **Stopping its own background job: not exempt on Claude Code.** The exemption needs the exact
  exit `128 + signal`, and `PostToolUseFailure` states no exit status (only error text, which
  FinishUP never parses). Such a failure keeps the ordinary duty: rerun the probe without the
  kill, or acknowledge it. `KillShell` and `BashOutput` are not read (payload unverified). Both
  decisions are pinned through the real handler by the Claude Code variants of
  `fixtures/observations/failed-command-exemptions.case.json` (OUT-006).
- **Doubled skill path:** not applicable (a Codex cache layout).

### Smart observation selection (issue #687)

Claude's shared hook ingress applies the selector only to the generic tool stream exposed by the
exact ordinary profile `claude-code-ordinary-observation-v1`. The structural profile remains
scoped to the existing FinishUP events; selecting a retention mode does not widen that subscription.
With the ordinary profile, **Focused/standard (512)** is the default. A paired, proven successful
routine `Read`, search, or inventory call may be summarized in Focused mode. Detailed keeps
eligible routine calls as individual records while pressure is healthy. Capacity is independent
of detail: `standard` (512), `larger` (2,048), and `largest` (8,192) can each be selected with
Focused or Detailed. The larger profiles have finite provisional budgets and do not certify a
Claude host cell or improve sustained throughput.

The host outcome remains authoritative. `PostToolUseFailure`, denial, cancellation, interruption,
partial, unknown or conflicting outcome fields, background or incomplete work, edits and side effects,
declared checks/negative verification, and reads protected for an obligation, claim, or finding
remain individual records in both modes. A pre-event keeps its native identity until a post event
proves success; a caller label or tool result field cannot downgrade protection. Claude's
post-only structural profile has no pre-event to pair, so it retains the host's supported
post-only identity contract.

Apply an owner choice from an exact preview:

```text
finishup observe selection-preview --workspace /exact/project \
  --detail detailed --capacity larger --session-id <claude-session-id> --json
finishup observe selection-apply --workspace /exact/project \
  --detail detailed --capacity larger --session-id <claude-session-id> \
  --accept --preview-digest <preview-digest> --json
```

This is a temporary session override unless `--persist` is supplied on both preview and apply
without `--session-id`; `--persist` is the explicit workspace choice. An optional RFC3339 UTC
`--expires-at` bounds either setting. `selection-status` reports the selected and effective values;
`selection-revoke` restores the safe fallback at the matching scope. These controls affect future
retention only. They do not rewrite accepted rows, extend Claude's five-second ordinary-event,
ten-second session, or three-second teardown budgets, or change content, privacy, provider, or
network authority. Under pressure, a selected Detailed session can be effectively Focused while
the owner setting remains Detailed.

**Configurable capacity (issue #828) — Claude Code decision.** Claude Code uses the same local
capacity path as every other host: `finishup observe selection-preview` with `--capacity
standard|larger|largest`, `--capacity custom --queue-count <64..8192>`, or `--capacity none`, then
`selection-apply --accept --preview-digest`, or the terminal interface's `/observe`. There is no
Claude Code-specific capacity control, and repository or plugin configuration cannot raise capacity.
An agent may relay a change only after the owner accepts the displayed preview's scope, values,
local-hardware consequences, remaining limits, and lower/pause/resume path; ordinary task permission
never authorizes an increase. `--capacity none` returns `capacity_no_cap_unsupported` because the
local state document has a 16 MiB safety ceiling, and changes nothing; the largest supported
capacity is 8,192 rows. MCP `status` stays read-only for capacity. Hook body caps and Claude's hook
budgets are unchanged. Custom counts need control schema `2.9.0` on both the client and the service;
an older revision drops a saved custom count to the default.

**Lowering above the fallback byte bound (issue #843) — Claude Code decision.** Claude Code uses
the shared store path with no Claude-specific behavior. Lowering, revoking, expiring, or ending a
larger selection can leave more accepted rows than the new target holds. Those rows still drain,
and the store keeps finite room, tied only to them, for refused-input loss, delivery attempts, and
session ends. A refused hook reports `hook_observe_degraded: outbox_overflow; loss accounted`
only after the loss is durable. The notice ends with `cause=<cause>`, the closed admission
dimension that refused, and the same cause is recorded as the `admission_loss_<cause>` reason in
`hook_diagnostics.reasons` (ADR-029, tb4n1 B3). Only later inputs of the lost host call, or calls it
spawned, carry `observation_input_loss`; the shared store path applies this to every host. If a `SessionEnd` hook cannot persist its local end, it stays
fail-open within its three-second budget. It prints
`hook_observe_degraded: session_end_unrecorded` and records that reason in
`hook_diagnostics.reasons`.

Use `protect-read` before an upcoming read when a later claim needs its individual identity. The
reference must be an `obl_`, `clm_`, or `fnd_` identifier; at most 32 logical reads are outstanding,
and the protection expires after ten minutes by default (an explicit expiry cannot exceed that
bound). This is a narrowing hint under existing observation consent and grants no content or
disclosure authority. `promote` can only promote an exact native identity while it remains in the
bounded buffer. After delivery it reports `promotion_window_closed` and `not_retained`; rerun the
current read as a new observation if historical bytes are required, and do not use that rerun to
prove the earlier state.

Claude ordinary content capture remains a separate consent arm selected by the exact profile.
Its workspace-wide capture lane allows at most 512 staging/pending tickets and 128 MiB of captured
content, independently of the structural capacity choice. The one-second native content drain
window and the host hook deadlines still apply. A timeout, cancellation, incomplete content group,
or service failure leaves partial/unknown coverage or `content_capture_unavailable` where the
boundary permits; it is never silently converted to a successful routine summary. Capture status
proves configuration only, not accepted bytes, AI-powered review selection, or receipt coverage.

Claude Code 2.1.251 passes an MCP tool's `tool_response` to `PostToolUse` as one bare JSON string
of the structured result (captured live on 2026-09-04 with a probe MCP server that returned both a
text block and `structuredContent`; the text block is dropped). The binder admits that shape next
to a `structuredContent` object and a single-text-block content list, and a fixture pins it. A
scoped successful `start` that still binds nothing records `start_bind_unparsed`,
`start_bind_invalid_ids`, or `start_bind_write_failed` in `hook_diagnostics` (issue #581); a start
the service refused records nothing. This capture proves the `PostToolUse` shape only; 2.1.251 is
not added to the evidenced capability-profile table, whose entries mean the whole native contract
was reviewed. The `PostToolUse` payload carries no `claude_code_version`, so version evidence still
comes from `SessionStart`.

The `SessionStart` context for a mapped session names the task, its frontier, the mapped
`session_id` and `writer_id`, and says to continue the task with `start mode=attach` by that
session id (a bare `task_id` is not a selector the guidance accepts, issue #580). The `resume` and
`compact` status probe connects with `--workspace "${CLAUDE_PROJECT_DIR}"` as its repository
locator, so a live mapping answers `active` with a refreshed frontier; a daemon fence refusal
records `status_workspace_unbound` or `status_workspace_mismatch` and keeps the mapping, and only a
genuinely replaced session records `mapping_stale` (issue #578). Claude Code does not use the
Codex-only `hooks session-start` command, so the issue #659 host-cwd fallback applies to it only
through the shared mapped-session lane: an explicit `${CLAUDE_PROJECT_DIR}` remains authoritative,
an empty or unset value stays the typed `workspace_unresolvable` failure with no ingest and no
probe, and a fence refusal records a companion `locator_source_explicit` row. No live Claude
compaction failure was observed for #659; the shared resolver is covered by unit tests only.

## Auto mode and host admission

Claude Code's auto-mode classifier sees the tool name, the request JSON, user messages, and
`CLAUDE.md`; descriptions, annotations, and tool results are stripped, so no descriptor wording
can satisfy it. `permissions.allow` / `ask` / `deny` resolve before the classifier and are honored
from the repository's `.claude/settings.local.json` (repository root, resolved through
worktrees to the main checkout); a plugin cannot ship permission rules. Allow rules use the
configured server name: `mcp__finishup__check` for an external `finishup` registration and
`mcp__plugin_finishup_finishup__check` for the plugin-owned server. (`code.claude.com/docs/en/permissions`,
`/permission-modes`, `/hooks`, re-read 2026-08-30.)

Host admission (issue #467) follows the exclusively observed MCP owner and writes exactly its
`check` name into `permissions.allow` (or `permissions.ask` with `--checkpoint`), digest-bound to
the file bytes. An external route must use the configured server key `finishup`; a differently named
exact FinishUP route remains visible to ownership status but refuses admission because its callable
permission name is not the fixed supported surface:

```text
finishup integrate claude admission preview --project-root "$PROJECT_ROOT" \
  --claude-path "$CLAUDE_PATH" --claude-config-root "$CLAUDE_CONFIG_ROOT" \
  --cache-root "$CACHE_ROOT" --marketplace-root "$MARKETPLACE_ROOT" \
  --mcp-ownership <external-registration|plugin-managed> --json
finishup integrate claude admission grant --project-root "$PROJECT_ROOT" ... --accept --preview-digest <digest>
```

The Claude roots are what the route observation needs (`status` on the plugin); without them
the route is unread and a grant refuses with `host_admission_route_unobserved`. A strict route
refuses with `route_not_policy`; a grant that does not permit review with
`grant_not_permitting`; a service that cannot be read with `grant_unverifiable`. A grant whose
exact entry already sits in the other list is a mode change — `grant` after `grant --checkpoint`
(or the reverse) moves the entry between `allow` and `ask` under the same digest-bound preview;
only re-granting the mode already set is a `noop`. A wider rule
(`mcp__plugin_finishup_finishup__*`, `mcp__plugin_finishup_finishup`), a deny rule, or the tool in both
`allow` and `ask` is `foreign` and never edited. A mutating preview warns
`host_config_not_compare_and_swap`; keep Claude and other settings writers quiescent during apply.
FinishUP rechecks the exact preimage immediately before mutation and verifies the result, but an
ordinary file cannot exclude a non-cooperating same-UID writer in the final syscall window. If
`.claude/settings.local.json` is tracked in git or `.claude` is a symlink, Claude Code holds its
rules until the folder is trusted; FinishUP itself refuses to edit through the symlink.

Reverse: `admission revoke` removes both exact owner forms; `plugin remove` and a `plugin
install|update` onto the strict route sweep it for `--project-root` and report
`admission_cleanup`; `setup disconnect --host claude` plans `remove_project_admission` for
`--project`, sweeps it before the plugin removal and reports `status.admission_cleanup`
(other projects are not enumerated; inspect them with `admission status --project-root`); a privacy commit that stops external review sweeps it; a leftover entry
shows as `host_admission_drift` in `provider status`. That report walks from the launch
directory to the repository root, so a subdirectory cwd does not read as `absent`.

The rendered `hooks/hooks.json` carries a sixth hook, `PermissionDenied`, matched to exactly the
external and plugin-owned `check` names. It fires after auto mode (or a rule or another hook) denies
the call and can allow nothing; the ingress keeps only a closed token and records one payload-free
`hook_diagnostics` reason — `host_auto_review_denied` (`source: auto_mode` or absent) or
`host_permission_rule_denied` (`permission_rule` / `hook`) — so `observe status` can show a held
check as host authorization, never as an AI-powered review status. FinishUP deliberately ships no
`PermissionRequest` hook returning `decision: allow`, which would make the plugin the authority over
the host's own review.

The same scoped hook reports a hold to the user (issue #857). Its stdout has
`hookSpecificOutput.{hookEventName, retry}` and a bounded `systemMessage`. Claude Code 2.1.281's
installed schema and handler and the [current reference](https://code.claude.com/docs/en/hooks#permissiondenied)
were checked on 2026-09-26: `PermissionDenied` drops `additionalContext`. The user sees the
first-hand notice; the model receives only the host's retry cue, with exact-request and pause
rules supplied by the shipped skill. Do not claim model-visible grant delivery from PermissionDenied.

| Facts | User notice | `retry` | Diagnostic |
| --- | --- | --- | --- |
| confirmed grant, recognized classifier verdict, first recorded offer this session | external review grant present; this invocation was held; one identical retry may be offered | `true` | `host_denial_retry_offered` |
| same session already offered a retry | present the exact call for human approval | `false` | `host_denial_retry_exhausted` |
| no verdict or unknown source/reason | classifier verdict not established; ask the human | `false` | `host_denial_retry_exhausted` |
| legacy `source` `permission_rule` or `hook` | owner rule held it; ask | `false` | `host_denial_retry_exhausted` |
| grant absent or unreadable | grant unconfirmed; closed reason named | `false` | `host_denial_grant_unconfirmed` |
| full, damaged, unsafe, contended or unwritable retry ledger | confirmation without a retry | `false` | `host_denial_retry_unrecorded` |

Current Claude omits `source` and does not fire this event on manual denials or deny rules.
No-verdict detection includes the reason prefix `Auto mode could not evaluate this action and is
blocking it for safety`, `Classifier unavailable`, and the legacy `no_verdict` token. Unknown
sources and missing reasons fail closed. Host payloads are never echoed.

The repository-bound grant read has a 2.5 s deadline covering connect, request and cleanup.
`observation/host-hold-retries.json` stores at most 64 session digests under the owner-only state
directory. Old offers are never evicted to make room: at capacity, new sessions need human
approval. Damaged or unsafe ledgers are preserved without offering another retry. Admission
remains the durable owner choice; revoke it through `finishup integrate claude admission revoke`.
A grant notice is not MCP route verification. The strict route still blocks external dispatch.
SessionStart can deliver a separate first-hand grant snapshot to the model when the shared
observation path is consented, local admission is absent, and spare context/time allows a fresh
repository-bound read. It names `finishup integrate claude admission grant` but explicitly leaves the
active route and host approval unconfirmed. It does not prove the grant at a later denial or that
the classifier consumed the notice. Local-only, deferred and unreadable paths add nothing.
Policy-route attribution for a held call and the live Claude auto-mode approval/denial cell remain
unverified and tracked in #857. No machine-wide last-started bridge record is used.

Claude Code surfaces MCP initialize `instructions` as server instructions in the model's context.
Whether the auto-mode classifier reads them is not documented, so the policy-route destination
disclosure (issue #479: provider, endpoint profile, and host, or the Codex runtime class, plus the
payload bound, read once at bridge startup) is informational on this host; it is not relied on for
admission, which stays with `permissions.allow`.

## Update

A released plugin byte change requires a new generated manifest version. Preview `--action update`,
consume a fresh exact review, and run `plugin update` with the same roots/ownership/route. FinishUP
rewrites only its exact marker-valid source, invokes marketplace update and qualified project plugin
update, then verifies the new cache/version/digest. New cached bytes are not active until reload or
a new session proves the loaded root. Preserve and report old/orphaned cache roots; do not delete
them merely because Claude normally sweeps them later.

## Disable and remove

Disable is its own preview/review/action and proves only the effective setting. Removal is likewise
preview-bound. It invokes:

```text
claude plugin uninstall finishup@finishup-local --scope project --keep-data
claude plugin marketplace remove finishup-local
```

Then it removes only the exact marker-valid private marketplace source. It preserves plugin data,
FinishUP ledgers, vault/keyring/provider state, privacy/workflow receipts, credentials, other scopes,
foreign marketplaces/MCP entries, modified sources, and orphaned caches. A lost/nonzero CLI result
is `outcome_unknown` — as is any post-mutation state the read-back cannot confirm, even on exit 0;
run status and reconcile rather than guessing rollback. Replacement and removal revalidate the
displaced tree after renaming it out of the public path and destroy only a marker-valid managed
tree; interrupted stage/rollback material surfaces in status as `recovery_required`.

## Proof checklist

Claude Code is not an allowlisted `finishup consent authorize` attestation client in v0.1. It may show
the agent-safe pending status and direct the user to a supported Codex attestation or local trusted
command, but it must not emulate `vault_initialize` or `vault_passphrase_rotate` authorization.
It still guides setup, installation, and settings choices in normal conversation and leaves each
supported product choice with the user. When AI-powered review is the stated goal, it recommends
Expanded first and explains Assisted as the lower-disclosure AI-powered option. It may show the full
v6 repository privacy preview, but its missing chat-authority capability is a technical boundary:
give the shortest exact trusted-local continuation and never silently downgrade the chosen recipe,
provider, or model.

First-run start continuation (issue #512): on a never-initialized install, the agent's first MCP
`start` returns non-retryable `VAULT_LOCKED` carrying
`safe_details.continuation: vault_initialization_required`. The Claude Code flow is trusted-local:
run `finishup consent prepare vault_initialize`, show the returned danger text to the user, direct
them to run `finishup consent review` on a local terminal (the `authorize_command` the generic
profile advertises is valid only for an allowlisted agent-chat client, which Claude Code is not),
wait for the ceremony's terminal result, then replay the exact original `start` request ID and
body once. On denial or expiry the agent states the boundary and continues without FinishUP.

Record source/render/marketplace/cache/executable digests, exact Claude version/OS/architecture,
scope, settings state, component inventory, enabled state, loaded root and session boundary, MCP
owner/source/runtime, scoped model call, hook consent/evidence, AI-powered review/provider attempt
and privacy receipt, and final workflow receipt as separate cells. Never summarize those cells as
one “plugin works” flag.

## Codex subscription evaluator from Claude Code

A Claude Code policy route may request the same service-owned `codex-chatgpt-subscription@1`
AI-powered evaluator. Claude never receives the Codex OAuth credential, dedicated home, app-server
handle, or tool authority, and Claude activation/model use is not proof that the evaluator ran. A
strict Claude route must produce `route_semantic_ceiling` with zero Codex child launch. Use the
[subscription evaluator runbook](codex-subscription-evaluator.md) and record Claude host activation,
AI-powered review attempt/runtime evidence, privacy receipt, corrective influence, and workflow
receipt as separate claims.

Evaluator runtime retention and repair (issue #855) is host-independent. From a Claude Code
session, the prompt menu, or `/provider`, `finishup provider codex-subscription repair` and
`runtime status|install|remove` behave exactly as documented in the
[subscription evaluator runbook](codex-subscription-evaluator.md#evaluator-runtime-retention-and-repair).
Decision for this host: supported through the shared provider surfaces, with no Claude-specific
step. Native Claude acceptance of a post-repair check is pending.
Capability admission of the evaluator's Codex release (ADR-006, 2026-10-13: the newest installed
Codex at or above `0.157.1` that passes the check, adopted by the next `repair` or `setup`) is
equally host-independent; nothing in the Claude host integration changes.

Fallback endpoint pairing (issue #582) is host-independent: whether the evaluator or a paired
API provider serves a given attempt is a service-side dispatch decision recorded in provenance
(`fallback_from`), with no Claude-Code-specific behaviour, plugin, or route input — the route
ceiling applies to dispatch authority regardless of which endpoint serves.

Routine/final Codex review budgets (issue #571 item A1) are host-independent too. The service
selects the budget profile from the frozen case: `final` when the frontier carries a completion
claim, `routine` otherwise. It then dispatches with that profile's configured effort and output
limit and records them in provenance. Claude Code gets no host-specific behavior, registration, route
input, or per-request selector, so the decision for this host is "supported, unchanged".
Recording a completion claim is the only way a check requests the final profile.


### Review packet reserved room and named missing items (#907)

Claude Code `Edit`, `MultiEdit` and `Write` captures carry workspace-relative paths, so the newest applied edit of each path is
reserved as the current diff and older hunks for the same path are marked `superseded_by`. Shell
rewrites without visible bytes are still uncaptured (#883). Verification output is reserved per
command when the agent records the action, result and output; captured tool output has no command
identity until #910. An `insufficient_packet` check lists `missing_for_assessment` items with
their availability in the MCP and CLI check result; recheck only after supplying an
`agent_suppliable` item.

### Large tasks and AI-powered review failure recovery (#674–#676)

This host uses the shared service status snapshot cache and bounded AI-powered review reference
selection. A reduced reference scope reports `semantic_reference_scope_reduced`; it is not full-task
AI-powered review coverage, and check, status and receipts keep saying so. It does not stop a
repaired local finding from resolving. An AI-powered finding raised under the same bound can
resolve after repair and a later completed review whose sent packet carried the finding's own row,
its response-linked repair evidence and a change made after it, and accounted for each subject
(sent, superseded by a sent claim, or an early event the history window evicted, #947); otherwise
`finding_material_outside_reduced_review_scope` is named. `semantic_included_refs_not_recorded`
means what that review sent could not be recorded; run one new check, and disclose the finding if
the code repeats. A newly reduced scope or a `truncated_payload` gap still blocks it (#904). Cross-host dogfood of this resolution rule on macOS, Linux and WSL 2
has not been run yet; owner #904. `failed/case_capacity_exceeded` and
`semantic_case_capacity_exceeded` mean the required packet, or since #1118 the rendered review
disclosure (the channel's byte ceiling or the reviewer exchange budget: 262,144 bytes, or on the Codex subscription route with `gpt-6.1-sol` 524,288 bytes and 169,144 estimated model tokens; ADR-006), could not fit, and
nothing was sent. Select a smaller claim/obligation scope for a new check. Shorter prose alone need
not fix structural capacity. A disclosure-capacity refusal has a `blocked_by_policy` /
`policy_denied` privacy receipt with `final_bytes` 0, and `finishup service diagnostics
--request-id req_…` shows `semantic_disclosure_capacity_exceeded` with the attempted size and the
limit.

For `coordinator_failure`, use the check's original request ID with
`finishup service diagnostics --request-id req_…` to read bounded failure stages. Dispatch entry can
have an unknown outcome, even with null provenance. A missing record is a diagnostic coverage gap,
not proof of non-dispatch. Preserve the original request/attempt identity and existing retry rules.
These shared-path regressions do not certify a fresh installed native-host session.


### Evidence-first closure

The shared guidance instructs this host to cite the evidence IDs it published (listed with
`filter.author=mine`, descriptions returned to their writer) and to find native captures with a
filtered `status view=evidence` read (`filter.strength=immutable_snapshot`) before publishing
replacement evidence, reusing only IDs a structural link (a `view=results` row's
`evidence_refs`, or a matching digest) ties to the claim. It no longer asks for an unfiltered walk
that matches on descriptions: under the default `agent_context` ceiling, other writers' and
host-observed descriptions are omitted (`local_disclosure_not_authorized`), which is a privacy
setting, not missing evidence.
Digest-only, unavailable, unselected and clipped items remain separate limits. Evidence discovery
and reuse do not prove native capture coverage or command success. Read `command_attempts` on
obligation rows: this profile may omit command text, in which case reconciliation is `unknown`.
Only service-stamped, explicitly linked observations can support a match or mismatch. The optional
CLI closure composer uses the same projected status inputs; it does not grant capture or egress.
These shared regressions are synthetic contract evidence, not live-host certification. A dogfood
transcript showing this host citing its own or filtered evidence IDs without an unfiltered walk,
and dogfood CI across macOS, Linux and WSL 2, are not yet recorded; that gap is owned by #914.

### Mechanical closure preparation (#953)

The current Claude Code MCP surface advertises the read-only `closure_prepare/1.0.0` support tool.
Discover its declaration before use and pass the returned session and writer identities with an
explicit selection. It inventories one pinned status frontier or prepares one explicit draft; it
never appends, judges work, or claims completion. The complete response frame is bounded: an
draft phases echo only the rows the selection names, and an oversized inventory returns
`LIMIT_EXCEEDED` (`closure_result_too_large`) without partial data. When the declaration is absent,
use `finishup closure-prepare --session-id <returned-session> --writer-id <returned-writer>` with
`--output <file>` outside the repository. This shared route is supported through the local bridge
on macOS, Linux, and WSL 2; native Windows has no supported FinishUP MCP route. MCP discovery,
activation, and native host dogfood remain separate evidence.

### Observation limitation findings and closure rechecks (issue #911)

Claude Code's ordinary profile is paired, so a missing `PostToolUse` leaves an orphan
(`unpaired_event`) and lag or drain gaps can raise the same advisory. Decision for this host:
supported, same rule as every host. The
rule is service-side and host-neutral: an observation-authored, non-actionable finding (the
"Observation coverage is incomplete or stale" advisory, including rows written by earlier builds)
never counts in `unanswered_finding_count` or `findings_unanswered`, and acknowledging it once is
optional and never supersedes a recorded check. It stays in `status view=findings` and on the
receipt as a disclosed limitation and does not become resolvable. `refresh_observation` remains in
operator-facing status and structured advice while a recoverable cause is present, but it is never
emitted through Claude's `hookSpecificOutput.additionalContext`; hook context carries work advice
only. The
shared guidance and this host's skill give the closure order: answer unanswered findings before the
final check (the current status frontier is a valid `finding_frontier`), answer only the findings
that check returns that are still unanswered, then `receipt`, then `work_closed`; no recheck follows
those answers, `work_closed`, or an `insufficient_packet` review without a new repair, while a
recorded repair still gets its re-check. Which conditions raise the advisory, and how the sticky
`unpaired_event` gap surfaces, are owned by issue #917. Verification: shared-path regressions cover
the ledger rule on the memory and SQLite backends; a live Claude Code dogfood transcript on macOS,
Linux and WSL 2 is not yet recorded. That gap is owned by issue #911.

### Closure readiness and standing limitations (#913)

Claude Code's reviewed pairing contract is post-only, so its observations carry no synthetic
`unpaired_event`, and `PostToolUseFailure` records a failed call. Its standing set therefore
depends on the capture profile and privacy policy rather than on pairing: content selection and
capture limits (`content_unselected`, `content_capture_unavailable`, `content_redacted`), the
AI-powered review bounds when a review ran, and `semantic_review_not_requested` on a local-only
route. A finished session whose remaining conditions are only standing reads
`ready_with_limitations`.

Classification is service-side and host-agnostic: the closed table in ADR-032 assigns each code
once, a code the running build does not know stays agent-actionable as `unclassified_gap:<code>`,
and nothing is removed from `known_gaps` or the receipt. `semantic_review_not_requested` is
standing on a local-only or optional route and on the strict MCP route (which never dispatches
AI-powered review), and agent-actionable only when the verification policy requires AI-powered
review, the serving route can dispatch it, and none has succeeded since the last material change.
A check on a route that did not require AI-powered review records `semantic_route_required:
false`; there the code no longer bounds the receipt conclusion (issue #986, same on every host). A check that asked for `deterministic_only` on such a route records no
`semantic_review_not_requested` at all, so no receipt, status or readiness view lists it (issue
#1041, same on every host).
The strict local-only MCP route is such a route even when the verification policy is `required`,
unless the check asked for `semantic_required` (issue #1021, ADR-040, same on every host).
At
`closure_readiness.state: ready_with_limitations` the agent requests the receipt without another
check; the receipt conclusion is unchanged (a local-only check stays `insufficient_coverage`).

X-HOST evidence: the derivation is covered by service-side contract tests over a Codex-shaped
ledger replay; a dogfood transcript on this host across macOS, Linux and WSL 2 has not been
recorded yet. That gap is owned by issue #913.

### What follows the last check on Claude Code (tb4n3 RC-6, #1029)

Claude Code names FinishUP's tools `mcp__plugin_finishup_finishup__<tool>` (or `mcp__finishup__<tool>` for an
external registration); both are read as FinishUP's own calls. `Read`, `Grep` and `Glob` are the
hook's `exploration` class; `Edit`, `Write`, `MultiEdit` and `NotebookEdit` are edits that
supersede a check unless every path is scratch or a FinishUP receipt; `Bash` is classified by its
command (`exploration` only for a closed read-only set, otherwise `other`). The `Stop` hook's
completion-signal evidence names no tool call. Decision: supported, same service-side rule as
Codex; tested through the real ingress in
`tests/unit/application/test_tb4n3_later_material_host_shapes.py`.


### Inspection check on Claude Code (#1048)

`check` with `"mode": "inspect"` is a read inside FinishUP: it records nothing, mints no finding, runs
no review and needs no FinishUP disclosure decision, so a lost answer is answered by asking again with
a fresh `request_id`. One call returns what is left to close (the `status` readiness split, then
every unresolved obligation and finding with what it lacks and whose move it is), the
hook-observed actions since the last check, and whether each obligation's resolution evidence links
to its declared deliverables or requested commands (`evidence_off_declared_items` when it does
not). Use it instead of a series of `status` reads; no status read or `dry_run` is required before
`publish_work`. The startup read is the operating card (`agent-instructions.md`); the larger pages
are read on demand. ADR-047. The MCP `check` tool and `finishup check` carry the mode, and the same
text is printed on both. The `Edit`/`Write` hooks record a write class, never a path, so observed
edits are listed by class.

Host approval is per tool, not per mode. An inspection is a call of `mcp__finishup__check` or
`mcp__plugin_finishup_finishup__check`, so Claude Code applies the `check` rule
([Auto mode and host admission](#auto-mode-and-host-admission)): admission in `permissions.allow`
runs it without a prompt, admission with `--checkpoint` (`permissions.ask`) prompts on every
`check`, inspection included, and without admission (always so on the strict route, which
admission refuses with `route_not_policy`) the permission mode decides; auto mode's classifier sees
the tool name and the request JSON, never the descriptor. Decision: supported behind the `check`
rule. A held inspection leaves nothing pending in FinishUP and no review to protect, so the agent reads
`status` instead and continues; the review-hold rules do not apply to it (guidance `review.md`).
The `PermissionDenied` hook skips its advisory for `mode: inspect` as it does for
`mode: deterministic_only`: a denied inspection shows no AI-powered review notice and spends no
retry offer.

### Guidance delivery on Claude Code (tb4n5)

- **Closure trigger in the skill description.** The skill description ends "Also use when a
  FinishUP finding, Stop message or receipt needs an answer", so a host that selects skills by
  description can load the skill again at closure. Decision: supported; whether this host
  re-selects the skill at closure is unmeasured until its dogfood lane runs.
- **Initialize body.** The Claude body already said "Do not list resources"; it drops its cadence
  sentence, which the operating card states once (ADR-047 amendment). The skill keeps one start
  sentence that names its antecedent, the card pointer and the closure judgment rules; the capacity
  procedure is the catalogued topic `workflow.md#change-local-retention-capacity`. Decision:
  supported.
- **Page-zero sections.** Page zero of a paged `read_guidance` read appends the section list after
  its end marker (`FINISHUP_GUIDANCE_SECTIONS ...`, one `#<anchor> <bytes>` line each) and carries
  `structuredContent.sections`. The list is outside the page bytes, so `GuidancePageAssembler`
  verifies the page as before. Decision: supported.
- **Check-cell deadline at closure.** Not applicable: Claude Code runs a tool call to completion
  and does not use code-mode `exec` cells. The close instruction is chosen from an observed
  capability, not the host brand, so Claude Code gets the neutral sentence and no `yield_time_ms`
  pragma.

### Bounded workflow recovery examples (#613)

These examples use the existing MCP operations on the pinned local Claude Code cell. Replace
placeholders with values returned by the current call or `SessionStart` context; do not reconstruct
them from memory, `CLAUDE.md`, or the live store.

- **Read retry.** If a `status`, diagnostics, or `status view=operation` read times out, repeat the
  same read intent with a new read `request_id`. Preserve its view, operation filter, cursor, and
  limit. An unreadable read is not evidence that the task or operation is absent.
- **Ambiguous write.** If a `start` response is lost before session/writer IDs are returned,
  replay the exact original `start` body once with the same request ID. Otherwise read
  `status view=operation` with `filter.operation_request_id` set to the original write ID:
  replay only `absent`; use stored `complete`; follow an exact typed continuation and required
  approval before replaying `pending`. Retain and report pending without a continuation,
  `quarantined`, or unknown. Never invent session/writer IDs or create a task to escape a write.
- **Refused check admission.** A check `OPERATION_PENDING` carrying the
  `check_admission_same_identity` continuation recorded nothing: its `reason_code` names the stage
  (`check_admission_capture_pending`, `…_in_progress`, `…_contended`, or `…_import_pending`) and
  `status view=operation` reads `absent` with the same `admission` stage. Replay the exact check
  body and request ID after `retry_after_ms`, at most three times, then report the check as not
  admitted. The service is host-agnostic here; this host needs no extra step (issue #838).
- **Exact-session attach.** When the `SessionStart` context provides a held `session_id`, use that
  exact value as the `mode=attach` selector. `${CLAUDE_PROJECT_DIR}` is the canonical workspace
  fence supplied by the host context; if the request carries identity refs, include the canonical
  `workspace_ref` + `external_ref` pair together, never `workspace_ref` alone. Use the returned
  successor `session_id` and `writer_id`, read `status`, and continue only from that binding. A
  bare `task_id` is not an attach selector.
- **Same-pair fresh conversation.** With no held session, call `start mode=create_or_attach` using
  the exact canonical `${CLAUDE_PROJECT_DIR}` value and the same stable `external_ref` pair, with no
  `session_id`. The same pair resumes; a different complete pair is independent work, even in the
  same workspace. A remote URL is not a workspace identity.
- **Explicit sibling handoff.** Use `start mode=create` only after same-task pair/session recovery
  is exhausted, every earlier write has a known terminal outcome, the Claude binding is healthy and
  authorized, and the user has declared one bounded remaining or repaired verification scope. Keep
  `${CLAUDE_PROJECT_DIR}` as `workspace_ref`, choose a different stable `external_ref` such as
  `<work-item>-recovery-v1`, and let the exact returned `start` result pass through Claude's
  `PostToolUse` binder. Verify the sibling's `mapping_present` and returned task/session/writer,
  then publish fresh plan, evidence, checks, and receipt for that scope. State that the predecessor
  receipt, findings, obligations, evidence IDs, and unresolved status remain separate; the sibling
  cannot make the predecessor look resolved. If no new scope exists, keep the old receipt and stop
  instead of creating another sibling.


## Runtime another account can write

A runtime another account can write (ADR-007, 2026-10-14) stops `finishup mcp serve` with `release_runtime_group_writable` or `release_runtime_world_writable` and the exact `chmod -R go-w` repair on stderr (`/mcp` shows the server as failed; `claude --debug` shows its stderr). Its hooks exit 20 with no stdout, so they make no allow or block decision (exit 2 is the only blocking code); Claude Code shows a non-blocking hook error; their stderr names the token without local paths and points at `finishup service run`, which prints the repair. Group write through the user's own private group (the Ubuntu/Fedora umask 0002 default) is accepted.

## Observation recovery diagnostics

Claude Code uses the shared selected-admission and outbox store. New native input obeys current hard
pressure and the complete projected buffer/outbox size; accepted replay work remains drainable.
Hard pressure can recover to high before optional detail recovers. A generation-fenced session
end retires pressure scheduling without deleting pending work or historical losses.

Unknown capture inventory can reject new input even when the outbox is empty. The READY
service now schedules a bounded inventory recovery pass independently of the next hook (#695),
using an existing unambiguous mapping and the authoritative catalog/bundle inventory. An unreadable
route or missing mapping stays blocked rather than being assumed empty; recovery retries after
it becomes readable without requiring a fresh event. Do not reset local state, enlarge capacity,
or toggle consent to manufacture a healthy status. Real hard limits continue to apply after
inventory recovery, and previous loss counts and identities remain unchanged.

Recovery emits fixed `capture_inventory_*` reason counts in its internal maintenance summary;
these are not ledger receipts or a new hook diagnostic format. Historical local selection losses with complete original route attribution are reported by
service maintenance even when no later envelope is admitted. New checks reconcile their task's
pending losses first. Each source/session/generation/route lane produces one permanent
`observation_input_loss` marker, preserving all local counts and identities. Missing original
attribution and overflow-only range history remain visible locally rather than being assigned to
an unrelated task. A terminal route drift or quarantined marker operation uses the same task
runtime with a distinct deterministic recovery operation; transient publication failures remain
fail-closed. Catalog scans run through separate read-only worker connections, keeping the service
event loop available during both inventory reads.
Route-valid lane-digest mismatches are reported with the same explicit loss gap and an
unreconciled marker; malformed routes or source identities remain local.
Host-shaped regression tests, including interleaved parent/worker routes and encrypted readback,
are not a version-pinned acceptance run inside the installed vendor application.

Hook and manual drain control failures have `control_` reasons. A protocol error is not a
`ledger_rejected` result. A control failure stops further calls on that connection; the next
hook, manual drain or service sweep can attempt the retained identity. Oversized or locally
invalid requests are terminal. Transport/protocol retries are bounded to 128 consecutive
same-cause attempts; owner-action conditions such as a forbidden method or incompatible
protocol stay pending until corrected. Retrying does not establish whether an earlier request
committed; exact source/cursor identity supplies replay deduplication.

`finishup observe status --workspace . --json` includes `hook_diagnostics.drain_failures`: up to
32 retained causal records with source/session commitments, generation and position, original
control reason and retryability, adapter stage, final disposition and correlation ID when supplied.
A `control` stage does not identify which side of the socket failed; `request_encode` and
`response_decode` identify locally observed boundaries. Missing correlation remains null. Typed ingest refusals have stage
`typed_ingest` and null control fields.
Diagnostic files rotate at 64 KiB with one backup; this is explicitly incomplete retained history.
A failed diagnostic append records `drain_diagnostic_unavailable` when store bookkeeping succeeds.
No command, prompt, path, raw session ID or raw source ID is included. Existing quarantine is
not automatically replayed or reclaimed, and new diagnostics cannot explain old entries.

Pre-tool hooks reuse advice at its recorded frontier; outcome hooks, lifecycle hooks and service
ingest refresh it. Once structural ingress is durable, ordinary hooks that spent the local
one-second allowance defer optional follow-up with `hook_followup_deferred`. Transient native
content and lifecycle hooks do not take that deferral. Drain snapshot, connect, RPC and local
bookkeeping share one elapsed drain budget; synchronous local writes cannot be interrupted safely.
Reads of the local observation store never wait for its lock (issue #689). Every store-lock
wait in one hook pass shares a single deadline measured from hook entry: 3.5 s for
tool events (5-second host timeout), 7 s for SessionStart and Stop (10 seconds) and 2 s for
SessionEnd (3 seconds); each wait
is still capped at two seconds. A pass whose capture cannot take the lock in time still exits
with the host's ordinary fail-open output, does not retain that input, and records a
`store_lock_timeout` diagnostic naming the holder's role, store phase and hold time (listed
under `store_lock_events` in `finishup observe status`); holds of one second or more are recorded
as `store_lock_long_hold`. Neither is reported as `observe` or `workspace_unconsented`.

This host shares the observe pass: an unexpected exception is recorded as
`observe_<exception class>` (`observe_exception_unavailable` for an unlisted class) and a drain
preflight names its stage (`drain_connect_timeout`, `drain_connect_failed`,
`native_content_stage_failed`), as described in INTERFACES (tb4n2 N-3).

For shared-store measurements and the remaining native-host coverage boundary, see
[the performance runbook](observation-selection-performance.md).

## Release notifications and upgrade choices

SessionStart can deliver one cached package-update recommendation in this host's context format.
The service checks on READY and at most hourly thereafter, under the existing update-check policy
and 24-hour PyPI cache. Hooks never access the network. Advice remains available when workspace
observation consent is absent or observation is disabled; it grants no observation authority.
Task/receipt advice can occupy the same context slot and defer the recommendation.

Use the exact advertised accept/decline command, including `--release-version`. A new decline skips
that release; older permanent declines remain respected. Acceptance only supplies the upgrade
instructions, and execution requires the user's explicit upgrade request. Package replacement does
not itself prove host activation; a compatible data migration is performed by the fresh service
before READY and must be verified separately. Preserve the existing host roots, ownership and
privacy choices; new settings such as Expanded review require a separate exact approval.

## Recovery directives in errors (ADR-030)

Claude Code's generic MCP profile delivers only the text `content` for `isError` results, so this
host is the one that most depends on the directive reaching the text channel. A public error
carrying a registered `continuation` token renders its frozen directive, any carried consent
commands, its guidance pointer, and its nudge inside the bounded (4,096-byte) text projection, dropped from the
least load-bearing end when the budget is tight.

**Bounded text and committed operations (ADR-043, issue #1025).** Because this host reads only the
text `content` of an `isError` result and the summary of a success, the summary is composed with its
required core first (verdict or error identity and location, the `overall next` instruction, the
review status/reason, the frontier with its head digest) and never raises. A text that cannot be
built never fails a committed call: the omitted clause is named
(`summary_render_failed:<builder>.<clause>`), a service diagnostic records it, and the structured
result is returned. Hook `additionalContext` over FinishUP's own 2,000-character cap ends with a cut
marker; no Claude Code document available here states a limit, so the cap is FinishUP's own. The
behavior is the same on macOS, Linux and WSL 2.

This is the host where the gap was observed: before ADR-030 a `VAULT_LOCKED` result whose
`safe_details` already carried `vault_initialization_required` and its prepare command reached the
model as `Error VAULT_LOCKED; retryable: no; correlation: err_...` and nothing else (issue #740).

The same projection names the rejected location of a schema-validation failure (`Rejected:
<reason> at <pointer>`), which this host previously lost entirely because the `fields`/`reasons`
lists are not protocol safe-detail keys. A timed-out `start` receives `start_timeout_same_identity`
(replay the exact start once) rather than the write directive, which needs ids a lost start never
returned.

No Claude-specific behavior is configured: the projection is host-neutral and lives in
`finishup.mcp.summaries`.


### First-start contention and long review recovery

Native and explicit MCP startup share the catalog lease-yield repair. A released start lease
carries the typed same-request retry directive; an active lease carries the bounded wait directive.
Both retain the original body and request identity. The shared service keeps an admitted semantic
check running after an ordinary client wait timeout or disconnect; an explicit control cancellation
or service shutdown still cancels it. This is shared service behavior, not proof of a new native
Claude dogfood run.

For a returned start error with `start_busy_same_identity`, the reservation remains durable and
only its fenced lease was yielded. Replay the exact start body and request ID once, without
inventing session or writer IDs. `start_pending_same_identity` instead means a live lease remains:
wait up to 60 seconds before the one exact replay. If still busy or pending, retain the original
request and report the unresolved start. These continuations do not authorize a new task.

**CLI JSON (issue #741).** When an agent in this host runs `finishup` in a shell with `--json`, a
CLI-owned JSON error body carries a `recovery` object resolved from the same registry. A workflow
command (`start`, `publish-work`, `check`, `respond`, `status`, `receipt`) also prints JSON when
stdout is not a TTY; its failure keeps the exact wire body on stdout and writes the directive
lines to stderr. This is CLI behavior shared by every host; no Claude Code-specific behavior is
configured.

**Provider outcomes (issue #742).** A check whose AI-powered review failed carries a
`continuation_for_semantic_outcome` token in the shared CLI and MCP check projections. Claude
Code depends on the MCP text channel, so the token and, when the bounded text budget allows, the
directive appear there. Raw provider text never reaches that projection. Hook advisories never
carry this token; SessionStart's vault-locked advisory appends its own `vault_unlock_required`
token after the host-specific prefix (issue #739). No Claude-specific recovery wording is
configured.

### Structural review progress (#571 A2)

Decision: supported through the shared MCP `status` tool with no Claude Code-specific behavior,
registration, or route input. Call `status` with `view: "operation"` and the check request ID while a long review runs; Claude Code receives the privacy-minimized text summary, which names the operation state, phase, attempt, condition, elapsed and remaining milliseconds, and the structured page carries every field. The phase vocabulary, deadline, and terminal outcome are
service facts, identical for every host; progress never includes provider text, tokens, reasoning,
or account identity. A read from a different session or writer of the same task may return
retryable `BUNDLE_BUSY` while the check runs. This is shared service behavior, not evidence of a
fresh installed native Claude Code dogfood run.

## Post-compaction recap (issue #1027, ADR-044)

Decision for Claude Code: **supported.** Claude Code reports `source: compact` on the `SessionStart`
that follows a compaction; the wrapper encodes it as the structural action `claude_session_compact`
and the shared observe pass reads the mapped session's compact `status`, then one bounded `obligations`
view, and appends the receipt-style recap to `hookSpecificOutput.additionalContext` after the held-ids
cue and the admission notice. The whole context is at most 4,000 characters (the recap at most 2,400;
every other hook context keeps 2,000). Each line names its source, withheld text stays withheld, and any
failure leaves the held-ids cue unchanged. `startup`, `resume` and `clear` starts are unchanged.

No `PreCompact` hook is registered, and none is needed: the recap is composed after the compaction from
the ledger, and the ordinary pass already drained the outbox when the last tool hook ran. Claude
Code's own limit on hook context size is not asserted here; the 4,000-character bound is FinishUP's.
Native acceptance of the recap on an installed Claude Code remains a pending dogfood lane; the
behavior is covered by hook-level tests only.

## Cold service attachment and recovery (issue #670)

Claude Code SessionStart returns its result through synchronous `additionalContext`, within
the existing ten-second registration budget. Ordinary tool hooks keep their five-second budget.

For an enabled, consented workspace with no mapped task, auto-attachment now gives the exact
selected service one second to connect or start through its fixed, instance-pinned launcher.
It never supersedes another installation. A compatible stamped holder that is still starting
is reused only while an owner-only nonblocking flock probe confirms that the singleton is held;
an unheld stale stamp is ignored and the fixed launcher makes a normal flock-protected start
attempt. A live incompatible or unknown holder is refused. The connection time counts toward
the existing five-second attachment RPC budget. Turn-boundary retries retain their one-second
outer budget and reserve part of it for the start RPC after a shorter connector arm; ordinary tool hooks and SessionEnd do not start a service. Local-only readiness
probes and unconsented/disabled observation do not take this path.

The native context distinguishes a service that is unavailable or still starting
(`service_unavailable`), an incompatible holder (`service_incompatible`), and an answered
admission conflict (`auto_attach_conflict`). Missing mapping remains explicit. Call cooperative
`start` before material work and follow its exact continuation; a conflict needs an authorized
task selector or explicit admission decision, not a service restart. Successful hook exit alone
does not establish attachment. A unique ended predecessor is attached before a new pair is created;
ambiguous predecessor tasks produce `auto_attach_binding_ambiguous` with a count only, and the
explicit session-plus-new-pair recovery preserves the selected root task even when unrelated
tasks share the canonical workspace (#814, #816). It still checks the active selector, workspace and
repository binding, and pending operations for that task; delegated child routes keep their
authenticated attachment path, and no task interaction authority is added.

Structural pre/post observations remain queued and keep their original identities across
bootstrap. A later successful mapping permits their normal drain. Missing transient content
remains a coverage gap; a recovered queue is not recovered content. Existing host/OS capability
and consent requirements still apply. Automated host-contract tests do not establish native
macOS, Linux, or Windows/WSL 2 acceptance. Native cold-start coverage remains tracked in #670.

## Repairing an accepted empty-scope claim (#859)

Use the shared `publish_work` operation (CLI: `publish-work`) and
[claim correction guidance](../../guidance/publication-policy.md#claim-correction-and-limitation-linkage).
Publish `claim_recorded/1.1.0` with a fresh claim ID, explicit `obligation_refs`, and every replaced
claim ID in sorted `supersedes_claim_refs`. An empty-scope target needs no overlap; each populated
target still does. For an empty C0 plus scoped C1, replace both in C2. Preview the exact batch first,
then append, recheck and request a receipt. History and unresolved evidence/review limits remain.
New completion claims must declare scope explicitly; obligation support is not scope. Intentional
`[]` remains coverage-incomplete and cannot carry obligation support. No host hook invents scope or
performs this repair. The shared service behavior applies on macOS, Linux and Windows through WSL 2;
source tests do not establish native host/platform acceptance.


### Reviewable native edits

With the ordinary content profile enabled, Claude Code `Edit`, `MultiEdit`, `Write` and
`NotebookEdit` calls enter the shared encrypted capture lane as changed-file content. Only public
edit fields are kept (`file_path`/`notebook_path` as a relative `path`, `old_string`, `new_string`,
`edits[]`, `content`, `new_source`, cell identifiers) plus the result's line-numbered
`structuredPatch`; the result's `filePath`, `originalFile` and unknown fields are never kept. No
Bash call is needed: the dedicated edit tools are captured directly. `PostToolUseFailure` marks the
edit `failed`. Shell heredoc edits (`cat > path <<EOF`, `tee path <<EOF`, `git apply <<EOF`) are
also captured from the post-tool shell event as changed-file or workspace-diff content, marked
`edit_source: shell`; edits made by `sed -i`, scripts or `git apply <file>` are not captured, but
the check-time change below still shows their result.

The capture runs from the post-tool event only, once per edit: the pre-tool proposal is neither
duplicated nor kept as raw tool input. Each captured edit names the host-reported outcome
(`applied`, `failed` or `unknown`), so a rejected or unconfirmed edit is never presented as applied
code. Every file locator is made workspace-relative; a locator outside the workspace, a
home-relative or drive-relative locator, or any `..` path is replaced by `<outside-workspace>` or
dropped. The rule is lexical and identical on macOS, Linux and Windows through WSL 2: POSIX
(`/home/<user>/...`, `/Users/<user>/...`), Windows drive (`C:\...`), UNC (`\\server\share\...`) and WSL
mount (`/mnt/c/...`) spellings are compared, with drive, mount and UNC forms matched
case-insensitively, and no filesystem lookup is made. Edits use the ordinary capture caps (at most
16 chunks and about 680 KB per event), not the routine-output budgets, and remain subject to the
existing capture consent, secret scanning and outbox admission.

Selection ranks claim-linked evidence first, then captured edits (newest first), then other captured
output, so later test logs or file reads cannot starve a patch. A selected capture whose envelope
has aged out of the latest-256 session window is still read by exact content reference; one that
cannot be reached is disclosed as `content_unselected`. Identical retained bytes are selected once.
Retained code is split into bounded UTF-8 excerpts, with omitted content and truncated prefixes
disclosed under the existing count and byte limits. Hooks do not create a Git diff; the service
does, once per check, as described in [Check-time change](#check-time-change). Bounded packet
inclusion does not prove that the reviewer detects a defect. Pause, revoke and content-capture
disable continue to stop admission through the existing shared controls.

### Check-time change

When the review recipe selects diff excerpts (`assisted`, `expanded`, or a custom recipe that keeps
the `diff` kind), each check carries a **check-time change** (ADR-031): the FinishUP service reads the
task's repository once, when the check runs, and puts the result ahead of every other excerpt in the
review packet. It covers committed and uncommitted changes to tracked files since the commit
recorded when the task started, plus untracked files Git does not ignore (`.gitignore`,
`.git/info/exclude`, a repository `core.excludesFile` and your global Git ignore file). Because the
base is a commit, uncommitted work that was already there when the task started is included too;
untracked files that were already there and are unchanged since are left out and only counted in the
header, because `start` records their names and a metadata digest with the base (#1045). A nested Git
repository has its own change read under its directory, from the HEAD `start` recorded for it when
there is one; its untracked files are left out or shown like the outer ones when `start` listed them
whole, and are otherwise named but never read. Up to four read-only task input files the task
statement names travel as separate repository excerpts (ADR-031, #1045 amendment). This is the same
on every host: it reads the repository, not a host capture. A header lists every changed
file with its line counts and says which files were not
shown. Script edits (`sed -i`, Python rewrites, `git apply <file>`), commits and hooks that never
fired are therefore reviewed even though no capture exists for them.

The directory is the one the check's own connection named: the project directory Claude Code started
the FinishUP MCP bridge in, or the working directory of `finishup check`. The service reads that directory
only when it resolves to the task's own repository, and never runs a shell, hook, filter, external
diff, credential helper or network transport. The task-start commit is recorded when `start` creates
the task. A task created before this version, or from a connection that named no workspace, has
none; its first check pins HEAD as the task's base, later checks diff from that commit so work
committed between checks stays in the change, and each such check reports
`check_time_change_base_unavailable` because work committed before that first check is not in it. It
needs no content profile or hook: with only the structural profile, or with plugin-directory loading
on macOS, the check still reads the change from the repository. The capture honours the review
recipe and privacy policy like any other excerpt, as `repository_excerpt` items: a policy whose
inference channel does not allow that category never sends them, and the check reports
`semantic_review_context_withheld`. Credential-like spans are redacted first
(`check_time_change_redacted`), every part still passes the never-send scan, files named like
credentials (`.env`, `.env.*`, `.netrc`, `*.pem`, `*.key` and similar, a name heuristic) are listed
by name only, and a change larger than the packet reports `check_time_change_truncated`. The whole
capture has 20 seconds. It is `check_time_change_unavailable` for a linked Git worktree or a
submodule checkout opened as the repository (its `.git` is a file), a repository root another
account can write (group write through the owner's own private group is fine, ADR-007), a repository whose effective Git config defines a filter or an include (for example
a repository-local Git LFS or git-crypt setup), a partial clone, a system Git older than 2.25, a repository
whose object store is reached through a link or borrowed from another repository (`.git/commondir`
or alternates), a repository whose Git settings point its working tree elsewhere (`core.worktree`),
a repository directory replaced at the same path between Git commands, or a working tree that kept
changing through three attempts to read it. A changed file, tracked or untracked, that is a link or
has a second name is listed but neither its content nor its line counts are shown. Object files a
local `git clone` hard-linked are read normally, because every Git object a shown diff uses must
match its own name. Beside `check_time_change_unavailable` the check records a reason code such as
`check_time_change_unavailable_changed_during_capture`, and the check result, `finishup status` and the
receipt each state that reason in one plain sentence. A later review clears an AI-powered finding
despite these limits only when it saw each file the raising review saw, whole or through an
identical view; for a file shown in part each check records a keyed commitment to where its
redactions and hunks lay, never its content, so a moved redaction or hunk keeps the finding open. A
replayed or resumed check reviews the change captured when it first ran, not the tree as it is
later. `finishup service diagnostics` counts the parts that reached the packet as
`semantic_check_change_parts_selected`.

### Caller digests and capture binding (#912)

A `content_digest` the agent publishes through ordinary publication is recorded as `caller_asserted`
with `digest_only` (or `withheld`) availability. On this host, as on every host, it raises no local
finding; the receipt's limitations name once, with a count, the cited evidence items whose
caller-asserted digests FinishUP did not verify, keeping digest-only items (the bytes were not
retained) apart from withheld items (the publisher recorded the bytes as withheld). The
service-side binding that would upgrade a caller digest matching captured bytes to verified
provenance (#912 part (b)) is not implemented yet, so
every caller digest keeps that unverified label here. When it lands, the captures it can bind to on
this host are `Edit`, `MultiEdit`, `Write` and `NotebookEdit` changed-file captures under the
ordinary profile (a whole capture or a hunk-sized byte range of it), shell heredoc captures, and
captured tool output. The follow-up owner is issue #912.

Native dogfood of this path on this host (macOS, Linux and Windows through WSL 2) has not been
run yet: the behavior is service-side and host-independent by construction, and only kernel and
application tests cover it. Parity is not claimed until that dogfood runs; the follow-up owner
is issue #912.

## Background semantic advice controls

The shared service offers frozen advice through the same approved review-packet assembly as
explicit checks (#1019). Rule metadata and scoped gaps are structural; finding summaries require
approval of `finding_summary`. Invalid or withheld advice stays blocked, and privacy receipt
category lists describe actual category denials separately from the request's failure reason.
This is shared dispatch behavior; the host's hook adapter and ordinary advice delivery are unchanged.

Background review is on by default wherever AI-powered review is configured
(`[verification] semantic` `required` or `optional`); an explicit `[observation]
semantic_advice_enabled` always wins, and `false` turns it off (issue #888, maintainer decision
2026-09-30). `finishup provider status` (`background_advice`), `finishup setup status --next`
(`facts.background_advice`) and the terminal interface status view show the effective state and
its closed reason. When on,
background review uses the shared service's routine budget, condition deduplication and durable
per-session interval on macOS, Linux and Windows through WSL 2. See
[background review frequency](../usage/providers.md#background-review-frequency) for disable,
resume and interval settings. The setting gates recovered pending work as well as new scheduling:
while it resolves off, startup closes rows an earlier service left pending as `cancelled` with no
provider identity (nothing sent), so re-enabling never replays them. Explicit checks and
local advice retain their independent behavior.

Background review is also admitted only while a provider is usable: an endpoint bound, the machine
policy admitting `llm_inference`, the configured credential present, and an ACTIVE task route
whose repository authority is granted and authorizes the configured primary endpoint for the
`semantic-review` purpose, judged by the same policy checks dispatch applies (issue #923).
Background review never engages a declared fallback endpoint, so its readiness reads only the
primary. Without them
the service writes no advice rows and reports `advice_semantic_unavailable`, not
`advice_semantic_pending`; rows queued earlier close as `provider_unavailable` without provider
work. Under a preview-required policy (the metadata-only recipe, or `preview_required` on the LLM
channel) background advice is skipped with `advice_semantic_preview_required`: no row, no pending
approval, no provider identity (#1019 round 2). Supported identically on this host; the host
adapter is unchanged. A foreground-cancelled call that may have started names its provider on the `cancelled` row
(usage unknown). This is service-side and identical on every host and supported OS; hook advice
rendering is unchanged.

## Root-owned project roots (non-root container users)

Claude Code project setup, hooks and MCP use the shared project-root rule (ADR-007, 2026-10-14): a
non-root user may use a root-owned project root that no other account can write, or a sticky one.
Files FinishUP writes inside the project must still be the user's own. Verified for Codex in a Boat
container as `nobody` and `agent`; the same check path is unit-tested for this host.

**Runtime another account installed.** Decision for Claude Code: same path as every host (shared entry
and setup code; no host-specific change). A runtime root installed and a non-root user runs stops
`finishup mcp serve`, `service run` and every hook with `release_runtime_not_owned` (exit 20) instead
of `release_runtime_unavailable: permission_denied` or "could not be verified". `/mcp` shows the server as failed and `claude --debug` shows its stderr; its hooks exit 20 with no stdout, so they make no allow or block decision and Claude Code shows a non-blocking hook error. Terminal
commands print the `.<prefix>-releases` directory the user must own; hook stderr carries the token
without local paths. Every connect path refuses to connect Claude Code to such a runtime (or one another
account can write) with that reason and leaves status and disconnect available. `finishup instance create --bind-runtime` on such a runtime
is `runtime_pin_unwritable` and keeps nothing, so a retry after the repair succeeds (ADR-028,
2026-10-14 amendment). Install FinishUP as the user, or see the Linux runbook for the one-user
`.<prefix>-releases` layout. Verified on Linux as `nobody` against a root-owned runtime (entry and
hook paths, not a Claude Code session); the Claude Code connect refusal is unit-tested.

**Review fixes (independent review of #1071).** Decisions for Claude Code: (1) a checkout root
made (`/app/.git` owned by root) is the project, used as a plain directory, through the shared
workspace binding (same path as every host); (2) Claude-specific: every plugin mutation runs
`claude plugin ... --scope project`, which writes `<project>/.claude/settings.json`, so preview
(and therefore apply) now refuses a `.claude` another account created or others can write
(`target_unsafe`) before any command runs; an absent `.claude` is left for Claude Code to create
(in a sticky root another account could create it in the instant before Claude Code does, which
FinishUP cannot fence; root can pre-create `.claude` for the user to close it);
(3) host admission never writes `.claude/settings.local.json` into such a `.claude` (same path as
every host; refined in round 2 below). Not changed: Claude Code's executable must
still be the user's own, so a root-installed `claude` is refused (`target_unsafe`) for a non-root
user, unlike the Codex launcher, which accepts a root-owned executable. Covered by tests through the
public preview/apply functions (connect and remove in 0755 and sticky root-owned projects, and a
squatted `.claude`) with simulated ownership.

**Review fixes, round 2.** Decisions for Claude Code (same path as every host unless named): (1) a
checkout root made (`/app` and `/app/.git` root-owned), or the user's own `git init` in a sticky
root-owned `/app`, now passes the service handshake: the service commits the plain directory
identity without running Git (Git refuses another owner's checkout), so hooks and MCP attach;
Git-based change capture reports `unsafe_root`. A root-owned `.git` file with more than one link
is not trusted. (2) A `.claude` root committed to the image is read normally: admission status is
`absent` (typically) and host admission's own reverse sweep (the privacy ceremony) reports nothing to remove instead of `write_failed`; a
grant into it is refused `target_unsafe`. A `.claude` another account made, or one others can
write, is `unknown` (`folder_not_owned`) in status and refused by grant and revoke; writes to
`.claude/settings.local.json` go through the host folder pinned by descriptor, never a link swapped in after the
check. (3) `setup run --host claude` and the full-screen interface's `/connect` refuse before any `claude plugin` command runs. Covered by tests through the public paths with simulated ownership, and the
repository identity with a real Git checkout owned by another uid.

**Review fixes, round 3.** Decisions for Claude Code: (1) the plain directory identity of a root-built
checkout is now its top's (the directory holding `.git`), the same from any subdirectory, so a
session started below the top meets its own hooks instead of `repository_identity_mismatch`
(same path as every host). (2) Check-time change capture reports `unsafe_root` for such a
checkout; the receipt reads "the repository failed a safety check (a link, another owner, ...)",
not "not a Git repository" (same path as every host). (3) `integrate claude plugin preview|install|update|enable` (any connect action) now refuses a runtime
that cannot serve this account with exit 20 and the token, before host discovery or any `claude
plugin` command; `disable`, `remove`, the removal preview and `status` stay open. Not covered:
`integrate claude plugin export`, a development carrier for `claude --plugin-dir`, not a
connection. Known gap: a `.claude` root committed to the image is refused `target_unsafe` by
every Claude Code plugin change (install, update, enable, disable, remove; status still reads it),
because each requires the user's own `.claude`; have root make it the user's (`chown -R <user>
<project>/.claude`). Follow-up: let removal read a root-owned `.claude` no other account can
write.

## Response and receipt timeout recovery

The shared MCP bridge allows 50 seconds for `respond` and `receipt` by default, below the
common 60-second host MCP tool limit; `start`, `publish_work` and `status` keep 30 seconds and
`check` keeps 300 seconds (a `check` with `mode: inspect` is a read and takes the `status`
deadline). Set `FINISHUP_MCP_DEADLINE_MS_<TOOL>` (one tool) or
`FINISHUP_MCP_DEADLINE_MS` (every tool except `check`; an inspection follows the `status` variables) in
the MCP server environment to change them;
values are milliseconds, clamped to 1,000-900,000. Keep them below the host's own tool timeout.
A timeout may follow a committed write. For `publish_work`, `respond` and `receipt` the bridge
checks `status view=operation` once and, when the write already completed, returns its stored
outcome directly. Otherwise use the timeout's pollable handle: `safe_details.replay_request_id`
as `status`'s `filter.operation_request_id` with `view=operation` and the carried `session_id`
and `writer_id` (`safe_details.state` is the probed state), or replay the unchanged write body
under that same request ID. Never mint a replacement write ID to recover an unknown outcome.
A lost first `start` still uses exact same-body replay because session/writer IDs may be absent.
This behavior is identical on macOS, Linux and Windows via WSL 2. CLI callers may set `--deadline-ms`.

## Reviewer packets and admitted outside-workspace inputs (issue #1082)

Decision for Claude Code: supported, service-side, identical on every host. The reviewer
instruction, the packet ranking (since #1108 the change's reserved share first, then task inputs
within an eighth of the excerpt room, the verification oracle, FinishUP's summaries of binary
inputs, redundant captured edits yielding to the latest verification) and the digest-only alias are
composed by the service from the ledger and the check-time read; Claude Code needs no host step and
nothing new is captured from it. `admitted_input_roots` is a field of the current repository's
privacy grant: `finishup privacy input-roots add <dir>` is a widening that applies only after the
trusted-terminal decision, `remove` is an immediate tightening, and `status`, `finishup privacy
show` and `/privacy` show it. Claude Code sessions, MCP tools and hooks have no write path to it; an
agent learns from the review guidance that only the owner can admit a folder. No Claude Code
capability gap. The consent-gated local copy of each outbound packet is not part of this change
(#1085).

## Reviewer instructions and packet order (n7, issue #1108)

Decision for Claude Code: supported, service-side, identical on every host. A tool output a Claude
Code hook captured reaches the reviewer behind `[FinishUP: observed output captured by a host hook
(evidence <evd_>)...]`, which the instruction treats as a witness; FinishUP's own records (an
approved check's result, an import report) carry their own labels; the agent's disclosures travel in
one `agent-disclosures` row marked as its assertion; and the packet lists the task, the change, task
inputs and observed output before the agent's account. Nothing is captured from Claude Code beyond
what its profile already captures, and no host step changes. The label's run clause (command action,
host-reported outcome, exit status) appears only when the hook recorded both the action and its
result with a keyed `omitted:hmac-sha256:` command identity equal to the capture's. That identity
comes from the post-tool command context the hook keeps only for runs FinishUP classifies as test,
build, lint or typecheck, as on Codex; any other command's output gets the bare label, without the
run clause. The run clause has no Claude Code host-payload test yet: the native capture test proves the label for Claude Code
tool output, and a hook-recorded run with the keyed identity takes the same service path as on
Codex, but that parity is unproven. Open follow-up, owned by the workstream issue #1108: a Claude
Code host-payload test of the run clause.

Issue #1102 (same decision for Claude Code, service-side, no host step and no new host payload): a
directory the task names inside the repository reaches the reviewer as FinishUP's listing of its
unchanged files plus the members most likely related to the change (sharing names with it, or beside
the changed files); a quoted or escaped path with spaces is one candidate, and when only the disk
can tell a spaced folder from prose the whole path is looked for before its words; an admitted
outside directory named without a trailing `/` is listed; an `other` follow-up request is answered
only from rows FinishUP recorded for the run or edit it names. When the task names a file or folder
outside the workspace that no admitted root covers, the check records
`task_input_outside_not_admitted`, whose fixed sentence names the owner's step
(`finishup privacy input-roots add <folder>` on a trusted terminal); it is a disclosure only, never
a Stop-gate item or a continuation on Claude Code. Claude Code still has no write path to admitted roots,
and FinishUP adds no unattended one: a non-interactive harness can admit roots only through an
owner-attended ceremony while it is provisioned. The code is decided once by the check-time read,
only for a path that exists outside the workspace and predates the task, so a route or an output
the agent writes never counts. The terminal interface shows the code without its sentence (it
renders coverage codes only); the owner's route there is the privacy panel, which names the
admitted roots or, with none admitted, the step `finishup privacy input-roots add <folder>`, while
the CLI, MCP and receipt print the sentence. `finishup service diagnostics` counts the task inputs on
`semantic_case_built` as integers only: `semantic_task_input_candidates`,
`semantic_task_inputs_read`, `semantic_task_input_listings`,
`semantic_task_input_excerpts_selected`, `semantic_task_input_outside_candidates` and
`semantic_task_inputs_outside_not_admitted`.

## Possible-credential filter opt-out (issue #982)

Decision for Claude Code: supported, service-side, identical on every host. `credential_heuristic` is a
field of the current repository's privacy grant that the service applies only to external
AI-reviewer egress; agent-context projection and the local model keep the filter. Claude Code needs no
host-specific step and gets no write path: `finishup privacy credential-heuristic disable` is a
widening that applies only after the trusted-terminal decision (walking the grant-creation
ceremony when the repository has no grant), `enable` is an immediate per-repository tightening,
and `--machine-default` moves only the default for new grants. MCP `status` carries
`credential_heuristic` (`repository`, `machine_default`) before any check; MCP tools and hooks can
only see the setting (status, the `semantic_review_credential_heuristic_disabled` check gap, the
external receipt's `secret_scan.credential_heuristic`). No Claude Code capability gap.

## Privacy receipts listing (issue #921)

`finishup privacy receipts list` and `get` are host-agnostic: every host's sessions write receipts
into the same local audit, and the operator reads them through the same CLI and control method.
Pages over 64 KiB now cross the local control socket in bounded chunks, an unreadable stored
receipt is skipped, counted and named (exit 40) instead of failing the page, and a store-side
failure is `privacy_audit_unreadable` rather than `invalid_request`. In-process tests drive the
real service, socket and client. Open evidence gap, owned by #921: a dogfood run on Claude Code
(macOS, Linux and WSL 2) that completes an AI-powered review session and then shows that
session's `network_egress` receipts in `finishup privacy receipts list`.

## Status page cost (issue #916)

`status` pages and `closure-prepare` no longer pay ~18 ms per returned row: the shared service,
control and bridge path decides schema validity without rebuilding diagnostics for valid results,
with byte-identical pages and receipts. This host uses that path unchanged. Its per-host dogfood
timing on macOS, Linux and WSL 2 is not yet measured; issue #916 owns it. See
[status render performance](status-render-performance.md).

## Hook schema loading (issue #1083)

A Claude Code hook process no longer builds the full schema catalog before its first control frame.
It parses only the control envelopes' schemas and their `$ref` closures, 92 of 232 documents,
with the same verdicts and errors ([interfaces](../INTERFACES.md)). Unchanged on this host:

- `hooks claude-observe` and `hooks startup-context --host claude`;
- hook registration, payloads, outputs, recorded events, ordering and timeouts.

Host decision: supported, same code path.

Latency: the #1083 replay drove 6 PreToolUse and 4 PostToolUse ordinary-profile callbacks from the
repository's recorded shapes through the build before and after the change on macOS arm64 (single
idle machine, shipped launcher). The median PreToolUse fell from 1,417 to 1,096 ms and PostToolUse
from 1,457 to 1,190 ms. Linux and WSL 2 timings are not yet measured; issue #1083 owns them.

Equivalence: the #1087 replay proof ([test instances](test-instances.md)) replayed the 19
ordinary-profile callbacks, and 9 malformed payloads, on Linux x86_64 on 2026-10-17 through the
merged predecessor (`0.3` at `c0198bb16`, with #1080 and #1086) and this change's head
(`ea1f6eda4`). Every exit code, stdout and stderr byte, drain, status read and ledger event with
its full payload compared identical after the normalization that runbook describes, which matches
run-generated values, such as task, session and result ids, one-to-one: 208 compared parts in the
Claude Code workspace, including 20 ledger events. In the new build 8 of those callbacks parsed
only their schemas and none built the full catalog; the old build built it in the same 8. A second
replay of the new head compared identical with the first.
The MCP bridge (`mcp serve --host claude`) is not replayed: it builds the full catalog as it starts,
so its validation is unchanged by this change.

## Expanded excerpt count (issue #907 Phase 1b)

Decision for Claude Code: nothing is host-specific, and the behaviour is identical on every host and OS.
The excerpt count is a privacy-policy and review-packet limit. It is enforced by the service, not by
hook or MCP adapters. From privacy policy 1.2.0 the Expanded recipe allows up to 64 excerpts within
its unchanged byte budget (16 KiB each, 128 KiB in total). An Expanded policy approved earlier keeps
16 until the owner re-approves through `finishup --privacy`. A packet above the approved count or bytes
is refused as `policy_denied`, never trimmed. A case that would exceed the per-case channel ceiling
is planned with fewer excerpts and discloses `content_unselected` instead of being refused.
`finishup privacy show` shows the current limits beside
the proposed ones. To go back to 16, choose Assisted or propose the earlier Expanded limits; that is
a narrowing, so it needs no new approval. The selection order within the budget (issue #907 Phase
1a) is recorded separately.

## Task statement for AI-powered review (issue #908)

Decision for Claude Code: supported through the agent-supplied field, identical on every host and OS.
The agent passes the user's request verbatim as `start.task_statement` (MCP `start` or
`finishup start --task-statement-file`). To revise it, the agent calls `start` again with
`mode=attach`, the `session_id` it holds, a fresh `request_id` and the whole amended request; a CLI
publisher may instead carry it in a `plan_revised` 1.1.0 payload. A resume that does not change the
request omits the field, and the recorded statement stays current. The review packet carries it as
the `task_statement` section labelled `agent_transcribed`, apart from the plan, only when the
approved privacy policy names that section (privacy policy 1.2.0 presets Goal-aware, Assisted and
Expanded; never Structural). With no statement recorded the task title stands in, labelled
`task_title_only`, and no gap is added. When the policy withholds the section, or its review channel
does not allow `task_description`, the check and receipt
carry `task_statement_unavailable` with `task_statement_not_authorized`; with neither a statement
nor a readable title they carry `task_statement_unavailable` with `task_statement_not_supplied`.

Claude Code's `UserPromptSubmit` payload can be captured under an ordinary content profile as `visible_user_message`, but that captured text never enters an AI-powered review packet; see below.

Host-captured prompts (`host_captured_user_prompt`) are not used on any host in this version:
captured prompt text never enters the packet, and the Expanded-only, explicit prompt-capture
choice that would allow it is still open on issue #908.

Automatic attach does not record a task statement. The shared observation hook opens the task
with a generic title and no `task_statement`, so until the agent calls `start` with the user's
request the reviewer sees at most that title (`task_title_only`), and the receipt says so.
Recording hook text there would label it `agent_transcribed`, which it is not, and would bypass
the prompt-capture consent still open on issue #908.
For Claude Code the first attach runs on `SessionStart`, before any prompt exists; a retry on
`UserPromptSubmit` sees the prompt only as `visible_user_message`, which stays out of review.

### Tool-call records and orphan notices (#917)

The default structural Claude Code profiles are post-only: their ledger records are byte-identical
after #917 (pinned by a replay of real `PostToolUse` payloads), and a post never diagnoses a missing
pre. The opt-in ordinary profile (`claude-code-ordinary-observation-v1`) is on the conservative
paired contract, so it receives the same fixes as Codex: an individually delivered `PreToolUse` and
its post share one action (described as observed via Claude Code hook), and a post with no open pre
keeps the standing `unpaired_event` record and triggers one "FinishUP notice (no response needed)"
per new orphan scope instead of a recurring stale-observation advisory. Claude Code has no
code-mode cell, so the stream wrapper rule does not apply; for the same reason the tb4n5 yielded-
and tool-less-cell decisions (ADR-029 amendment of 2026-10-13) are Codex-only, and Claude Code has
no `clock.sleep` tool (the `clocksleep` no-activity spelling is Codex's hook name). The same
amendment's rejected-call record is host-agnostic: on the paired ordinary profile, a pending
`mcp__plugin_yoetz_yoetz__*` attempt whose call FinishUP's MCP server answered with an error closes as
`rejected_by_yoetz` (after a 5 s grace in which a post, if Claude Code sends one, still pairs, or at
once when the session ends or its generation advances). The Claude Code adapter commits to the call
(tool, FinishUP session, writer and `request_id`, or for a `publish_work` sent without one its
canonical arguments; nothing else) from the hook's `tool_input` before structural
normalization drops it, and passes only that commitment on; a body too large to keep its
`tool_input` keeps the ordinary expiry;
`observe status` names every ending under `pending_attempt_endings`, and local ring eviction is
`local_retention`, never `truncated_payload`. Post-only profiles keep no pending attempt, so
nothing changes there. The hook drain diagnostic `drain_budget_exhausted` is renamed
`drain_pass_delivered_nothing` and `observe status` reports the outbox `delivery_lag` (enqueue to
acceptance) for Claude Code hooks exactly as for Codex (ADR-022 amendment of 2026-10-13).

### Limitation requests, `reopened` and one dialogue per concern on Claude Code (tb4n3 RC-1 and RC-7, #1024, #1030)

Host decision: supported, no host-specific code. The change lives in the shared kernel, `respond`
and review paths (ADR-034 and ADR-040 amendments of 2026-10-11), so Claude Code behaves exactly as the
other hosts. The Stop hook and the MCP `respond` tool take the shared path; a Claude Code session sees the same `respond` description and the same `closure_after`. What a Claude Code agent can rely on:

- A reviewer finding that asks the agent to `state_unresolved_limitation` is a to-disclose item, not
  repair work. `kernel/limitation.limitation_standing` reads it; `finding_blocks_receipt` is false
  for it. The agent's answer decides what it means (owner decision 2026-10-12, ADR-040 and ADR-046
  amendments): one reasoned `respond` `acknowledged` (or `self_verified`) or a
  `finishup-verification-limit:<obligation id>` decision says the requirement may be met but cannot be
  verified here, and settles it as a disclosed verification limit with no recorded resolution
  attempt required (never clean, at best `insufficient_coverage`); `acknowledged_not_done` says the
  requirement is NOT met and keeps `unresolved_findings_remain` like any unmet requirement. When an
  unanswered request is the only agent work left, the check's next step is `disclose_limitations`.
  The Stop hook and readiness read the same closure class on every host.
- `acknowledged_not_done` is no longer a one-way door: `respond` with `reopened` and a reason takes
  it back, and a qualifying `check` that tested the work after the answer resolves it (also for
  `self_verified`).
- One concern stays one finding: a re-raise over a settled item (or an open item of the same kind
  over the same concern) is recorded on that item and listed in the check's review summary instead of
  minting a new id; the agent's own earlier rebuttal stands after a later acknowledgement.
- Never empty or withdraw a working deliverable over a finding or an "empty file if unsolved" clause.

Verification: `tests/integration/application/test_tb4n3_limits_dialogue_shapes.py` drives the real
check, respond, status and receipt operations with a compliant reviewer; a live Claude Code transcript on
macOS, Linux and WSL 2 is not recorded for this change.

### Call-schema traps on Claude Code (tb4n4, #1049)

Host decision: supported, no host-specific code. Every change lives in the shared protocol request
models, the MCP bridge's `read_guidance` dispatch and error hints, the status text and the kernel's
`command_attempts` rule, so Claude Code takes the same path as the other hosts. What a Claude Code agent can rely on:

- `decision_recorded` carries no id of its own; a `decision_id` in its payload is accepted and
  ignored (never recorded, and a retry with or without it replays the same request).
- A `status` `limit` sent as a JSON integer from 1 to 100 is read as its decimal string.
- A `read_guidance` anchor that names exactly one catalogued topic of its document (the heading's
  slug, an explicit anchor beside it, or words only that anchor contains) reads that topic; the
  result's `uri` is the catalogued one. An ambiguous or unknown anchor is still refused with the
  document's anchors, unless it is exactly the catalogued anchor of one other guidance document
  (n7, #1103; see below).
- A resolution without `resolution_evidence_refs` (omitted, empty or the wrong id kind) is refused
  with the sentence that says what the list holds; the `status` `view: "obligations"` text states the resolution recipe, that field included.
- A run linked to a requested command with a `command` action (the PL6-3 link) is a disclosed
  equivalence: it reads `command_attempt_uncorroborated`, never `command_attempt_mismatch`, and a
  `self_verified` refusal on a remaining `command_attempt_mismatch` names that link as the exit.
- A `result_recorded` payload's `evidence_refs` still names evidence ids only; the refusal for a
  `res_` id names where a result id goes.

Verification: `tests/unit/mcp/test_tb4n4_call_traps.py`, `tests/unit/kernel/test_tb4n4_command_link.py`
and `tests/integration/application/test_tb4n4_decision_id_replay.py` replay the recorded shapes
through the bridge validation, `read_guidance` dispatch, the kernel and the real publish operation;
the tb4n4 exports themselves were not replayed, and a live Claude Code transcript on macOS, Linux and
WSL 2 is not recorded for this change.

### Avoidable MCP rejections on Claude Code (n7 RC3, #1103)

Host decision: supported, no host-specific code. Every change lives in the shared publish and
respond request models, the `respond` and `receipt` applications and the `read_guidance`
resolver, so Claude Code takes the same path as the other hosts. What a Claude Code agent can rely
on:

- A `claim_recorded/1.1.0` draft may leave out an empty `limitation_refs` and
  `supersedes_claim_refs`, and a plan beside `no_obligations_reason` an empty `obligation_refs`.
  Each is the empty list: one request, digest and stored payload with the explicit `[]`, and not
  named in `server_filled`. It is judged like an explicit `[]`, so a completion claim that leaves a
  required live failure or partial result out is still refused (`limitation_refs_complete`). An
  unknown result can be disclosed in `limitation_refs` and is not required for admission, but
  omitting a relevant one may produce a later `material_limitation_omitted` local finding.
  `supporting_refs`, a revision's `obligation_changes` and evidence `observed_at` stay required.
- A `respond` answer may list its `evidence_refs` in any order: the request model sorts it before
  the schema check, so it is the same request as the sorted list. The service also drops a
  repeat, but the advertised schema keeps `uniqueItems`, so send each id once.
- A refused `respond` payload is `INVALID_REQUEST` with `safe_details.reason_code`, a `field`
  pointer from a frozen table and a continuation (`input_correction_new_identity` unless the reason
  maps its own), and its message states the rule. On Claude Code, an `isError` result delivers only
  the bounded text, which never renders the message: it names `Reason: <reason_code> at <field>` and
  the continuation directive, and for `response_fields_invalid` a `Remedy:` clause. That clause is
  chosen by the reason alone and rides on every `respond` refusal with that reason, including
  respond's own checks (an unrecorded `evidence_refs` id, nothing to reopen, an AI-powered finding
  acknowledged without a reason), so it lists every rule behind the reason and the `at <field>`
  pointer says which one broke. The set reasons (`unsorted_set_field`, `duplicate_set_member`,
  `set_member_not_ascii`) are shared with other operations and carry no remedy; canonicalization and
  the id pattern leave them unreachable for a request the schema admits.
- The `respond` and `receipt` catch-alls keep their messages and add `reason_code`.
- The `respond` refusal details and the catch-all `reason_code` come from the service, so they
  appear once it restarts (`finishup service restart`). This change leaves the schema manifest
  unchanged, so an upgrade does not supersede a still-running older 0.3 service on its own.
- A `read_guidance` anchor unknown on its page (or any anchor on a focused page) that is exactly
  the catalogued anchor of one other guidance document reads that topic, and the result's `uri`
  names it: `agent-instructions.md#publish-shapes` reads `request-templates.md#publish-shapes`. An
  anchor two documents share, an alias and a word subset never cross documents.

Verification: `tests/unit/protocol/test_publish_payload_empty_sets.py`,
`tests/unit/protocol/test_respond_reference_sets.py`,
`tests/integration/application/test_publish_server_filled.py`,
`tests/integration/application/test_respond_status_receipt.py` (the payload refusal rendered for
the Codex, Claude Code and Cursor profiles), `tests/unit/mcp/test_guidance_topics.py` and
`tests/unit/mcp/test_tb4n4_call_traps.py`; the n7 exports were not replayed, and a live Claude Code
transcript on macOS, Linux and WSL 2 is not recorded for this change.

### Receipt privacy ceiling (N5)

Shared service projection, no host-specific path. Every receipt an agent can request (the MCP
`receipt` tool, or `finishup receipt` run by the agent, under a pseudo-terminal or not) is the agent
projection: normal prose, titles, codes and counts stay; undeclared repository names the policy
withholds become `(receipt prose withheld: repository_excerpt)`, including `./` and full-path
spellings (from `/`, `~`, `$VAR` or `file://`; quoted when a directory has spaces) of any name, a
top-level name without an extension included, and an exact name the requesting writer published itself returns. Large receipts stay
valid: omission lists coalesce and an over-long field is cut visibly. The owner's full receipt is
`finishup receipt --owner-view` (or *Your full receipt* in the terminal interface), which needs the
`owner_receipt_view` reauthentication. Verified by in-process tests on macOS, including a real
pseudo-terminal; Linux and Windows through WSL 2 run the same service code but were not exercised
for this change.

Owner-view presence decision for Claude Code (#1073): same path as every host, because the owner view is
a CLI and terminal-interface flow, never an MCP tool or hook. On macOS the service itself raises a
LocalAuthentication dialog (Touch ID or the login password) showing the confirmation code the
command prints, on either vault mode, including setup's system-keychain choice. A vault passphrase
the owner chose is asked for once when the service cannot show a dialog, or directly with
`--use-passphrase`; a passphrase kept in the system credential store is never prompted for on its
own. On Linux and WSL 2 there is no presence provider: only a vault passphrase the owner types
completes it, and a vault without one, or with one kept in the credential store, fails closed with
`owner_view_unavailable`. Run directly, Claude Code's Bash tool gives the command no terminal, so an
agent-run `--owner-view` ends with `owner_view_requires_terminal` before any dialog opens; the
owner runs it in their own terminal. The agent can still wrap the command in a pseudo-terminal
(for example with `script`), and then the dialog appears on the owner's screen as it does under
Codex: cancel any dialog whose code you did not just see in your own terminal. If an agent's own ceremony is open, the owner's command reports
`owner_view_busy` with its own code, and any dialog on screen is not the owner's. The dialog itself is covered only by stub-helper tests until
the manual check in [test-instances.md](test-instances.md#owner-view-with-touch-id-manual-check-on-a-real-mac-1073)
runs on a real Mac.
## Per-task review mode and agent opt-in (ADR-049)

**Decision for Claude Code: supported, the same MCP path as every host.** A task starts with local
checks under the owner's recommended setting (`conversation_review = local_agent_opt_in`); the agent
turns on AI-powered review for its own task with one `publish_work` draft, `decision_recorded`
version `1.1.0` with `review_mode: "ai_powered"` (`"local"` turns it back off), and then checks
without `mode`. `check` and `status` carry `review_mode`; the receipt names each switch. Guidance:
`finishup://guidance/review.md` (when to turn it on, when to stay local, the exact draft). Nothing
Claude Code-specific is involved: no hook, skill or registration field changes.

- **Owner setting.** `finishup privacy conversations agent-opt-in|owner-approval|local-only|ai-powered|status`
  for the current repository; first-run setup records it from its three answers. Owner approval
  makes each review the agent turns on wait for `finishup privacy decide-disclosure`, the same
  `awaiting_human` path as **Ask every time**.
- **Route.** Every interactive setup answer now registers the policy route. A registration made by
  an earlier local-only setup is on the strict route: an opted-in task there (or any task under
  "every task") runs local with `route_local_only`, and the check prints the fix,
  `finishup setup run --route-profile policy`; the Claude Code form is
  `finishup setup run --host claude --route-profile policy`. Then start a fresh Claude Code
  session.
  Non-interactive setup keeps the strict default for a fresh registration. The plugin's MCP route
  lives in the marketplace source every project of the configuration root shares (#1058), so
  re-rendering it on the policy route changes it for the other connected projects too; the
  preview names them (`route_changes_for`).
- **Not set up.** Where no reviewer or repository policy exists, an opted-in task runs local with
  `ai_review_not_set_up` and the one-time owner commands (`finishup --set`, or
  `finishup provider codex-subscription setup`, then `finishup --privacy`).
- **Host auto-review.** A local-only owner on the policy route sends nothing, but `check` is still
  advertised as open-world; an automatic reviewer that holds every `check` (see the host admission
  section) holds these too until the owner grants admission or re-registers on the strict route.
- **Upgrade.** A policy approved before the setting existed keeps its behaviour, and its checks and
  receipts are unchanged, until the owner chooses a setting or an agent switches a task.
- **Every task.** Under `ai_powered`, or a policy approved before the setting existed with its
  inference channel on, a `review_mode: "local"` switch is recorded but changes nothing: checks
  that omit `mode` still run AI-powered review, and a check that names `deterministic_only` keeps a
  required review as a bounding gap (review round 1).
- **Closing review.** A task that already used AI-powered review and now runs local (it switched
  back, or one check named an AI-powered `mode`) still owes its closing review; the Stop gate's
  `check` with `final_review: true` and no `mode` runs it (recorded `source: check_request`).
  Where the owner has since chosen local only, that check records `owner_local_only` and the
  closing review is no longer owed.
- **Enforced at dispatch.** The privacy gateway refuses AI-powered review (and background advice)
  under an explicit `local_only`, including a check already in flight when the owner narrows; a
  failed read of the setting runs a check that omits `mode` local, with any required review left
  as a bounding gap. Background advice is admitted only under `ai_powered`.
- **Receipt and status.** Each switch names the actor the ledger recorded, its actor type and
  assurance, and the declared authority; a task whose check recorded a mode says how it ran even
  without a switch. A policy that predates the setting and reads as local only says AI-powered
  review is not set up, not that agents may not opt in. Review turned off in the verification
  settings has its own reason, `review_disabled`.
- **First-run privacy.** The first and third setup answers list the privacy options with Assisted
  review as the default (marked recommended only for a provider with reviewed data-use terms);
  Private stays selectable and says that tasks stay local under it. The terminal interface's
  `/connect` for Claude Code now runs the chosen answer's setup after connecting, as first run
  does (it asked the question and dropped the answer before).
- **Other repositories (review round 2).** A fresh install's first repository grant gives the
  installation row the hybrid (or the narrower answer), so another project or an independent clone
  starts local; a repository without its own privacy grant reports "AI-powered review is not set
  up for this repository" (`ai_review_available` false) and an opt-in there records
  `ai_review_not_set_up` until the owner approves that repository's grant (terminal or chat; a chat
  grant starts on the same first-grant default). Installations whose row already sent work keep
  the released repository-grant handoff.
- **Agent-driven setup.** Preview with `finishup setup run --host claude --route-profile policy
  --non-interactive --json` for every answer; without `--route-profile policy` a fresh
  non-interactive registration is strict and every task stays local (`route_local_only`).
- **Round 3.** In a repository without its own grant, `finishup privacy conversations
  agent-opt-in` (or `owner-approval`) walks that repository's privacy grant with the setting
  included (a local terminal is required; otherwise `local_terminal_required` and the command
  names `finishup --privacy`). With a reviewer bound, `finishup --privacy` lists the AI-powered
  review options (Assisted review by default) on a first grant and under agent opt-in or owner
  approval. Switching back to local after the closing review costs one more closing review
  (`review.md` says so). The MCP receipt summary's review-mode pointer is JSON-receipt only.
  Same path on Claude Code; no host-specific change.
- **Round 3 verification.** A first Private grant in a repository reads as local only (an explicit
  `local_only` where it inherits an earlier repository's hybrid). `finishup --privacy`'s
  AI-powered review listing words Assisted review for the route: on a route without reviewed
  data-use terms it is the default, not recommended, and its draft records no evidence
  requirement. Where the released carry-forward is pending, status says the installation's earlier
  permission is carried forward when a task first starts in the repository.
  Same on Claude Code.

## Setup refresh and suggested reviewer model (FinishUP 0.3, #1067)

Decision for Claude Code: supported. The shared setup path changed, and every item below
applies on macOS, Linux and Windows through WSL 2.

- **Plan summary.** The connection preview describes each change in a plain sentence ("Install the
  FinishUP plugin, Enable the FinishUP plugin") as Codex plans already did. The plan body's change
  tokens and its digest are unchanged, so an accepted preview still binds the same bytes.
- **Agent list.** The guided list shows each installation's executable path and says one agent is
  connected per run. The default is the Codex a plain `codex` command runs when one is
  installed, otherwise the first entry.
- **Suggested reviewer model.** Codex-subscription AI-powered review suggests `gpt-6.1-sol` at
  `medium` (final and routine) for a new binding, falling back to `gpt-6-luna` with a printed
  reason when the Codex FinishUP runs does not list it (ADR-006 amendment of 2026-10-14). The
  evaluator is a separate Codex runtime, never the connected agent, so this is the same path on
  every host. An explicit `--model` and an existing binding are never substituted.
- **Project folder first.** `finishup setup run` checks the project folder before the review and
  privacy questions; on a machine where only Codex is installed (or with `--codex-path`) it does so
  before the Codex wizard's first question. Run from the home folder, the filesystem root or a
  symlinked path, a terminal user may type a project folder, and registration, the privacy step
  (local-only, or the provider's disclosure policy) and an API key's repository binding then use
  that folder; otherwise setup stops with `workspace_locator_invalid` and a next step (it used to
  fail as `internal_error` after every answer).
  An intentional home-folder workspace (such as a container with `WORKDIR /root`) uses
  `--project "$HOME" --allow-home-project`, also with `--non-interactive`; default setup still
  refuses home, and `/`, symlinks, and unsafe ownership/writability remain refused. The same
  choice reaches native hooks and MCP through the reviewed exact-home launcher argument.
  JSON previews and results report `status.home_project_allowed` (inside each batch member).
  After that opt-in, ordinary HOME project files support reviewer reads, check-time changes
  and requested-output verification through the same service path as other projects (#1161).
  Reviewer paths are relative to the issued root alias; absolute paths and hidden components
  remain refused. Every dot-named file or directory at any depth (`.codex/`, `.claude/`,
  `.cursor/`, `.ssh/`, `.config/`, `.cargo/`, `.vault-token`, a nested `backup/.ssh/` and
  also project dot files such as `.github/` or `.cursorignore`), the top-level `Library`,
  `AppData` and `snap` trees, copies named exactly `Library` or `AppData` at any depth (such as
  `backup/Library/`), and credential/auth file names such as `credentials.toml`, `auth.json`,
  `token.json` or `kubeconfig` at any depth stay excluded, including tracked files. Excluded outputs remain
  unverified. Structural capture reports a symlink outside those exclusions as
  `symlink_unsupported`, as in any project, and never follows it. This adds no observation
  grant or disclosure authority. The service admits HOME for any authenticated same-user
  connection naming it, because the launcher's opt-in is not carried across the handshake;
  binding it to a recorded opt-in is tracked in #1181. See [ADR-012](../adr/ADR-012-first-run-setup-wizard.md#home-review-and-observation-parity-1161).
  `setup disconnect --host claude --project "$HOME" --non-interactive --json` previews
  removal without a new home opt-in; approve that exact preview. Observation and disclosure
  remain separate. Adapter tests cover the locator/renderer decisions; no additional native
  host or OS certification is claimed (issue #1154).
- **After a Codex-subscription sign-in.** The guided provider step reports the Codex-held credential
  (`external_runtime_oauth`) as ready instead of `Credential: unknown` with exit 20, shows the bound
  model and any fallback, asks no API-key verification question, and prints its own layer report
  (the sign-in stays in the dedicated evaluator home; no live review is demonstrated) instead of the
  API-key vault report. A declined or failed privacy step is incomplete on every provider path
  (`finishup --set`, the guided connection and the Codex-only wizard): exit 20, its reason, and a
  `finishup --privacy` next step, plus the credential step when an API key was never stored, with no
  setup marker written. A completed step ends with "start a fresh agent session" instead of the
  former Codex-only "Preview Codex MCP registration again".
- **Ambiguous or missing installation.** Connect and disconnect name the installations to pass
  with `--host-path` (or say none was found) instead of the misleading "trusted local terminal"
  step.

Verification: `tests/unit/cli/test_setup_wizard_smoothness.py`,
`tests/unit/cli/test_host_connection.py` and `tests/unit/cli/test_codex_subscription.py`. The vault
and provider steps of `finishup setup run` were not walked end to end for this change (the
sandbox walk had no macOS keychain), and no native Claude Code session was recorded for it.

## Pristine skill upgrades across releases

Claude Code delivers its skill inside its managed plugin marketplace, independently of the Codex
project-skill installer. Its source inspection validates the complete installed inventory against
the source's own marker, then classifies intact earlier sources as `native_managed`. Connect can
replace those bytes with the current renderer even when guidance changed. Actual edits invalidate
the marker and preserve the source as a destination conflict. The Codex `owned_skill_update`
warning is specific to Codex; Claude Code keeps its existing managed-source update behavior.
This is adapter coverage, not a new claim about a native host/OS lifecycle cell.

## Observed verification-output follow-ups

Verification-output follow-ups retain complete post-tool verifier input locally beside its
output, under the existing scoped content-capture consent and byte limits. The shared resolver
uses the authenticated same-phase input only for eligibility; it never sends that input as an
excerpt. Older captures without this context remain withheld. Private and repository-excerpt
denial withhold the auto-supplied output. This shared path applies on macOS, Linux and WSL 2;
native Windows is not claimed.

### Closing currency and observation replay (PR #1080)

Closing-review currency follows what a command did to the workspace, never its text (owner decision,
PR #1080 round 5; ADR-033). Under the ordinary observation profile, the Claude Code `PreToolUse` and
`PostToolUse` hooks fingerprint the workspace around every `Bash` call and every other tool except
FinishUP's own, the native `Read`/`Grep`/`Glob` reads, edit tools and planning or web tools (so
`BashOutput`, `Task` and third-party MCP tools are covered), and the post envelope carries
`workspace_effect`. A `run_in_background` launch has no completion fact, so its effect is
unavailable (`background_launch`) and it stays material. Host decision (n7 RC1, #1105): no change to
the completion rule; Claude Code's `PostToolUse` already is the call's closed success fact and
completion, unlike Codex's (which fires for a non-zero exit too and states no exit). The structural
profile observes only FinishUP's own tools, so it records no shell calls at all. An unchanged
command (`date -u`, `rg`, `sed -n`, `git status`, a FinishUP CLI read) does not re-arm the closing
review; a command that changed the workspace does, and so does one whose effect FinishUP could not
establish, which the Stop text says. A command that backgrounds or detaches a process (`cmd &`,
`nohup`, `setsid`, `disown`, an `&` handed to `bash -c`, `eval` or `ssh`) is never established,
because it may write after the call ends; a quoted `&` in an argument of a program FinishUP knows
does not run its arguments or stdin as code in the form given (`curl 'h?a=1&b=2'`, `sed 's/x/&/'`,
`rg 'a&b'` without `--pre`) is not a background launch, while `sudo`/`doas`, `wget`, shells,
interpreters, other code-running programs, a wrapper or assignment in front of the program
(`env -S`, `LD_PRELOAD=`, `PATH=`), ANSI-C quoting (`$'...'`) and any `#` or `<<` in the text (a
quote in a comment or here-document body is one bash ignores) keep the cautious reading (#1089).
Round 6: neither is a call whose exit leaves a process it started still running in the project (a
launcher whose new-session child keeps working, with no background word in its text): before
comparing, the post-call hook reads the process table (`libproc` on macOS, `/proc` on Linux and WSL
2) for a process of the same user that started during the call, is no longer parented by the host,
and has its working directory or a file open for writing in the project; one found, or a process
table that cannot be read, makes the call unverified. A directory that gains or loses an entry while
it is being compared does too. A pre-call snapshot that could not finish before the host stops
waiting is never stored, and the 0.75 s bound covers the whole pass, hashing included. Verification
runs (test, build, lint and typecheck runners, and the task's requested commands) and package
installs stay material whatever the workspace shows. The workspace is everything under the project
root, ignored files included; inside VCS metadata only the internal churn (objects, refs, reflogs,
the index and lock files) is skipped, so `git status`, a commit or a branch stays unchanged while a
`.git/config` or hook edit counts; `node_modules`, `.venv`/`venv`, `.tox`/`.nox` and tool caches are
compared at their first level (files by content, subdirectories by identity); `__pycache__` bytecode
is skipped but any other file there counts; FinishUP's saved receipts and state are skipped. A task
that declares a delivery inside the project where the comparison does not reach it (a VCS store such
as `.git/objects` or a skipped bookkeeping file such as `.git/HEAD`, below the first level of a
dependency environment or tool cache, `__pycache__` bytecode, a saved receipt) gets no unchanged
command; a declared `.git/config`, `.git/hooks/*` or `node_modules/x.js` is compared and does not.
Effects outside the root (databases, `/tmp`, the network, a deliverable path outside the root,
judged against the task's absolute `workspace_ref`) are out of scope, as before.
`finishup observe status` names a degraded comparison once as a `workspace_fingerprint_<reason>`
diagnostic (`too_large`, `timeout`, `unreadable`, `root_unusable`, `store_unusable`,
`process_table_unreadable`), and names `workspace_fingerprint_consent_unreadable` when the pass could not re-read consent and so recorded nothing; a call without its pre-call snapshot or still running is recorded on
its result as `(workspace unverified)` instead, and `finishup observe status` counts every reading
by its closed reason (`workspace_effect:` line; JSON `workspace_effect_readings` with the last 64
readings and their call ids: `call_incomplete`, `background_launch`, `process_lingering`,
`workspace_unsettled`, ...; n7 RC1). A closing review that ended without a judgment is not asked for
again (`semantic_review_no_judgment`; the check's own continuation, at most one new check, or a
disclosed finish). A repeated delivery of the same call that states another fact is kept as an
annotation under the call, and `changed` or `unavailable` outweighs `unchanged` (round 6). Real
edits and review-mode switches still re-arm; receipt, work-close and lifecycle records do not. The
behavior is the same on macOS, Linux and WSL 2; native Windows is not claimed.

Call-keyed hook/stream overlap requires an agreeing committed action core and checks reused
evidence against its original causal action/result association. An evidence-only collision cannot
create a different call or lend evidence to its pre-action. Missing captured evidence is appended;
conflicts still reject. Generic `finalize` and `*_regression` names grant no verification credit;
task-specific verifiers can use explicitly requested command matching under ADR-045. Capture consent,
authenticated command/output binding, privacy policy and provider limits remain required for verification-output auto-supply.

### Server-filled publish boilerplate and brief status (#1084)

Host decision: supported, no host-specific code. The change lives in the shared protocol request
models, the publish application, the MCP bridge, `finishup publish-work` and the startup gate hook,
so Claude Code takes the same path as every other host. What a Claude Code agent can rely on:

- `publish_work` may omit `request_id`, `expected_frontier`, and each draft's `event_id`,
  `occurred_at`, `causal_parents`, `artifact_refs` and `evidence_refs`. The service still
  requires `request_id`: the FinishUP MCP bridge (or `finishup publish-work`) mints a fresh one
  per call and names it in every result and error (the CLI prints it on stderr before sending);
  nothing is persisted. The service mints event ids from the task, writer, request id, position and preview
  role, records its own clock, copies the payload mirrors, and guards an omitted frontier with the
  one it reads on admission. The result's `server_filled` names every filled envelope value and
  the frontier (an omitted empty claim or plan list is the empty list and is not listed), and
  `status view=operation` shows the committed operation's record. Reference-set fields are sorted
  and de-duplicated; text lists are kept as sent. A request that sends every value behaves exactly
  as before.
- After an unknown outcome, retry by sending the `request_id` the error names; the service
  replays. An id-less resend is never a retry. Right after the same writer's id-less call, the
  bridge refuses an identical id-less body (`publish_repeat_unconfirmed`, continuation
  `publish_identity_choice`) and names the earlier id as `replay_request_id`: a call the agent
  saw succeed is recorded, so it changes the body or sends a fresh `request_id`; an unseen result
  is retried with that id. Otherwise it is a new publication, so a review-mode switch back is
  simply published again, and a `finishup-blocker` confirmation names its re-check in the
  rationale, so it differs from the claim. The guard lives in the bridge's memory, so there is none after a bridge
  restart, after the writer's next publish, after an hour, or for the CLI. An agent that must
  retry across those sends its own `request_id`.
- A cooperative write that lands while an id-less, frontier-less batch is in flight returns
  `FRONTIER_CONFLICT`; hook observations do not. Send `expected_frontier` when the batch rests on
  something read earlier and another writer shares the task.
- No `date -u` call is needed to timestamp a draft. A time FinishUP filled is marked
  `occurred_at_source: service_clock` in `status view=history` and in check review inputs.
- An MCP `status` read returns `detail: brief` unless the agent sends `detail: "full"`;
  `limit` defaults to 20, and `view: results` accepts `filter` `after_sequence`, `actor_id`
  or `author: "mine"`. The brief text still names `Closure: <state>`, the agent-actionable tokens
  and, at `ready_with_limitations`, the stop-and-request-the-receipt instruction.
- The text summary carries the filled field names and up to eight minted event ids
  (`minted event ids: [index] evt_…`), and an id-less error names the minted request id, so an
  agent that reads only text can still cite a minted event id or retry by id.
- The startup gate hook never sees a minted request id before the call, so in required startup
  mode an id-less `publish_work` is admitted with no pre-call ticket. Its ticket opens only at a
  post-call event that carries the structured result naming the minted `request_id`, and minted
  event ids are matched by position in `accepted_events`; a sparse first plan still releases the
  gate. Claude Code delivers MCP error results to hooks as text only (or as `PostToolUseFailure`
  with no `tool_response`), so an id-less publish that errors or loses its reply holds no ticket and
  substantive tools are not held for it; a concurrent delegate's tool can pass while one is in
  flight (each tool is still live-probed against the current accepted plan). The agent retries by
  the minted id the error names, which takes a ticket again. Owners who need fail-closed tracking
  have agents send their own `request_id` ([required startup](required-startup.md)).
- Host tool-call ids are not used: none of the three hosts' MCP call identity is verified in this
  repository, so the bridge mints its own. The hook never sees that id, so a rejected id-less
  `publish_work` is matched to its pending hook attempt by a commitment to the agent's own
  arguments (tool, FinishUP session and writer, and the canonical body both the pre-event and the
  bridge see; ADR-029): the attempt closes as `rejected_by_yoetz`, not `pending_attempt_expired`,
  and two identical rejected bodies close one attempt each. It still expires when the arguments
  have no canonical form (a fractional number, for example) or the pre-event body outgrew the
  1 MiB hook parse and was reduced to its identity view.

Verification: `tests/integration/application/test_publish_server_filled.py`,
`tests/unit/mcp/test_server_filled_bridge.py`, `tests/unit/mcp/test_publish_identity_guard.py`,
`tests/unit/cli/test_startup_gate.py`, `tests/unit/protocol/test_publish_server_filled_fixture.py`,
`tests/conformance/operations/test_status_contract.py` (brief and results-filter cases) and the
MCP unit suites exercise the shared path. A live Claude Code session on macOS, Linux or WSL 2 is not
recorded for this change; native Windows is not claimed.

### Verification recognition (n7 RC2, #1106)

Host decisions for Claude Code:

- **Actual workspace changes (DET-2).** The shared hook fingerprint makes a source change by a
  script or opaque tool stale earlier verification, even without a lexical write token.
  Optional `workspace_write_scopes` contains only closed classes for actual additions, changes
  and deletions; no paths or content. Exempt documentation and conventional notes, scratch, logs,
  caches and build output preserve freshness under ADR-042, with declared outputs taking
  precedence. Unavailable effects and changed effects without usable classes
  conservatively stale verification. Task facts and completion evidence share the same observed
  facts; Stop, status and all receipt formats name the existing stale-verification gaps. Rerun
  the affected tests or requested verification after the change, then check again.
- **Patch-then-test commands.** Shared classifier: a `Bash` command that applies a heredoc patch
  (`git apply <<EOF`, `patch -p1 <<EOF`) and then runs a test is a verification run even when
  the patch body holds an odd quote, and the patch is a write of the files its diff headers name.
  Supported.
- **Stream-first calls and hook outcome corrections.** Not applicable: Claude Code has no second
  (session-stream) copy of a call, so its hook copy is the only record and keeps its own identity
  and outcome.
- **Documentation edits.** `Write`, `Edit`, `MultiEdit` and `Bash` writes of only project
  documentation (README, changelog, `docs/*.md`; a notebook is never documentation) are named
  `docs`: real work, never stale-making for an earlier verification unless a declared output is
  documentation or a directory. Nothing in a data directory (`tests`, `fixtures`, `golden`,
  `resources`, `prompts`, …) is documentation, and those directories are read inside the workspace
  only, so a host-managed worktree (`<repo>/.claude/worktrees/<name>`) is not data. A `Bash`
  write's relative target is placed under the hook payload's `cwd` and one leading `cd <dir> &&`
  (also inside a whole `bash -lc '…'` script); a heredoc body is data, so a README whose text says
  `cd repo` stays documentation. A target that cannot be placed (any other `cd`, `env -C`, a nested
  `sh -c` that changes directory), a fixture written after `cd tests`, and a heredoc patch with
  any file it cannot read (`patch -d`, `git apply --directory`, a pure rename, copy or mode change
  next to a README update, a binary file) are ordinary edits; `git apply --stat --apply` applies,
  so it is a write (#1106 r2, r3, r4). `Write`, `Edit` and `MultiEdit` name absolute paths and
  need no working directory. Unverified: Claude Code's shell keeps a `cd` from an earlier call,
  but no captured payload shows `cwd` following it (the recorded fixtures all state the project
  root). If it does not, a relative README written by a later call while the shell sits in
  `tests/` reads as `docs` (gap kept; follow-up is the #1106 owner's). The exemption is lexical:
  a doctest, docs build or Markdown lint that reads the file is not made stale by a later edit of
  it unless the file is declared. A `docs` row's check inspection shows no `write_scope`
  (check-result 1.5.0 keeps its list; follow-up is the #1106 owner's). Supported.
- **Background verification.** Gap kept: A `Bash` call with `run_in_background` that the agent polls
  through `BashOutput` is recorded when it launches; its completion is not a verification (output
  text is never read). Run verification in the foreground, in one tool call (the shipped guidance
  says so).
- **Upgrade.** The control-request 2.9.0 `write_scope` enum gained `docs` in place; a new hook
  and an older running service fail the handshake as `manifest_mismatch` before any frame, and
  hook rows wait until the next MCP bridge start or `finishup service restart` supersedes the old
  service. The hooks and the service also share one local observation store, which a service
  that predates `docs` cannot read once it holds a `docs` row, so a hook records `docs` only while
  the running service is stamped with this installation's schema manifest. Otherwise (no service
  running, or an older one) the write is recorded as an ordinary edit, as before #1106: a
  documentation edit then can still give one Stop prompt (#1106 r2).

## Review result lead and supply that counts (W6, #1107)

**Host decision: supported, same field.** Claude Code delivers `structuredContent` for successful
tools, so every check result's `agent_next` (ADR-043 amendment) reaches the model beside the
unchanged 4,096-byte text summary, whose missing-item sentences now name the linking field; what
counts as supplied rides in `agent_next`. Claude Code's MCP output limit is far above these sizes; the field order
(`agent_next`, `overall_next`, `missing_for_assessment` before findings) costs nothing here.
`isError` results are unchanged. `status view=operation` for a finished check returns
`check_outcome`, and its text summary adds `check outcome: <verdict>; next: <action>;` and the lead
when room remains. Same gap as Codex: after an attach or a service restart the page keeps only a
`supply_missing_input` lead rebuilt from the stored missing items and omits any other continuation
(storage follow-up owned by #1100). The captured output of a Bash re-run of the target's exact command the PostToolUse
hook observed after the request counts as supplying a targeted `verification_output` (or `other`)
item once the reviewer was sent it (ADR-006 amendment). That path exists only on the ordinary-work observation
profile: the default structural profile observes no generic `Bash` calls, so there the agent
publishes `result_recorded` of the target's action with the output in `summary`, which `agent_next`
says on every host (capability gap owned by #910). An observed run never answers
`command_identity`; a respond counts only for a finding target, and a description never counts. Verified by `tests/unit/cli/test_status_operation_render.py` and the host-neutral tests named in
the Codex runbook.

**Reviewer reads on Claude Code (#1118). Host decision: supported.** The reviewer conversation runs in the service for every host: up to three reads, each sent in its own privacy-checked exchange, within the channel limits. What it read reaches this host as `reviewer` on the check result (closed tokens, folder aliases, opaque source ids, line spans, sizes and the privacy receipt of the exchange that first carried each read; never a path or content), as the read lines at the head of the MCP text channel's reviewer section, in the CLI and TUI check text, and in every receipt format; a same-id check replay returns it too. Hooks carry no reads, and status's operation `check_outcome` stays structural without it. Claude Code's output limit carries the reviewer section, read lines included, whole.

**Reviewer read recovery on Claude Code (#1173). Host decision: supported, service-side.** As on every host, the reviewer gets three reads that return content within at most five attempts (ADR-006, #1173): a refused or empty read costs an attempt and its bytes, not a content read, and comes back with a correction for its cause (an unknown folder alias, an absolute path, a hidden or traversing name, an ignored file, a path outside what the task declared, or a record the frozen review case does not hold) that never repeats the refused path. A read the reviewer still asks for after its reads end executes nothing; if the review's one repair is unused it is asked once for its judgment, otherwise, or when the review offered no reads because every exchange needs the owner's approval, the review ends `read_limit`. `reviewer.reads` lists every attempt and `reads_used` counts content reads; the MCP text, CLI, TUI and receipt read line adds `N of 5 read attempts` when the two differ. The controller runs in the service, so nothing differs by host.

**Residual requests on Claude Code (#1118 unit 4). Host decision: supported.** As on every host, the reviewer's own reason for each residual request reaches the agent inside the fenced `review_summary` ("What the reviewer still needs"), never in `agent_next` or the structural item; a `full_local` receipt carries the same summary as one fenced advisory item, an exported receipt says it was withheld, and the privacy projection decides the agent's view of either; a linked supply no longer erases a reviewer's repeat (`semantic_missing_already_supplied` discloses it); and a `semantic_required` check stops at the same round limits, reading `incomplete_check`. The reviewer's own reads (up to three, bounded and privacy-checked) run in the service, not in the host, so they behave the same here; the provider route that serves them is a separate role (ADR-006). Recovery's `check_outcome` stays structural and omits the reason. Claude Code's output limit carries the reviewer section whole.


## Total reviewer packet budget (AIP-3/AIP-4, issue #1108)

Decision for claude-code: supported by the shared service composer for MCP, CLI and hook-triggered
reviews; no host adapter change. On supported macOS, Linux and WSL 2 paths, over-limit packets omit
agent plan/claim/obligation prose and ordinary history before reducing specification, current diff
and decisive verification excerpts. The current diff floor is tied to the final packet limit;
impossible protected packets retain the existing refusal. Synthetic task-input and change
omissions name valid linked subjects. Packet omissions, coverage and omission totals flow through
the existing CLI/MCP/TUI summaries and JSON, markdown and text receipts. Small packets are unchanged.
These are shared-composer tests on macOS/Linux, not new native host or WSL session certification.
No installation, upgrade, disconnect or reverse-state behavior changes.

## Batch setup decision (2026-10-19, issue #1119)

Claude Code participates in `setup run|disconnect|status --host all` and repeated `--host`
selections through its existing plugin connection plan on macOS, Linux and WSL 2. The combined
approval binds the executable, configuration, project, route and per-host preview; macOS or PAM
authentication still runs for Claude Code on the foreground terminal, after the agent is named.
Shared-project review-mode warnings and conservative shared-piece removal remain in the preview.
Failures stop later members and preserve individual outcomes. Native-host/platform evidence
limits elsewhere in this runbook still apply.


## Provider key removal decision (2026-10-19, issue #1119)

Same path on every host: the owner runs `finishup ai key` to replace a key, or
`finishup ai forget-key` (`finishup provider credential remove`) to remove it after default-No
confirmation and trusted-terminal reauthentication. `/provider` hands over the terminal for that
same removal flow. Agents direct the owner to it and never run it; no MCP or chat-consent removal
path is added. The configured API fallback is targeted when Codex is primary. Binding and privacy
policy stay unchanged, and status is presence-only after readiness reload. Shared-path tests do not
claim a new native-host or platform certification.


### Reviewer judgment calibration (#1145, #1146)

This host uses the shared reviewer instruction and finding pipeline. `decision_needed` is an
advisory priority-3 choice: keep both interpretations and the destructive cost visible, then
record the choice and reason with `respond acknowledged` or `respond rejected`. It never counts
as unmet work or blocks Stop/closure. Closing review challenges the decisive acceptance measurement
and uses the existing task-declared inputs beneath owner-admitted roots; this change admits no
new root. Details and offline checks: [reviewer instruction evaluation](reviewer-instruction-evaluation.md).

### Review context and delivery (#1139, #1126, #1148)

Read the full finding before choosing a response.
Treat `review_delivery` as a bounded advisory preview.
When it reports truncation, follow its `status view=findings` continuation with `detail=full`,
`limit=1` and the returned cursor.
Stop when the finding you will answer includes its action, alternative interpretation and
uncertainty, or labels them withheld.
For example, a long check can keep an instruction while its alternative falls outside the preview.

Treat `not_in_frozen_case` as unavailable in this frozen check.
Do not infer that the item was never recorded.
Follow the missing-input continuation so a later check can freeze the requested item.
For example, an unknown ref can be outside this case.

The shared packet builder retains bounded prior dialogue ahead of ordinary bulk.
The task, diff floor and latest verification remain protected when whole prior dialogues yield.
The MCP text advisory keeps bounded summary, action, alternative and uncertainty ahead of evidence.
The complete structured record remains available.
Offline contract tests cover this path. Native Claude delivery has not been re-dogfooded here.
Issue #1139 owns that validation gap.

**Closure honesty (#1140, #1143, #1144, #1149). Host decision: supported through shared service
results.** Check carries the same readiness verdict that status and Stop consume, with finding
work, missing assessment input and standing limits distinguished. A stopped requested review is
`unavailable / round_limit_unassessable`, with no new attempt, and required review remains
incomplete. Receipt JSON/markdown/text distinguish an agent-disproved concern from an asserted
repair. Trusted byte-identical in-workspace shell rewrites preserve verification freshness;
changed reports remain conservative pending #1143's dependency/role manifest. These decisions
are shared across macOS, Linux and Windows through WSL 2; no native Windows support is implied.
