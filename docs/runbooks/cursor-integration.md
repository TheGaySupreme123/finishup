# Cursor local integration runbook

MCP input advertisements use the shared compact authoring schema, targeting 4,800 bytes per tool.
Required fields, enums and event envelopes remain inline; read `read_guidance` at
`finishup://guidance/request-templates.md` for payload variants, conditional rules and complete
examples before authoring a payload. Full server validation and repair hints remain unchanged.
Cursor's `outputSchema` and `structuredContent` validation contract, including tuple compatibility,
is unchanged by the input-size reduction. This does not certify an untested Cursor/OS cell.
Descriptions remain when they fit, with priority field rules restored first for larger tools.
If the description-free form exceeds the CI budget, the bridge emits
`mcp_advertised_input_schema_over_budget` and still serves that minimal form; CI rejects the drift.

Codex's external MCP removal reconciliation (issue #860) does not apply to Cursor IDE or CLI:
Cursor project MCP cleanup uses its own digest-bound file mutation, not `codex mcp remove`.
The Cursor lifecycle and outcome contracts remain unchanged.

For setup prerequisites, use `finishup setup status --next --host cursor-cli` with the same
executable, configuration root and project. `--operation connection` inspects installation without
provider sign-in; `local` and `review` inspect their respective vault/privacy prerequisites.
Storage-only continuation is `finishup setup vault` in a trusted terminal. This shared #737 path adds
no new native-session capability; Linux/WSL first-use and storage acceptance remain bounded by
[the platform runbook](linux-and-wsl.md#setup-and-vault-acceptance-still-owned-by-737).

## Guided desktop connection (issue #767)

Use `finishup setup run --host cursor-ide` or `--host cursor-cli`. These are distinct installations:
IDE uses MCP roots, while Agent CLI receives the explicit `registered-project` binding. Setup
composes the native user plugin and an external MCP entry for the selected project in one exact
review. The user-wide plugin scope is disclosed; regular Cursor and testing profiles are never
silently interchanged. `--host-path`, `--host-config-root`, and `--project` override discovery.
Agents first request `--non-interactive --json`, present the plan, and repeat its exact request ID
and digest with `--accept`. OS-authenticated artifact presence still applies.

`setup status|disconnect --host cursor-ide|cursor-cli` uses the same target options. Disconnect
removes the selected project's separately managed MCP entry and, when it is the last connected
project, the owned user plugin; it preserves other projects, unrelated configuration and FinishUP
data. A changed or foreign source is refused. A repeated exact connection is a no-op; a partial
connection is re-previewed from its actual state.

**Several projects in one config root (issue #1058).** The user plugin (hooks, skill) serves every
project under the config root; only the project MCP entry is per project. Cursor does not list
which projects use the plugin, so setup keeps `<config root>/.yoetz-connected-projects.json` (the
record shared with Codex's model, ADR-012): connect records the project, a disconnect while
another live project remains removes only that project's MCP entry (the preview's
`status.shared_with` names the others), and the last project's disconnect removes the plugin and
the record. Status reports `connected_projects` (recorded) and `connected_projects_observed`
(recorded projects whose own project MCP entry is still FinishUP's); a recorded project that is no
longer observed keeps the plugin until `setup disconnect` runs for it, which forgets it. When the
plugin is found without a record (it was set up by an earlier release, including a Yoetz-era
`plugins/local/yoetz`, or the record was lost), other projects may use it that no record names:
the record and every preview carry
`membership_unknown`, an ordinary disconnect keeps the plugin, and among the setup commands only
`setup disconnect --remove-shared` removes it. The low-level `integrate cursor plugin remove`
removes the user plugin for every project by design; its preview (`--action remove`) names who
uses it (`shared_with`, `membership_unknown`, `shared_removed_for_every_project`), which the
artifact digest does not bind, so prefer `setup disconnect` to disconnect one project. `setup status --host cursor-ide|cursor-cli` names unknown membership as soon as the plugin
is found without a record and gives the exact `--remove-shared` preview command. Cursor has no list of
trusted projects to inspect, so there are no Codex-style possible users and no
`membership_unverified` refusal here: unknown membership simply keeps the plugin. Every Cursor
setup apply for one config root holds FinishUP's per-configuration lock across revalidation, the
plugin and MCP changes, and the record update, so a concurrent setup is refused as stale and its
retry joins. The lock is an exclusive `flock` on a 0600 file under FinishUP's own state directory
(`host-config-locks/`), keyed by the config root's resolved path, NFC, case-folded; it touches no
Cursor directory, so the first setup into a config root that does not exist yet (for example a
nested `--host-config-root`, or Cursor Agent CLI's `CURSOR_CONFIG_DIR`) creates it without a
manual `mkdir`. That case is covered by unit
tests for both Cursor IDE and Cursor Agent CLI, not by a native Cursor run (no Cursor binary was
available for the 2026-10-14 re-check). A lock that cannot be taken stops as
`connection_lock_unavailable` before any change, naming the lock folder; it does not serialise
a setup run by another FinishUP installation, where the record's compare-then-rename is the only
guard (it narrows that race; it does not close it).
Untested: a state directory on NFS, SMB/CIFS, WSL DrvFS (`/mnt/c`) or another network or FUSE
filesystem (ADR-012 amendment item 7). The record keeps the name
`.yoetz-connected-projects.json` whatever the MCP server key is called; one that is not an
owner-only regular file with valid content stops `setup run`, `setup status` and `setup
disconnect` as `connection_projects_record_invalid` with a continuation naming the file (make it
owner-only again with `chmod 600` or restore it; removing it makes membership unknown, so the
plugin stays on an ordinary disconnect). Cursor keeps the review mode in each project's own MCP
entry, not in the shared plugin, so connecting a project on another review mode changes no other
project (no `route_changes_for` here). `--remove-shared` previews and the interactive consent say
the disconnect is home-wide and name the projects that stop using FinishUP. The TUI has no
`--remove-shared` and shows a generic continuation for these refusals; use `finishup setup
disconnect|status --host cursor-ide|cursor-cli` from a terminal.
A second path to an already connected directory is
refused as `project_connected_via_other_path`; disconnecting under the current path clears it. A
moved project's `.cursor/mcp.json` entry still names its old path and reads as foreign under the
new one; remove that entry by hand before that disconnect. `setup disconnect --remove-shared` is
the explicit home-wide disconnect: it removes the user plugin and the record even while other
projects use them (their project MCP entries stay). A disconnect whose approval file
(`.cursor/permissions.json` or `.cursor/cli.json`) cannot be read safely, such as a symlink, stops
before any change as `connection_admission_cleanup_failed`.

macOS uses LocalAuthentication; Linux and Windows through WSL 2 use the trusted PAM console path.
Windows-side IDE discovery/configuration is not inferred from a Linux executable or directory.
An IDE available only outside the selected WSL environment needs an explicit capability disposition.
Track each OS and each IDE/CLI cell's exact-candidate installation, status, repeat setup,
disconnect and reconnect in #767. Provider authentication and model sessions are outside that
installation acceptance. The Windows-side IDE with Remote WSL remains unverified; #722, owned
by the FinishUP integration maintainer, tracks that separate cell. CLI proof does not establish IDE proof. Existing evidence below
remains limited to its named cells; configuration success never claims session activation.

## Conditional agent guidance

The skill keeps its activation boundary, core workflow, and safety floor in the entrypoint.
Before `start` read the core, `agent-instructions.md`: it is the operating card and is enough for
ordinary work. Workflow, publication policy, and coverage and receipts are read only when a result,
error or continuation names them, or when unsure; no status read or dry run is required before a
write, and `check` with `mode: inspect` gives the picture in one read (ADR-047). Setup/consent, vault/credential operations, transcript import, and
recommendation decisions route to the corresponding sections of request templates only when
needed. Already-read guidance need not be fetched again while present in context.

When Cursor may clip a large guidance document, use the `read_guidance/1.1.0` page route with a
bounded UTF-8 `page_size`. Cursor's `structuredContent` delivery is not relied on for this host:
validate each marked `content` page with `GuidancePageAssembler`, carry the revision/digest
continuation, and require the complete page set and final digest before treating guidance as
loaded. The URI-only request remains unchanged; native fresh/resumed/compacted Cursor
acceptance for the page route remains a pending dogfood lane.

Use `semantic_if_configured` only when AI-powered review is known to be optional; omit `mode` when
relying on the configured default. Select `semantic_required` for an explicit user requirement,
effective policy, or named acceptance criterion requiring independent AI-powered judgment. Preserve
required review and all host/disclosure approval boundaries. Installed guidance bytes alone prove
neither activation nor AI-powered review dispatch.

Both Cursor renderers select `skills/cursor/finishup/SKILL.md`; the standalone generic portable export
retains its neutral entrypoint. Cursor's entrypoint respects the active Plan/Ask/Agent mode, separates
a Cursor plan from a published FinishUP plan, and names distinct IDE and CLI tool-discovery surfaces.
Full application restart remains conditional on the documented activation mismatch, without
changing privacy authority.

A new Cursor session reads guidance and discovers tool schemas before calling MCP `start` as
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
See [required startup](required-startup.md) for current-plan gating, native MCP approval behavior,
opt-out and exact acceptance limits. Portable Agent Plugins do not carry this gate; regular Cursor
desktop enforcement remains unverified until the native acceptance run completes.

Design basis, checked 2026-09-09: Cursor's [skills guidance](https://cursor.com/docs/skills)
uses descriptions for relevance and loads references progressively. FinishUP therefore keeps the
material-work trigger in metadata and the long procedures in shared references. Cursor's
[customization guidance](https://cursor.com/docs/customize-cursor) distinguishes skills for
specialized workflows from persistent rules; no always-on rule or new plan-approval step is added.
The [CLI mode guidance](https://cursor.com/docs/cli/using) informs the active-mode boundary;
the [MCP guide](https://cursor.com/docs/mcp) informs tool discovery and host approval. These design
choices do not promote an untested IDE/CLI version or establish native behavioral acceptance.

Cursor's own [create-learning-path skill](https://github.com/cursor/plugins/blob/main/teaching/skills/create-learning-path/SKILL.md)
and [compatibility skill](https://github.com/cursor/plugins/blob/main/agent-compatibility/skills/check-agent-compatibility/SKILL.md)
in its official plugin repository use direct triggers, short workflows, relevant guardrails, and
an explicit output contract. The Cursor FinishUP skill follows that structure. It keeps automatic
selection enabled; examples of explicitly invoked orchestration skills do not justify making
ordinary FinishUP activation manual-only.


This runbook covers the current local Cursor IDE and Agent CLI implementation rows from issue #153. Operational
TypeScript/Python SDK support is deferred; the SDK package/bridge fixtures remain metadata-only
experimental scaffolding and do not define current capability cells. Cursor Cloud and Cloud Agents are out
of scope. Keep regular and testing profiles separate; every command below names the exact Cursor
configuration root and project.

## Proof facets are independent

Explicit attach uses the same service contention repair as other hosts (#744): retry-ready
start reasons retain the operation and release its lease for an identical-request replay.
`start_lease_pending` retains a live owner and calls for waiting up to 60 seconds before replay.
Cursor's canonical JSON text preserves the same code, reason, and service message as structured
output. A first start needs no invented session/writer IDs to retry. Hook deadlines and existing
structural-only observation scope are unchanged; shared service tests are not native Cursor proof.

Record these separately: FinishUP source and wheel identity; rendered artifact; installed bytes;
Cursor product/SDK/bridge identity; plugin source; discovery; activation; skill delivery; MCP owner;
MCP binding; raw MCP runtime; model-visible tools; correlated model-controlled use; hook capability;
observation consent; accepted observation evidence; service/provider readiness; privacy receipt;
workflow receipt. A later facet never backfills an earlier one.

## Exact local cells

The current implementation pins are Cursor IDE `3.17.8` build `3.17.8` and Cursor Agent CLI
`2026.07.09-a3815c0`. Record the executable digest, OS, architecture, scope, and activation
source. The retained `@cursor/sdk==1.0.23`, `cursor-sdk==1.0.24`, and bridge `sdk.v1` values are
metadata-only fixture pins for future design work; they are not supported compatibility cells.
Cursor's Python package deliberately has no `1.0.23` release; it aligned with the shared SDK
release line at `1.0.24`. Nearby versions are untested, not implicitly compatible.

Untested is not disabled (issue #656). Hook ingress maps only the IDE cell `3.17.8` to its
reviewed profile; a supplied unknown version — including the Agent CLI build — is admitted as
`untested` and its compatible events ingest under the conservative paired contract, while an
omitted version takes the legacy post-only carrier. Neither branch is promoted to the reviewed
profile, and neither loses ordinary hook observation. This decision was recorded without a new
live Cursor upgrade run; distinguishing the IDE from the Agent CLI capability scope in a
disposable instance remains the acceptance evidence for a promotion.

A pinned test instance (ADR-028, issue #604) adds a second guard beneath the artifact binding:
when the native MCP entry and hook commands name the absolute launcher of a runtime created with
`finishup instance create --bind-runtime`, that launcher resolves its own root even if Cursor drops the
`env` block or a hook runs without it, and a different `FINISHUP_ISOLATED_ROOT` is refused as
`isolation_root_conflict`. The artifact-level `isolation_binding` status is unchanged and still
required; the pin does not replace it, and it does not prove isolated plugin discovery either.
The everyday Cursor profile must keep naming the everyday launcher by absolute path. See
[`test-instances.md`](test-instances.md).

## Linux and WSL

Installation evidence (2026-09-20, issue #767): the installed 0.2.4 wheel passed preview,
connect, status, repeat/no-op, disconnect and reconnect for Cursor Agent CLI
`2026.09.18-9a7762b` on Ubuntu 24.04 x86-64 and Ubuntu 24.04 inside actual WSL 2, and for
Cursor IDE `3.21.16` on Ubuntu 24.04. The common setup discovery verifies the executable and
reported version; the IDE install check verified its managed plugin and project MCP files.
The [acceptance record](https://github.com/TheGaySupreme123/finishup/issues/767#issuecomment-5750168131)
binds the source, wheel digest and per-platform outcomes. Provider login and model runs were
outside this installation acceptance.

The separate native IDE identity inspector (`discover_cursor_ide`) accepts the Linux installed
package root, such as `/usr/share/cursor`, or its native `cursor` executable (including an explicit
symlink to that executable). For an extracted AppImage, select its `usr/share/cursor` directory.
It reads the version from `resources/app/package.json`, the build commit and Cursor application
name from `resources/app/product.json`, and hashes the native ELF executable after requiring an
ELF64 little-endian ET_EXEC or ET_DYN header. Version and commit metadata must be bounded printable
ASCII identity fields. It does not launch
the IDE, extract an AppImage, or change a host registration. Missing installations report
`cursor_ide_unavailable`; an unextracted AppImage or unrecognized layout reports
`cursor_ide_layout_unsupported`; malformed metadata, linked package members, and non-Linux
executables report `cursor_ide_identity_invalid`. Select the native binary/root rather than the
`resources/app/bin/cursor` shell wrapper. This inspector is distinct from common setup discovery,
which probes the installed host's command and version. The macOS bundle inspector is unchanged.
Today this inspector is library-only: no CLI, MCP, TUI, or receipt surface invokes it. A caller
must supply the package root or native executable directly; this read does not add an operator
selection step to common setup or host discovery.
The [vendor installation guide](https://cursor.com/docs/get-started/quickstart) documents Linux
package and AppImage installation.

Native-session capability remains **unproven** for Linux/WSL under #722. An identity read on WSL
applies only to a Linux installation inside that distribution, not the Windows-side IDE. The
reviewed native evidence case stays `cursor-ide-native-3.17.8-macos-arm64`; installation success does not
admit a new session/observation capability case. The Windows-side Cursor IDE with Remote WSL
is unverified and remains owned by the integration maintainer in #722. Cursor Cloud is outside
this scope. Shared host facts are in [`linux-and-wsl.md`](linux-and-wsl.md).

## Preview and install

Use an explicit isolated root; never point a test at regular `~/.cursor`. An isolated Cursor
home isolates only Cursor: an isolated-FinishUP test cell must also export `FINISHUP_ISOLATED_ROOT`
(ADR-026) into the cell's `mcp.json` `env` and hook commands, or the plugin's FinishUP children
resolve the live service singleton and state; prove the mode with
`finishup service isolation --json` from the cell environment. The Cursor plugin
command surface is `preview`, `install`, `status`, and `remove` (`--action replace` previews a
replacement); the generic `update`, `enable`, `disable`, and `export` commands listed by the shared
group are Claude Code lifecycles and refuse for Cursor with
`cursor_plugin_command_unsupported:<command> supported=preview,install,status,remove` (exit 2).

Issue #561 changes only FinishUP-owned external Codex registration. Cursor remains supported through
its native plugin projection: when `FINISHUP_ISOLATED_ROOT` is set, the exact validated root is
rendered into the plugin-managed `mcp.json` environment and every native hook command, and is
bound by that artifact's preview and marker digests. Cursor uses its own
`isolation_binding` status field; it does not consume the Codex `mcp add --env` path.
The status comparison selects the hook set from the installed profile: ordinary artifacts use
`postToolUse`, `postToolUseFailure`, and `preToolUse` alongside lifecycle hooks, while structural
artifacts use `afterFileEdit` and `afterMCPExecution`. An exact MCP binding alone is insufficient;
a root drift in any expected hook surface reports `isolation_binding: different`.

```text
finishup integrate cursor plugin preview \
  --cursor-config-root /exact/testing/home/.cursor \
  --project-root /exact/testing/project \
  --format native \
  --mcp-ownership plugin-managed \
  --route-profile strict \
  --json
```

Review `request_id`, `preview_digest`, target scope, format, before state, MCP owner state, route,
artifact digest, and warnings. Apply with the same request and digest. A stale preview, modified or
unmanaged copy, symlink, rollback residue, or conflicting MCP source refuses without overwrite.

The preview output includes an exact argv-shaped `authorization.prepare_command`. Run it without
editing the digest:

```text
finishup consent prepare plugin_artifact_apply --target-digest <preview_digest> --json
```

Then apply with the same request and digest plus `--accept`. `--accept` binds the digest you
reviewed; it is not authority. Apply then proves fresh, action-bound, OS-authenticated presence
through the cell for the platform, which the preview names under
`authorization.human_presence.mechanism`:

- **macOS** (`macos_local_authentication`): a fresh Apple LocalAuthentication device-owner
  prompt names the exact operation, full preview digest, and pending review ID.
- **Linux, including Ubuntu or another distribution under WSL 2**
  (`linux_pam_trusted_console`): the command writes the same operation, digest, and review ID to
  the terminal and asks for the invoking account's Linux password, verified through PAM
  (`login` service). Run it from your own foreground terminal: an agent's Bash tool, a
  redirected shell, or a background process has no trusted console and fails closed. The account
  needs a password (`passwd`); a WSL 2 distribution sets one at first launch. Coverage: unit
  tests drive the ceremony with a scripted PAM, and CI on Ubuntu 24.04 proves only that real
  Linux-PAM rejects a wrong password for the runner's account. The 2026-09-20 installed
  lifecycle checks additionally exercised successful real PAM approval on Ubuntu x86-64 and
  WSL 2 using disposable local accounts. Each mutation required one password prompt; a
  repeated no-op required none. A real interactive Linux setup also passed its confirmation
  and single PAM prompt (issue #767).
- **Any other platform** (`unsupported`): fails closed.

Successful authentication consumes that pending once before install, replace, or remove.
Cancellation, an unavailable policy or PAM stack, timeout, a wrong or empty password, a
stale/reused/mismatched pending, a terminal without the password, or `--accept` alone fails
before mutation. This proof is installation authority only; it does not prove discovery,
activation, skill delivery, MCP runtime/model use, hooks, observation, AI-powered review, or
workflow completion.

Replaying the same request and digest after a committed install or remove whose result was lost
reconciles at the already-selected state without mutating bytes or spending a second review. Pass
`--action install` on an install replay: the tree now exists, so the inferred default becomes
`replace`, and a replace replay reports `preview_stale` because the accepted digest bound the tree
the commit already destroyed. Reconcile a wedged replace through `status`, never by re-applying.

Portable uses root `plugin.json`; native uses `.cursor-plugin/plugin.json`. One installed tree may
contain only one of those manifests.

For local IDE development the explicit user root resolves to `plugins/local/finishup` below the named
Cursor configuration root. File install is not live MCP runtime. `Developer: Reload Window` can
leave a shared `mcp-process` helper on the previous route; fully quit that exact Cursor app, verify
its processes exited, and relaunch with the same isolated profile. `finishup integrate cursor plugin
status` reports `mcp.runtime.activation` as `matched` or `full_restart_required` when a live scan
is available. That is activation work, not installation proof. For CLI use the exact installed tree
with `--plugin-dir`. Cursor also supports `.cursor/skills`, `.agents/skills`, and compatible host
skill directories. Those are separate delivery paths: a copy or a project rule cannot serve as
evidence that this plugin was discovered. Record the actual loaded source before claiming delivery.

The current Cursor desktop host can still discover a user-local plugin under the regular shared
`~/.cursor/plugins/local/finishup` when launched with another user-data directory. Treat that as a
host discovery limitation: an isolated user-data directory does not by itself prove isolated
plugin discovery. Keep the explicit plugin root, FinishUP root binding, and discovery observation as
separate proof facets; a clean cell must verify which plugin directory Cursor actually loaded.

## MCP ownership and source precedence

### Project registration and root selection

A user-local plugin can be discovered and its MCP tools can be connected while a workspace
operation returns `SESSION_CONFLICT` with `repository_identity_required`. The reviewed Cursor
implementation can emit absolute filesystem paths in `roots/list.uri` and include multiple open
projects in the shared MCP process's root inventory. FinishUP accepts that strict local path shape
through its Cursor adapter and safely canonicalizes every root. An explicit project registration
selects the intended repository from the host's inventory. Hook `workspace_roots` and an agent's
terminal working directory remain separate facts and cannot replace the MCP client's roots.

For this host behavior, use an explicit project registration and an external-registration plugin
for the skill and hooks. First remove the existing plugin-managed artifact through its normal
preview, consent, and authenticated remove lifecycle. There must be only one `finishup` MCP owner.
Then invoke the exact intended FinishUP launcher to preview and install the project entry:

```text
/absolute/finishup integrate cursor project-mcp preview \
  --project-root /exact/project --cursor-config-root /exact/cursor/config \
  --route-profile policy --json
/absolute/finishup integrate cursor project-mcp install \
  --project-root /exact/project --cursor-config-root /exact/cursor/config \
  --route-profile policy --accept --preview-digest <preview_digest> --json
```

Install the native plugin with `--mcp-ownership external-registration` through the authenticated
plugin lifecycle. Its launcher and isolated root must match the project entry. The project entry is
`.cursor/mcp.json`, has the pinned launcher plus `mcp serve --host cursor --project-root
<exact-project-root>`, and carries only the validated `FINISHUP_ISOLATED_ROOT` environment binding when
isolated. Strict mode appends `--semantic off`; omitting `--route-profile` preserves an existing
owned route. The project registration command never launches a service and never grants AI-powered
review egress or host trust. The startup selector is validated against the exact owned project
entry, launcher, route, and directory/configuration identity. It must match a repository in the
active client's validated root inventory; empty or unsupported roots, malformed responses, timeouts,
and mismatches still fail. A changed registration or selected repository retires the MCP session.
Use the existing project admission commands for an authorized policy route.

`project-mcp status` reports configuration ownership separately from unknown host trust and
unobserved runtime binding. Open that project in Cursor, activate the changed server through
Cursor's MCP controls, and use a fresh agent conversation. After changing the entry, disable and
enable its project source to create a new connection, then verify the active command: Reload can
retain an older process or cached definition. Verify a model-controlled `start`, native hook
evidence, captured content, and authorized AI-powered review dispatch separately. Multiple distinct
roots still require a validated selector that matches one host-reported repository. Codex and Claude
Code retain their own existing registration paths.

Reverse the registration with `project-mcp preview-remove`, then `project-mcp remove` using the
exact preview digest and `--accept`. Removal and strict registration sweep only FinishUP-owned
project admission entries and report that result, including an already-absent registration.
Unrelated MCP servers and top-level JSON values are preserved; changed files are serialized as
canonical JSON. Foreign, duplicate, malformed, oversized, hard-linked, or symlinked configuration
is refused. This explicit writer currently requires POSIX descriptor-relative filesystem APIs.

The preview binds both target directories, all three known source preimages, the launcher, the
isolated root, and the before/after project configuration digests. Apply rereads those facts and
atomically replaces the project file through a pinned directory. Cursor does not share a lock
with this writer, so `host_config_not_compare_and_swap` discloses the remaining cross-process
race; this is not a multi-file transaction. After a lost result, inspect `status` and obtain a
fresh preview before retrying. No automatic migration or overwrite of another source occurs.

Ownership mode is exactly `external_registration` or `plugin_managed`. Observed state is exactly
`absent|external|plugin|dual|foreign|ambiguous`. Configuration source is plugin, project, user,
inline-create, or inline-send. Preserve duplicate and foreign same-name entries.

The future SDK design records this precedence in metadata fixtures only; it is not an operational
SDK support claim:

1. per-send inline servers (replace creation-time servers);
2. creation-time inline servers;
3. plugin servers when `plugins` is selected;
4. project `.cursor/mcp.json` when `project` is selected;
5. user `~/.cursor/mcp.json` when `user` is selected.

An inline/project/user `finishup` server must not create a plugin-managed pass. Prove negative controls
for each source, duplicate exact entries, a foreign same-name route, and the alternate strict/policy
route. The exact plugin-managed routes are `finishup mcp serve` (policy) and
`finishup mcp serve --semantic off` (strict) for the byte-identical portable carrier. The native
Cursor target adds `--host cursor` and binds the exact launcher: its `mcp.json` entry is
`command: <absolute finishup executable>` (or the interpreter, with `-m finishup` leading `args`) followed
by `mcp serve --host cursor` (policy) or `mcp serve --host cursor --semantic off` (strict) — the
same launcher the native hooks use and the `/3` marker records. In an isolated artifact the MCP
entry also carries exactly `env: {FINISHUP_ISOLATED_ROOT: <validated-root>}`; arbitrary environment
keys remain foreign. Cursor's MCP reference resolves a
bare `command` through the desktop app's sanitized PATH, which in the 2026-08-29 dogfood launched
an older ambient runtime (control schema 2.1.0) behind a marker-valid then-current plugin (2.3.0); the
bound entry removes PATH from the runtime choice (issue #468). Issue #1076 does not change
Cursor. The native plugin `mcp.json` already names that absolute launcher and, when the artifact
is isolated, writes both `FINISHUP_ISOLATED_ROOT` and `YOETZ_ISOLATED_ROOT` (ADR-048). A bare PATH
command is not what that entry launches. That profile retains
`structuredContent` and also repeats the exact canonical JSON body in text `content`, because
pinned Cursor `3.17.x` can otherwise hide structured results from the model. It adds no
environment or secret beyond the exact isolated-root binding and does not widen the service
route. Decision for Cursor (issue
#579): supported here — the `--host cursor` text channel is the exact canonical JSON wire body,
so `safe_details.reason_code` and `safe_details.field` are already model-visible for
`EVENT_INVALID`. The generic bounded `Reason:` summary is the Claude Code path; Cursor tests lock
that the JSON copy still carries those tokens and is not reduced to the weaker summary. Route recognition accepts a
hand-written bare `finishup` (external registrations) or a known launcher (this runtime's or the
installed marker's) with the exact serve arguments, optionally with exactly the validated
`FINISHUP_ISOLATED_ROOT` environment binding. Route-shape recognition can describe a structurally
valid binding, but lifecycle ownership requires the artifact's exact root; a different valid root
is `foreign` and cannot count as owned or admitted. Any other command, prefix, or key set is
`foreign`. Raw initialize and
tools/list prove only runtime registration. Require a correlated model-controlled `start` or
`status` call for use.

`finishup integrate cursor plugin status` reports the state-root binding as `isolation_binding`
(`ambient|isolated_exact|missing|different|unobserved`). `ambient` and `isolated_exact` require
the marker and every root-bearing MCP/hook member to agree; a marker alone does not prove the
child launch binding. `different` covers a changed root or a root-bearing member whose binding
drifted. It reports the executable binding under
`launcher`: `installed` and
`artifact` launchers; `executable` (`matched` — same launcher and it exists; `drifted` — the
installed tree binds another installation than the one reading status; `missing` — the bound
executable is gone; `unbound` — portable or legacy `/1` marker; `unobserved`); `mcp_binding`
(`exact_launcher`, legacy `ambient_path`, `absent` for external registration, `foreign`); and
`identity`, probed by running the installed launcher's read-only `version --json` and comparing
`package_version`, the `control-result` schema version, and `resource_manifest_digest` with the
runtime reading status (`observed: false` when it cannot answer). `mcp.runtime.executable_activation`
compares live Cursor-helper children with the installed launcher: `executable_mismatch` forces
`activation: full_restart_required`. A tree rendered before issue #468 stays marker-valid and shows
`state: modified` with `mcp_binding: ambient_path`; perform one exact previewed replace, then
fully quit Cursor.

### Applied-route drift decision (issue #537)

Decision for Cursor: not supported here — no additional state-root applied-route record
at this time. The plugin-managed `mcp.json` entry already binds the route profile and declares
`--host cursor` (the exact serve arguments, including `--semantic off` for strict), and the `/3`
marker records the same launcher the native hooks use; the live binding and launcher read-backs
above remain the authority for which route this host serves. The explicit Cursor identity also
prevents the Codex-only applied-route drift comparison from being applied to this host. A stale
serving process shows as `executable_mismatch` / `full_restart_required`, not as
applied-vs-serving drift. If a ceiling check ever needs a Cursor-specific applied-route record,
that is a separate design-gated change.

### Initialize instructions body (issue #918)

Decision for Cursor: supported here — the native `--host cursor` bridge serves the same compact
initialize body as Codex (`COMPACT_INITIALIZE_INSTRUCTIONS`, at most 2,048 bytes) instead of the
19,835-byte `agent-instructions.md` document. No Cursor-specific constraint argues for the full
body. Cursor documents no instruction-size cap, and it does not document whether or how it puts
MCP initialize `instructions` into the model's context, so the full block was never a guaranteed
delivery path for the safety floor on this host. The compact body names all five guidance URIs
and tells the agent to read `agent-instructions.md` with `read_guidance` before the first
`start`. Cursor's `read_guidance` result is unchanged: its text `content` still carries the whole
document, because Cursor does not reliably deliver `structuredContent`, so the full safety floor
stays model-visible one call away. The route tail and the destination disclosure are composed
exactly as before; the Auto-review question below is unaffected. The same body on Codex and
Cursor, and a compact body on Claude Code, keeps the three native hosts consistent.

The portable Agent Plugins carrier (`finishup mcp serve` without `--host cursor`) keeps the generic
full body, like every generic route. An open Cursor session keeps the instructions from its
`initialize`; after an upgrade, a full application quit starts a bridge that serves the compact
body. Evidence boundary: `tests/unit/mcp/test_compact_host_instructions.py` locks the selection;
the #918 cost evidence is Codex-only, and the Cursor dogfood lane (macOS, Linux, WSL 2) is pending.
Revisit this decision if that lane shows agents skipping the safety-floor read.

## Auto-review and host admission

Cursor's Auto-review run mode sends non-allowlisted MCP calls to a classifier that may allow,
redirect, or ask; Ask Every Time was removed in 3.5. Its inputs are undocumented and it "is not
a security boundary" (`cursor.com/docs/agent/security/run-modes`, `/reference/permissions`,
`/cli/reference/permissions`, re-read 2026-08-30). The levers are `mcpAllowlist` (`server:tool`,
case-insensitive, `~/.cursor/permissions.json` and `<workspace>/.cursor/permissions.json`
concatenate; no deny list exists) and the Agent CLI's `permissions.allow` `Mcp(server:tool)` in
`<project>/.cursor/cli.json` (deny wins over allow). Cursor does not document whether the
classifier sees MCP initialize `instructions`, so the policy-route destination disclosure of
issue #479 is not relied on on this host; `mcpAllowlist` remains the lever.

Host admission (issue #467) writes both project-scoped entries for exactly `check`:

```text
finishup integrate cursor admission preview --project-root <project> --cursor-config-root <root> --mcp-ownership plugin-managed --json
finishup integrate cursor admission grant --project-root <project> --cursor-config-root <root> ... --accept --preview-digest <digest>
```

`.cursor/permissions.json` receives `finishup:check` (the docs name the server by its `mcp.json`
key, which is `finishup` for every FinishUP route). `.cursor/cli.json` receives `Mcp(finishup:check)`
for an external registration or `Mcp(plugin-finishup-finishup:check)` for the plugin-managed server,
following the exclusively observed owner: the CLI names a plugin-bundled server
`plugin-<plugin>-<server>` (live-verified 2026-08-29). Whether the IDE names a plugin-bundled
server the same way is undocumented and unverified; the acceptance cell in issue #467 is open.
`status` reports `partial` when only one of the two files carries the entry. A wildcard
(`finishup:*`, `*:*`, `Mcp(*:*)`) or a CLI deny rule is `foreign` and never edited.

The other workflow calls have a local effect: `start`, `publish_work`, `respond`, and `receipt`
append or read records in the local FinishUP ledger, while `status` and `read_guidance` read local or
packaged state. None of these calls publishes to GitHub or invokes an AI-powered review provider.
This describes the effect after FinishUP receives the call; it does not predict Cursor's admission
decision. Cursor Auto-review may still hold a non-allowlisted local call as a shared-state or
external-workflow action, and Cursor provides no hook event for that classifier decision.

For a held local call, use Cursor's visible approval control for that exact call if the workflow is
authorized to continue. A hold before invocation is not a FinishUP result and creates no operation,
review status, provider attempt, or receipt. After approval, let Cursor execute the exact held
call and continue from its returned result. If Cursor requires resubmission or the response is
missing, retry the same request body and `request_id`. If the call may have started but its result
is ambiguous, use `status view=operation` with the original request identity or replay that same
request according to the operation's recovery instructions. Do not mint a replacement request or
duplicate event identity. This recovery procedure does not change Cursor's Auto-review settings or
prove that a future call will be admitted.

A mutating preview warns `host_config_not_compare_and_swap`; keep Cursor and other settings writers
quiescent during apply. FinishUP rechecks each exact preimage immediately before its atomic mutation
and verifies the combined result, but ordinary files cannot exclude a non-cooperating same-UID
writer in the final syscall window. If the second surface drifts after the first changed, the
operation reports `write_failed` rather than claiming a transaction-wide rollback.

Reverse: `admission revoke`; `plugin remove` and an install/replace onto the strict route sweep
the entry when `--project-root` is given and report `admission_cleanup`; `setup disconnect --host
cursor-ide|cursor-cli` plans `remove_project_admission` for `--project` (both Cursor surfaces),
sweeps it before the plugin and project MCP removal and reports `status.admission_cleanup`
(other projects are not enumerated); a privacy commit that
stops external review sweeps it; `provider status` reports `host_admission_drift`. That report
walks from the launch directory to the repository root, so a subdirectory cwd does not read as
`absent`. Cursor publishes no hook for a classifier denial. A held `check` is visible only through
the #187 pause/approval flow, while a held local call has no FinishUP-side denial diagnostic; that
gap is documented, not diagnosed. The host-hold advisory Claude Code's `PermissionDenied` hook
emits (issue #857) therefore has no Cursor carrier either: the shipped skill carries the
agent-side rule (a current grant read before asserting authorization, Cursor's visible approval
control for the exact held call, no downgrade), and admission remains the durable fix.
Mirror the Claude ingress if Cursor publishes a post-decision denial event.

The Cursor session-start context can also name `finishup integrate cursor admission grant`
when a fresh repository-bound read confirms an external-review grant and project admission is
absent. It reports a startup snapshot only: active MCP route and host approval remain unconfirmed.
The shared path requires active observation consent, skips deferred/local-only work, preserves
existing context, and spends at most 500 ms of remaining hook time on the grant read. No route
cache, host subprocess, settings change or retry is introduced. A missing notice proves nothing
about consent. The stdout contract is regression-tested; new native macOS/Linux/WSL acceptance
is still open on #857.

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
restart; that is the intended outcome of an upgrade, not a defect.

Claim correction is carried by the shared `publish_work` descriptor at
`publish-work-request/1.1.0`; Cursor hooks and subagent inheritance do not synthesize a replacement
claim. The matching local-control schema is 2.4.0; manifest mismatch stops an older 2.3.0 helper
before its frozen opaque branch can classify the new pair. Fully restart the exact Cursor profile
and re-prove descriptor plus correlated model use after upgrading before reporting the capability
as active.

## Legacy Yoetz registrations

FinishUP was named Yoetz through 0.2.5 (ADR-048). A Cursor configuration connected by Yoetz carries
the user plugin `~/.cursor/plugins/local/yoetz` (frozen marker `.yoetz-cursor-plugin-install.json`),
MCP entries under the `yoetz` key (project `.cursor/mcp.json`, user `mcp.json`, or the plugin's own
`mcp.json`), isolated-mode hook commands that set only `YOETZ_ISOLATED_ROOT`, and admission entries
under the `yoetz` server name. FinishUP reads these; it writes only `plugins/local/finishup`, the
`finishup` key and both isolation-root names. Until migration the old plugin keeps working: tool
calls named `yoetz:<tool>` and `plugin-yoetz-yoetz:<tool>` (each only beside its own server key),
the start binding, the startup gate, and `yoetz`/`yoetz.exe` children in the runtime classifier are
all recognized as FinishUP.

**Status.** `finishup integrate cursor plugin status --json`, its previews and `finishup setup
status --host cursor-ide|cursor-cli` report `legacy_installation` for the plugin tree; the MCP block
and `integrate cursor project-mcp` status, preview and apply report `legacy_registration` for the
`yoetz` key. Both use `none`, `legacy_only` (owned but outdated), `duplicate` (owned under both
names) and `foreign` (not provably FinishUP's; reported, never touched). A legacy plugin tree is
owned only with a valid frozen marker; its recorded launcher then also proves ownership of MCP
entries that name it.

**Plugin migration.** The guided connection and `finishup integrate cursor plugin install` (after an
install or `--action replace` preview) migrate an owned `plugins/local/yoetz` in the same reviewed
preview, which binds the legacy tree's digest (warning `legacy_installation_owned`; connection plan
change `migrate_legacy_plugin`), and keep the startup mode (`optional` or `required`) it was
installed with. Remove and disconnect also take a legacy-only install (`remove_legacy_plugin`). If a
lost result has to be reconciled after a migration, the legacy digest is gone and reconciliation
fails closed with `destination_conflict`; status shows the real state.

With several projects connected to one configuration root (#1058), the legacy user tree is shared
the same way as `plugins/local/finishup`: a disconnect that keeps the user plugin for other recorded
projects (`shared_with`, or unknown membership) also keeps an owned `plugins/local/yoetz`, and the
last disconnect, or `--remove-shared`, removes both. Yoetz 0.2 connected several projects to one
configuration root and kept no record of them, so an owned `plugins/local/yoetz` alone (no renamed
plugin, no record) counts as shared pieces found without a record: status and every preview carry
`membership_unknown`, an ordinary disconnect removes only the project's MCP entry and keeps the
tree, and only `setup disconnect --remove-shared` removes it (change `remove_legacy_plugin`). A
connect that migrates it records the project with `unknown_members`, which later connects keep;
the low-level `integrate cursor plugin preview --action remove` says `membership_unknown` too.
Recorded members whose project entry is still FinishUP's under the earlier `yoetz` key, proven by
a marker-recorded launcher, count as observed connected.

Decisions from the 0.3 port review (2026-10-15), per host: Cursor's Yoetz-era rule above is the
strongest of the three hosts. Cursor has no binding that names a project, so an owned
`plugins/local/yoetz` found without a record stays until `--remove-shared`, even for one project.
Codex differs: there the project its Yoetz-era marketplace table names counts as a member, and
Yoetz-era pieces found without a record only make trusted checkouts serving FinishUP's manifest
possible users, so with neither an ordinary disconnect removes the registration. Claude Code
needs neither rule, since it lists every project's install itself. The transport-less
`mcp_servers.yoetz` leftover diagnosis, keeping an owned `yoetz` registration a project still
needs, and the post-disconnect `shared_registration_retained` status are Codex-only: Cursor has
no user-level transport a project table depends on, and its `configured` reads the project's own
MCP entry. After a completed or repeated (`unchanged`) disconnect that keeps the tree,
`next_step` adds the exact `setup disconnect --host cursor-ide|cursor-cli ... --remove-shared`
preview, as `setup status` does. The terminal interface's `/disconnect` offers no home-wide
removal of its own: when pieces were kept it reads "Integration removed from this project; shared
pieces kept" and shows that same command to run in a terminal, so the separately disclosed
home-wide consent stays in one place. A disconnect never plans the admission sweep for a
surface it does not edit (exact legacy entries count only on an otherwise absent
`.cursor/permissions.json` or `.cursor/cli.json`, never on a foreign one), as for every host.

**Project MCP migration.** A project entry under `yoetz` that launches this installation (its
`finishup` script, its `yoetz` alias, or a launcher a FinishUP marker recorded) is owned but
outdated. Project MCP install rewrites it as `finishup` and drops `yoetz` in one preview (warning
`legacy_registration_owned`); remove deletes both keys; owned entries under both keys read as
`duplicate`, not unreadable. A `yoetz` entry in the user or plugin source is reported but only the
project file's entry is migrated. A FinishUP server still registered under `yoetz` in
`~/.cursor/mcp.json`, or in a not-yet-migrated `plugins/local/yoetz`, is an existing FinishUP
source: project MCP install refuses (`external_source`, or `multiple_sources` when the project file
also holds an owned entry) rather than adding a second server, and setup readiness says that
connect will not edit that earlier-name entry. Migrate or remove it first; for the plugin, the
Cursor plugin install or replace migrates it. A foreign project `yoetz` entry is not counted as a
source. New plugin `mcp.json` entries, hook commands and project entries
export both `FINISHUP_ISOLATED_ROOT` and `YOETZ_ISOLATED_ROOT` with one value while the `yoetz`
alias ships; readers accept either name alone or both equal, and two different values are not
FinishUP's binding.

When the project file holds an owned `yoetz` entry beside a foreign `finishup` entry, project MCP
remove and disconnect remove only the owned `yoetz` entry. The preview warns
`foreign_entry_present`, and the result keeps that state for the retained foreign entry. Project
MCP install still refuses to overwrite it; rename or remove the foreign entry yourself before
migrating.

**Admission.** Grant writes only the `finishup` forms. The exact legacy entries `yoetz:check` (IDE),
`Mcp(yoetz:check)` and `Mcp(plugin-yoetz-yoetz:check)` (Agent CLI) are reported as `legacy_entries`,
removed by `admission revoke` and the removal sweeps, and retired by a grant once nothing FinishUP
owns uses the `yoetz` name. A grant is refused with `legacy_registration_active` while Cursor serves
FinishUP only under `yoetz`.

**Manual steps for state FinishUP cannot prove.** Anything under the legacy name without proof is
`foreign` and stays; inspect it and remove it yourself only if it is a leftover:

- A `plugins/local/yoetz` tree with a missing or modified marker: delete the directory after
  checking it holds nothing you want.
- A `yoetz` MCP entry that names a launcher FinishUP cannot prove, for example an old runtime path
  that no longer exists: delete the `yoetz` key from that `mcp.json`.
- Order matters when you run the explicit commands instead of the guided connection: running
  `integrate cursor plugin install` (which migrates and deletes the legacy tree and its marker)
  before `integrate cursor project-mcp install` loses the marker-recorded launcher, so a legacy
  project entry naming a moved old launcher reads `foreign`. Run the project MCP step first, or use
  the guided connection, which captures the recorded launchers before the plugin step.

## Multitask delegation after an outage

The #499 lifecycle repair applies to cooperative Cursor children: activity renews session health,
abandonment is durably service-stamped, and an unused expired handle leaves an abandoned
reservation. The #507 native start-callback correlation bridge is Codex-only and does not change
Cursor's unsupported native-subagent decision or earn a capability cell. The #754 multi-agent v2
child identity source is Codex-only on the same boundary: it reads a Codex rollout `session_meta`
header, and Cursor has no session-stream family of its own, so its native-subagent decision and
capability cell are unchanged.

Liveness follows the shared #837 rule. Admitted Cursor hook events count as contact at their own
receipt time, including late sweeper delivery and `stop`, while `sessionEnd` ends contact. Cursor
registers no subagent lifecycle hooks, so no in-flight hold applies. A quiet period past the lease
plus the recovery window with no workflow call or hook event is the recorded Cursor gap, and
raising `lineage.contact_lost_recovery_seconds` is the supported mitigation. After abandonment,
refusals carry `lineage_successor_task`: keep the held session for history and receipts, and start
one successor task for new work.

Cursor subagents inherit the parent's MCP tools, so delegated workers reach the same `finishup`
bridge process. The bridge latches the first availability failure of that binding
(`service_unavailable`, `service_incompatible`, `protocol_mismatch`, `endpoint_unsafe`,
`peer_untrusted`): the parent's error carries `safe_details.availability: terminal_unavailable`
with `host_profile`/`route_profile`, and every later call under a new `request_id` — any tool,
any worker — returns the same `correlation_id` with `availability_inherited: true` and mints no
new diagnostic, startup, or supersede. Parallel first calls (ordinary host behaviour) share that
same single attempt: they do not each mint a diagnostic before the latch exists (issue #476). The
latch clears when the original `request_id` replays after the
named repair, when `finishup service run|restart|stop` changes the stamped holder, or (retryable
classes only) when one quiet handshake succeeds. The skill tells the coordinator to carry a
bounded `finishup_availability` block into each assignment and tells delegates that inherit it to
make no FinishUP call and publish nothing; lifecycle commands are never a response to
`INTERNAL_ERROR`. In the 2026-08-29 dogfood (issue #469) the initial outage was the ambient-runtime
mismatch above; the delegates only amplified it. Report those two facts separately, and never
claim delegate publications or attribution without a task and session.

## SDK TypeScript and Python (deferred)

Operational local SDK support is deferred for the planned `0.2` readiness slice. The TypeScript and
Python fixture rows retain package, bridge, setting-source, and precedence metadata only; they are
marked `metadata_only` and `not_a_support_claim`. No SDK import or execution, bridge start,
activation, model-controlled FinishUP call, or SDK hook capability is currently advertised or proven.

Promotion requires a new design-gated issue and independently reviewed proof for each binding:
package/bridge identity, explicit `local.settingSources` or `local.setting_sources`, source-winning
negative controls, model-visible FinishUP operations, one correlated model-controlled call, and an
independent final result row. Until that work lands, use only the IDE/CLI implementation paths above
and keep each support claim bounded by its actual proof facets.

## Hooks and observation

Cursor remains structural-only for issue #302: its native hooks retain digests and allowlisted
outcome metadata but no captured content object, so they do not mint `observation_captured`
evidence. The ordinary-work profile below is a separately acknowledged capability/privacy
expansion; the default structural profile retains the boundary above.

The default structural artifact remains unchanged. An explicitly rendered ordinary-work artifact
uses `cursor-ordinary-observation-v1` and subscribes to Cursor's generic `preToolUse`,
`postToolUse`, and `postToolUseFailure` events plus lifecycle signals. `afterMCPExecution` is
subscribed only to bind an exact FinishUP-owned successful `start`; it emits no observation,
content, or advice in this profile. It leaves `beforeShellExecution` and `afterFileEdit` out until a
deduplication contract proves they are distinct from the generic stream. The hook command carries
the exact profile id with `--observation-profile`; the id records the normalization contract and
does not certify the installed Cursor build.

Review packet reserved room (#907): a Cursor `postToolUse` `Write` capture carries a
workspace-relative `path`, so the newest applied write of each path is reserved as the current
diff and older writes are marked `superseded_by`. Edits that reach FinishUP only through
`afterFileEdit` are not captured in this profile, so their paths get no reserved slot; agent
evidence and generic `postToolUse` output compete by recency. Verification output is reserved
per command when its output can be linked to a recorded action and keyed command identity.
Unpaired or unidentified generic output stays explicitly unverified. The named-missing-item
check result, gaps and guidance are the same as on Codex and Claude Code; the check-time diff
provides the current repository view when its capture is available.

The ordinary `postToolUse` path emits queued work advice through the documented
[`additional_context` output](https://cursor.com/docs/hooks#posttooluse), including when a
command's exit is unknown or nonzero. Advice is marked delivered only after successful stdout
emission. `postToolUseFailure` has no consumable output, so its advice remains pending for a later
supported event. The rendered ordinary hooks use a lightweight entrypoint that avoids loading the
full CLI application graph. Ordinary events have a five-second budget, `sessionStart` and `stop`
ten seconds, and `sessionEnd` three seconds. Local structural capture, pairing, and the outbox
intent close before the bounded service drain; advice-bearing events remain synchronous so
`additional_context` stays on the current hook response. Legacy edit/MCP hooks keep their existing
output behavior, and automatic Stop follow-up messages remain disabled. Hook success never
substitutes for an explicit command/test exit fact.

**Failure supersession (#909).** On the ordinary profile a later `Shell` run of the same command
(only the latest limiting run is judged; a `postToolUse` with `exitCode: 0` clears an earlier
failure) can supersede an earlier failed run before a completion claim. A later failure or partial
rerun leaves the latest run live, and an unknown outcome or edit never retires the failed
verification. The receipt keeps unresolved runs disclosed as limitations. `Shell` failures also reach
`failed_command_unresolved` advice. The hook computes an installation-keyed `command_commitment`
from `tool_input.command` on `preToolUse`, `postToolUse`, and `postToolUseFailure`, then discards
the text. Decision: supported on the ordinary profile. **Gap:** a shell `postToolUse` without
`exitCode` stays `unknown` and neither fails nor supersedes; an oversized body whose content is
omitted carries no identity; the default structural artifact observes no shell calls (owner: #910
for Cursor shell outcomes). Native dogfood acceptance of this path on macOS, Linux and WSL 2 is not
yet recorded (owner: #909).

Stale-verification advice is scoped to the logical tool call rather than the observed phase, so a
`preToolUse`/`postToolUse` pair carrying one call identity reports one
`edit_after_successful_check` finding with both phases as evidence. The reviewed post-only
structural profile is unchanged and still reports one finding for its one observed phase; FinishUP
does not fabricate a pre-event to complete a pair (issue #680).
Built-in shell success is a host outcome, never a check: local advice moves its
verification baseline only on a current `passed` approved-check fact or an explicit success from a
dedicated verification tool, and never on a routine read (issue #681). This host adds no reviewed
check signal of its own, so a Cursor session with no approved check keeps
`completion_without_verification` instead of inheriting a baseline from a successful command.
For ordinary MCP tool events, `tool_output` contains tool-domain data. Only the outer MCP
`isError`/`is_error` signal contributes execution status; nested `status`, `outcome`, `success`,
and exit-like fields do not describe the host execution. Built-in shell outcomes retain their
separate exit-status handling.

**Shell outcome contract (issue #910).** On the ordinary profile a `Shell` `postToolUse` records
an outcome only from an explicit `exitCode`/`exit_code` in its `tool_output`, which is `success`
for 0 and `failure` with that `exit_status` otherwise. Hook success alone is never taken for a
command's success. A `Shell` `postToolUse` without an exit field stays `unknown` and carries
`host_outcome_unavailable` for that record. A `postToolUseFailure` is recorded as `failure`, with
the closed status from `failure_type` (`error`, `timeout` or `denied`), or `interrupted` when
`is_interrupt` is true. Its message is never parsed for an exit code. It is unverified whether
Cursor's real `Shell` `postToolUse` carries `exitCode`. Until a captured payload settles it, the
documented decision for a result without one is `host_outcome_unavailable`, never an inferred
outcome. The capture is owned by issue #910. The default structural profile records no generic
tool outcomes. The shapes are pinned by `fixtures/observations/cursor-shell-outcomes.case.json`,
which is derived from the documented hook payloads with raw hook stdin capture pending. Native
acceptance on macOS, Linux and Windows through WSL 2 is not established by source tests.

Select these hooks with `--observation-profile ordinary` on the existing native Cursor plugin
preview/install/status commands. Repeat the same profile when applying an exact preview. To
return to structural hooks, preview a replacement with `--observation-profile structural` and
apply that exact preview. Portable artifacts reject ordinary observation; selecting a native
artifact does not grant content capture.
Preview names the selected profile. Status reports the requested profile and confirms an installed
profile only when its verified marker and artifact digest match; otherwise that installed value is
unknown rather than inferred from the request.

Native content is a second, per-host consent arm. After granting structural observation, enable or
revoke it with:

```text
finishup observe content-enable --workspace /exact/project \
  --profile cursor-ordinary-observation-v1
finishup observe content-status --workspace /exact/project --json
finishup observe content-disable --workspace /exact/project \
  --profile cursor-ordinary-observation-v1
```

This arm persists through later structural grants in the same workspace: connecting Codex,
rerunning Codex setup, or repeating `finishup observe grant` keeps it and does not advance its content
fence (#835). Only `content-disable` or `observe revoke` removes it; after a revoke, enable it again
explicitly.

The service accepts Cursor chunks only when that exact profile is active in local consent and in
the mapped task grant. A missing or mismatched profile drops plaintext chunks and records
`content_capture_unavailable`; chunks are not written to the structural outbox. Authorized native
hooks reserve the workspace drain before enqueueing the structural row, keeping a background sweep
from consuming it before the foreground content attempt. The nonblocking reservation is released
on cancellation or after the bounded drain; contention can still leave a content gap.
Content-bearing ordinary-profile native passes have a one-second drain window. Contentless
structural rows, including FinishUP-owned MCP mutations whose result is already durable elsewhere,
defer service delivery. When chunks exist, the pass prioritizes the current event after its
same-session FIFO prefix, within that one-second drain and sixteen-row bound. Teardown
keeps its host-clamped three-second hook, records local lifecycle/outbox intent, and defers service
delivery to a later hook or the sweeper (a ready service polls for undelivered rows every
5 seconds while idle, and retries a row that already failed an attempt at the 60-second idle
interval);
it skips local advice construction because the closing host
cannot receive it. A stale or blocked
backlog produces the explicit gap when the hook completes.
A hard process kill or service failure before authenticated service-side staging completes may
lose transient content without a durable gap marker; there is no plaintext local spool or offline
acceptance guarantee. For this ordinary Cursor profile, the capture-only service request can commit
encrypted objects, manifests, and a metadata-only capture ticket before the structural FIFO ingest.
After that boundary, a retry revalidates the original host/source and content-authority generations,
requires the complete expected group/part set, and reuses the ticket rather than reminting content.
The bounded staging handoff can therefore survive a service restart, while a revoked or incomplete
ticket remains an honest content gap. The installed Cursor IDE `3.19.7` fact is a candidate local
host observation while this runbook's pinned compatibility cells remain unchanged; it cannot
certify the ordinary profile without an exact isolated fixture and receipt evidence for native hook
delivery, accepted content, AI-powered review selection, and influence.
Native AI-powered review selection uses the accepted tool event's durable session route and does not
require an approved-check policy. Local capture consent and repository disclosure permission
remain separate requirements.

A handoff that its structural row can no longer consume (the row was already acknowledged,
quarantined, or refused) is retired by that row's own delivery, by the READY maintenance sweep once
it is 30 seconds old, or by a new CHECK's preflight, instead of holding shared oldest-age pressure
at the hard limit (#836). Its payload-free retirement account and
`content_capture_unavailable` marker commit before the ticket is tombstoned or its reservation is
released; a failed or cancelled account leaves the handoff retryable, and a replay is idempotent by
ticket identity. `observe status --json` names each retirement under
`capture_handoff_retirements`. A handoff whose row is still queued keeps counting toward pending age.
This hook sends its Cursor content profile only with
Cursor rows; a queued Codex or Claude Code row drained from the same workspace carries no profile, so
it is not refused as `content_capture_profile_mismatch`.

### Hook cost and timing (issue #915)

Every `hooks cursor-observe` pass folds one sample into the bounded aggregate that
`finishup observe status --json` reports as `hook_diagnostics.pass_timings` (text: `hook_pass_timing`).
Entries are keyed by host `cursor`, the raw Cursor event (`afterFileEdit`, `afterMCPExecution`,
`preToolUse`, `postToolUse`, `postToolUseFailure`, `sessionStart`, `stop`, `sessionEnd`) and the
rendered profile path (`structural` or `ordinary`), with `count`, `p50_ms_at_most`,
`p95_ms_at_most` (histogram bucket bounds), `max_ms`, an `outcomes` tally and a `recent` view. A
`preToolUse` sample includes the neutral permission write. A sample runs from the console entry to
the end of the pass; Python interpreter start and process exit are excluded, so add that term,
measured on the same machine, before comparing with host-visible latency. The `hooks startup-gate`
and `hooks startup-context` commands are not in the aggregate, although each is its own
synchronous process: `startup-context` on every `sessionStart`, and in required startup mode
`startup-gate` on session, prompt, `preToolUse` and MCP events. The aggregate is therefore the cost
of the observation hook only, not of every FinishUP hook Cursor runs.

Registration decision on Cursor (issue #915, recorded 2026-09-30): unchanged, and no latency
improvement is claimed. Cursor hooks are synchronous by host design (5 s for tool events). The
structural default subscribes `afterFileEdit` and `afterMCPExecution` per edit or MCP call plus the
session events; the ordinary profile adds `preToolUse`, `postToolUse` and `postToolUseFailure` for
every tool call, and required startup mode adds `startup-gate` processes. Cursor has no async hook
form, so the lever, if the measurements call for one, is a minimal-import fast path rather than an
async split. That is decided from the aggregate of a Cursor dogfood run in both profiles on macOS,
Linux and WSL 2; those measurements are not recorded yet, and the gap is owned by issue #915.

### Oversized hook payloads (issue #667, tb4n1 B5)

A Cursor hook body over the 1 MiB trusted parse cap (`MAX_HOOK_STDIN_BYTES`, shared by every host;
256 KiB until tb4n1 B5) is not admitted as a full event. An ordinary write to a large file can
reach this bound: Cursor's native tool input carries the whole file content (the dogfood writes
that opened issue #667 were roughly 389,000 bytes each, which now fit). The hook stays fail-open
and Cursor continues.

When that body is a complete document at or under the 8 MiB skim cap (`MAX_HOOK_SKIM_BYTES`),
FinishUP parses it with the same NUL, UTF-8, duplicate-key, and JSON checks as a normal event. Image,
audio, and video bytes (an MCP `image` block, a `data:` URL) are first replaced with a fixed
placeholder; if the body then fits the trusted cap it is admitted whole and records no gap.
Otherwise FinishUP keeps a closed identity view. The structural row records the session, tool name, and tool-call id
when those values are bounded tokens. A path commitment is kept only for `afterFileEdit` and for a
`postToolUse` edit tool that did not fail or get denied; a read, a pending `preToolUse`, or a
failed edit commits no changed path. Whether an `error` value was set is kept as a bit, never its
text, and an unkeepable `workspace_roots` is refused as it is at full size. File contents, edits,
prompts, and command text are omitted. The row's content references stay empty,
including when native content capture is authorized. Coverage on that row is
`payload_content_omitted`, and hook diagnostics record `cursor_payload_content_omitted`. A receipt
can name the edit and must not treat the omitted bytes as captured. A FinishUP MCP tool in a scoped
spelling (`finishup:<tool>`, `plugin-finishup-finishup:<tool>`, `closure_prepare` included) records
neither: its content is never captured, so the identity row is complete. Cursor's ordinary
`postToolUse` spells MCP calls as the generic `MCP:<tool>`, which names no server, so such a call
cannot be attributed to FinishUP and keeps the gap.

A body over the skim cap is refused before any parse. A complete oversized body that fails
validation is also refused, and it records `cursor_payload_invalid` as well as the size gap. Both
of those outcomes record `cursor_payload_too_large` and the workspace `payload_too_large` gap, and
they mint no structural row. A parsed oversized body that finds no session or no resolvable
workspace records the same gap. The ordinary profile's `afterMCPExecution` skip is deliberate at
every size and records no gap. The pure `read_cursor_hook_payload` replay still refuses above the
trusted cap, so a captured oversized body cannot be reparsed as a trusted full event.

The caps are fixed; raising them is not an operator control. Codex and Claude Code apply the same
skim since tb4n1 B5. The refusal or the omission costs exactly that one event; the next ordinary
event still ingests.

Matcher decision (tb4n1 B5): Cursor's generated hooks carry no per-tool matcher, and its ordinary
`postToolUse` names MCP tools only as `MCP:<tool>`, so no matcher could exclude FinishUP's own tools
without also excluding another server's tool of the same name. Excluding them would also leave
their `preToolUse` unpaired. The size problem is fixed in the reader instead.

Observed images (P3-2, issue #1013): Cursor image results arrive as MCP `image` blocks in `tool_output`. Before the bytes are
dropped, the hook records up to 8 images per call as digest-only facts: SHA-256 and byte count of
the decoded image, a media type sniffed from its bytes (PNG, JPEG, GIF, WebP, else
`image/unknown`), and pixel width and height read from the header only. The service records one
`evidence_recorded` row per image (`artifact`, `content_digest`, `digest_only`), listed in the
call's result `evidence_refs`, with the description `Observed image tool result <type> <w>x<h>
(<n> bytes); pixels were not captured or sent`. No pixel is captured, stored, or sent; the agent
can cite the evidence id as its own inspection of the output. This holds at every body size up to
the 8 MiB skim cap.

### Failed-command findings (issue #1104)

A failed `Shell` call becomes an observation finding (`failed_command_unresolved`, kind
`failed_work_omitted`) seconds after it is recorded. Decisions for Cursor:

- **Retire on pass: supported when `postToolUse` states `exitCode`**
  (`fixtures/observations/cursor-shell-outcomes.case.json`). A later passing run of the same
  command, alone or as a segment of a passing `&&` chain run as is (no leading assignment, `env`,
  `nohup`, `exec`, `time` or input redirection, ADR-025), retires the finding (closure basis
  `retired_by_passing_run`). A chain whose earlier segment may not hand control back
  (`exec CMD`, `exit`, `eval`, `source`/`.`, an unsafe `set` or `shopt -o`, an unresolvable
  command word such as `$RUN`, `exec>log` or `{exit,0}`) is recorded `masked` and retires
  nothing. Pinned by the Cursor case in
  `tests/integration/observation/test_failure_supersession_hosts.py`. A post without `exitCode` (#1091 N4) is `unknown` and retires nothing,
  which is honest; the fix stays with #1091. An edit never retires it, and no check resolves it
  (`observed_failure_not_rerun`).
- **Retire on a passing planned verification: supported when `postToolUse` states `exitCode`**
  (owner decision 2026-10-18, ADR-025). A later passing run of a command an effective obligation
  requests retires every earlier failed-command finding, even one for another command (closure
  basis `retired_by_planned_verification`); a post without `exitCode` is `unknown` and retires
  nothing. Pinned by `test_cursor_passing_planned_verification_retires_an_unrelated_failure` in
  `tests/integration/observation/test_failure_supersession_hosts.py`.
  A planned segment must have run as is (a leading assignment, `env`, `exec`, `nohup`, `time` or an
  input redirection passes nothing), a planned command that masks its own exit (`| tail`, `!`,
  `|| true`, `&`, `;`) never counts, and the passing call must have begun after the failed call
  finished. A failure it retires must still be named in a completion claim's `limitation_refs`.
  The passing run must be a verifier (the hook's runner class `test`, `build`, `lint` or
  `typecheck`; a planned `true` or `ls` retires nothing), and the obligation must have been
  effective when its `postToolUse` landed (owner decision 2026-10-18, #1104 comment 6252094173).
  Both conditions are host-neutral kernel rules pinned in
  `tests/unit/kernel/test_finding_retirement.py`; no Cursor-specific test covers them yet.
  Known gap (follow-up on #1104): the hook-side advice can still list the retired item until the
  observation evidence changes; `status view=advice`, the Stop gate, check and the receipt read
  the ledger and do not.
- **`acknowledged`** settles it as a disclosed failed command (`failed_run_disclosed`, never
  clean); `acknowledged_not_done` settles it as bookkeeping. A later pass still retires it.
- **Read-only chains and FinishUP's own CLI: supported**, as on every host.
- **Stopping its own background job: supported in one command** (`server & ...; kill $!;
  wait $!` with `exitCode` 143, or 130/137 for `-INT`/`-KILL`). Any other exit keeps the duty.
  Known limit: a host timeout that terminates the whole command with `SIGTERM` also exits 143;
  the postToolUse payload states no timeout flag, so FinishUP cannot tell the two apart. Both
  decisions are pinned through the real handler by the Cursor variants of
  `fixtures/observations/failed-command-exemptions.case.json` (OUT-006).
- **Doubled skill path:** not applicable (a Codex cache layout).

### Smart observation selection (issue #687)

Cursor's shared hook ingress applies the selector to the generic tool stream only when the exact
ordinary profile `cursor-ordinary-observation-v1` is installed and rendered. The structural
profile remains its existing post-only/native event contract; selecting a retention mode does not
widen it. With the ordinary profile, **Focused/standard (512)** is the default. A paired, proven
successful routine read, search, or inventory call may be represented by a bounded summary in
Focused mode. Detailed keeps eligible routine calls as individual records while pressure is
healthy. Capacity is independent of detail: `standard` (512), `larger` (2,048), and `largest`
(8,192) can each be selected with either mode. The larger profiles have finite provisional budgets
and do not certify an IDE cell or improve sustained throughput.

Failures, denials, cancellation, interruption, partial, unknown or conflicting outcomes, edits and side
effects, declared checks/negative verification, and reads protected for an obligation, claim, or
finding remain individual records in both modes. A pre-event keeps its native tool identity until
a post event proves success. Ambiguous shell composition and caller-supplied routine labels do not
make an event eligible for summarization. Cursor's `afterMCPExecution` binding event remains
binding-only for the ordinary profile; the structural profile's `afterFileEdit` remains edit
evidence. Neither path is turned into a routine read by selection.

Apply an owner choice from an exact preview:

```text
finishup observe selection-preview --workspace /exact/project \
  --detail detailed --capacity larger --session-id <cursor-session-id> --json
finishup observe selection-apply --workspace /exact/project \
  --detail detailed --capacity larger --session-id <cursor-session-id> \
  --accept --preview-digest <preview-digest> --json
```

This is a temporary session override unless `--persist` is supplied on both preview and apply
without `--session-id`; `--persist` is the explicit workspace choice. An optional RFC3339 UTC
`--expires-at` bounds either setting. `selection-status` reports selected and effective mode and
capacity; `selection-revoke` restores the safe fallback at the matching scope. These controls
affect future retention only. They do not rewrite accepted rows, extend Cursor's ten-second
session/stop, five-second ordinary event, or three-second teardown budgets, or change content,
privacy, provider, or network authority. Pressure can make a selected Detailed session effectively
Focused until the bounded recovery policy returns it to its still-valid selection.

**Configurable capacity (issue #828) — Cursor decision.** Cursor uses the same local capacity path
as every other host: `finishup observe selection-preview` with `--capacity standard|larger|largest`,
`--capacity custom --queue-count <64..8192>`, or `--capacity none`, then `selection-apply --accept
--preview-digest`, or the terminal interface's `/observe`. There is no Cursor-specific capacity
control, and repository or plugin configuration cannot raise capacity. An agent may relay a change
only after the owner accepts the displayed preview's scope, values, local-hardware consequences,
remaining limits, and lower/pause/resume path; ordinary task permission never authorizes an
increase. `--capacity none` returns `capacity_no_cap_unsupported` because the local state document
has a 16 MiB safety ceiling, and changes nothing; the largest supported capacity is 8,192 rows. MCP
`status` stays read-only for capacity. Hook body caps and Cursor's hook budgets are unchanged.
Custom counts need control schema `2.9.0` on both the client and the service; an older revision
drops a saved custom count to the default.

**Lowering above the fallback byte bound (issue #843) — Cursor decision.** Cursor uses the shared
store path with no Cursor-specific behavior. Lowering, revoking, expiring, or ending a larger
selection can leave more accepted rows than the new target holds. Those rows still drain, and the
store keeps finite room, tied only to them, for refused-input loss, delivery attempts, and session
ends. A refused hook reports `hook_observe_degraded: outbox_overflow; loss accounted` only after
the loss is durable. The notice ends with `cause=<cause>`, the closed admission
dimension that refused, and the same cause is recorded as the `admission_loss_<cause>` reason in
`hook_diagnostics.reasons` (ADR-029, tb4n1 B3). Only later inputs of the lost host call, or calls it
spawned, carry `observation_input_loss`; the shared store path applies this to every host. If a `sessionEnd` hook cannot persist its local end, it stays fail-open within
its three-second budget. It prints `hook_observe_degraded: session_end_unrecorded` and records
that reason in `hook_diagnostics.reasons`. Cloud agents do not run `sessionEnd`, so for them the
override ends by revoke or expiry.

Use `protect-read` before an upcoming read when a later claim needs its individual identity. The
reference must be an `obl_`, `clm_`, or `fnd_` identifier; at most 32 logical reads are outstanding,
and the protection expires after ten minutes by default (an explicit expiry cannot exceed that
bound). It narrows retention under existing observation consent and grants no content or
disclosure authority. `promote` can only promote an exact native identity while it remains in the
bounded buffer. After delivery it reports `promotion_window_closed` and `not_retained`; rerun the
current read as a new observation if historical bytes are required, and do not use that rerun to
prove the earlier state.

Cursor ordinary content capture remains a separate consent arm selected by the exact profile. Its
workspace-wide capture lane allows at most 512 staging/pending tickets and 128 MiB of captured
content, independently of structural capacity. The one-second native content drain window and
host hook deadlines still apply. A timeout, cancellation, incomplete content group, or service
failure leaves partial/unknown coverage or `content_capture_unavailable` where the boundary
permits; it is never silently converted to a successful routine summary. Capture status proves
configuration only, not accepted bytes, AI-powered review selection, or receipt coverage.

Cursor has no `codex exec --json` import surface. Issue #301's bounded import authorization makes
no Cursor adapter change; Cursor evidence continues through cooperative MCP and native
hook/observation paths.

The native IDE plugin advertises only `sessionStart`, `sessionEnd`, `afterMCPExecution`,
`afterFileEdit`, and `stop` for the pinned local profile. It intentionally excludes
`afterAgentThought`. Cursor also supports Agent Plugins: FinishUP's portable artifact supplies the
standardized skills and MCP components there, while hooks remain a Cursor-native plugin capability;
the portable CLI artifact therefore advertises no hooks. SDK fixture metadata advertises no hook
capability; the SDKs' file-based hook contract is not execution evidence. Hooks call
`finishup hooks cursor-observe`, are fail-open, and never enforce Cursor work.

### Delegate identity and file overlap (#508, #509)

The current exact local capability cell is IDE `3.17.8` and Agent CLI
`2026.07.09-a3815c0`. A read-only inspection of the installed app found Cursor `3.19.7`; its
resolver contains `SubagentStartRequestQuery` / `SubagentStopRequestQuery` fields such as
`subagent_id`, `parent_conversation_id`, and `tool_call_id`. Those shipped type definitions are
artifact evidence only and do not prove that the pinned 3.17.8 IDE or CLI emits, forwards, or
binds them at runtime.

The decision is **not supported here** for native subagent observation on both surfaces. The IDE
profile advertises only the five hooks above, and the CLI profile has no admitted hook or SDK child
signal. An inherited MCP session may carry an attach handle only through cooperative prompt
delivery; no separate child session identity is currently proven. A child `afterFileEdit` has only
the one-way changed-path digest, so #503 file-overlap attribution is `not observable for a
delegate` unless the child explicitly registers and supplies its own task/session. Such activity
is recorded as an attribution gap and never silently assigned to the parent.

### Cooperative qualification procedure (#509)

Regular Cursor Task subagents can inherit this session's FinishUP MCP tools. That inheritance is the
supported cooperative path. It is not a native subagent hook and it does not prove host
correlation. The qualification matrix and this run's native cells live in
[multi-agent-conformance.md](multi-agent-conformance.md#host-qualification-rows).

The #509 source guidance repair puts the no-selector helper rule in the workflow and host skill.
The shared initialize safety floor remains unchanged because of its advertised-surface budget.
The parent must give the helper that rule explicitly; spontaneous adoption of the repaired
guidance is not qualified by this run.

Supported, when the child actually calls FinishUP:

1. **Delegated-attach.** The parent calls `start` with `mode=delegate` and its current
   `session_id`. The returned child is `parent_minted` and `accepted`. Pass the complete
   `attach_handle` only inside that child's assignment. The child calls `start` with `mode=attach`
   and that handle alone, then uses the session and writer that call returns. The parent keeps its
   own binding. Do not guess `subagent_id` before the spawn. After the child returns, read
   `status view=lineage`. A successful attach is not host correlation: Cursor still has no
   subagent lifecycle hook, so a missing host identity stays an explicit gap.
2. **Self-registration.** A second child calls `start` with this workspace, its own
   `external_ref`, and the parent's `parent_session_id`. This macOS run used
   `mode=create_or_attach`. The composed fixture
   `test_self_registration_pending_acceptance_closure_and_receipt_rollup` uses `mode=create`
   with that same parent session. Either call begins `self_registered` and `pending`. The parent
   publishes `child_accepted` for that child task.
   Acceptance keeps the origin. An accepted child cannot later be rejected. The child still owns
   its plan, publications, check, receipt, and `work_closed`. The parent rollup is a later parent
   check of the recorded manifest; the child's receipt does not close either task and does not
   prove the parent incorporated the work.

Unsupported signals, which stay unsupported when a fixture is green:

- A Task launch, a prompt handoff, or a helper summary is not a child receipt and not
  `child_accepted`.
- An unregistered helper that was told not to call FinishUP is not a child. Do not publish
  `child_accepted` for it, and do not treat a pending `host_observed` annotation as its ledger.
  If the host cannot start a helper that stays off FinishUP, the native negative row stays
  `untested` and the composed fixtures cover it.
- `explore` and other read-only helpers are not evidence that a general subagent completed a
  FinishUP workflow.
- Linux and WSL native-session capability remains unproven (#722). This procedure does not admit
  those cells.
- This macOS run recorded `work_abandoned` on the parent while its parent-minted child was still
  open. That matches the missing subagent hold above. Abandonment is not child completion, and a
  later successor task does not inherit that child.

If a future exact cell proves a child signal, the service may stamp one `host_observed` pending
annotation from `subagent_id` plus parent conversation/tool correlation. An accepted parent-minted
delegate or cooperative self-registration then binds that annotation; host metadata alone never
creates a child task. The #509 row stays evidence-gated until an isolated cell reports child start,
publication, observation, advice isolation, and receipt separately. Cursor Cloud/Cloud Agents and
the portable CLI artifact remain separate unsupported surfaces.

Cursor's installed hook profile is post-only. `generation_id` identifies the
host turn/conversation and remains metadata; it is never used as a tool-call
identity or to synthesize a missing `PreToolUse`. A future paired Cursor
profile must be an exact capability-profile table entry and declare a real
tool-call identity before pairing is enabled.

Native hook artifacts and the plugin-owned `mcp.json` resolve the invoking `finishup` launcher to
one exact command at render time. A
console-script invocation resolves to that absolute executable; the documented `python -m finishup`
entrypoint (ADR-007) is preserved as an equivalent module invocation of the same interpreter.
Explicit absolute and relative invocations retain their path intent and never fall back to
an ambient `PATH` entry; only a bare `finishup` name uses `PATH`. The resolved launcher command is
recorded in native marker schema `/3`; an explicit invocation does not silently bind a
different ambient-PATH installation, and a malformed `/2` or `/3` launcher invalidates the marker.
The `/3` marker also records the exact isolated root or null for ambient mode. Portable markers
remain `/1`. A valid legacy native `/1` or `/2` marker is recognized as managed-but-modified so users can
perform one exact previewed replacement (or safe removal) instead of being stranded. The rendered
timeouts are 10 seconds for `sessionStart`/`stop`, 5 seconds for
`afterFileEdit`/`afterMCPExecution`, and 3 seconds for `sessionEnd`; `failClosed` remains false.
`sessionStart` uses Cursor's documented `session_id`/`conversation_id` conversation identity and
persists the validated pair as a bounded local alias, so later events carrying only
`conversation_id` resolve to the same FinishUP session; an event whose pair contradicts the validated
alias is rejected as `cursor_session_ambiguous` rather than splitting one conversation across
sessions. Cursor's hooks reference (re-read 2026-08-28) describes `sessionStart`'s `session_id` as
"the same as `conversation_id`", so one conversation maps to one FinishUP session by the host's own
contract and the alias is a defensive bound. Local rendering and integration tests cannot prove
live host session binding.

Advice uses Cursor's native output contract rather than the Codex/Claude Code envelope.
`sessionStart` may emit `additional_context`. `stop` does not emit `followup_message` for ordinary
advice because Cursor would auto-submit it as a new user message. **Stop-time closure gate (host
decision: supported).** The one exception is the closure gate: when a mapped session stops while
closure still requires agent action, `stop` emits `followup_message` naming what remains, so Cursor
continues the agent. A `stop` with `loop_count > 0` follows an earlier follow-up and is treated
like `stop_hook_active`: only an announced re-check not yet asked, or a withdrawn deliverable not yet voiced, may follow, and FinishUP's cap of two gate
continuations per turn stays under Cursor's own default `loop_limit` of 5 automatic follow-ups. The decision reads only the service's compact `status` for the mapped session (`closure_readiness`, read on the route the session's MCP server named on its last successful `status` or `check`, remembered across service restarts); it fires when `agent_actionable` holds open obligations, an unconfirmed blocker, an unrepaired receipt-blocking finding (agent work only), a finding the agent rejected that awaits a reviewer ruling (`finding_rejection_awaiting_ruling`), a planned verification that was not observed, failed, or ran before the latest edit, an edit to the work after the last verification run (`edited_after_last_verification`; temporary scratch and FinishUP-owned writes such as a saved receipt never count, ADR-042), a git-ignored requested output, or a declared deliverable deleted or renamed away (`declared_output_removed`, ADR-035), or a declared deliverable that held content and is now empty or truncated (`declared_output_emptied`, ADR-041 and ADR-045: keyed on the file, not the obligation, so acknowledging or republishing the obligation does not clear it; the gate text says why from the file's recorded history and names the one exit, a `finishup-assumption` decision that names the file; a standing `declared_output_content_moved` disclosure adds an informational note to gate text that fires anyway, never a token), or a delivered source file that may read a file the agent created and no requested item declares (`deliverable_references_undeclared_file`, #1044, ADR-035 amendments: a name the deliverable provably only writes does not count, and a bare file name a declared file shares, or that nothing ties to the file's directory, is counted on the receipt as `deliverable_references_ambiguous_name` instead; the text names each such file, quoted and bounded, from `closure_readiness.undeclared_references`, where a name the agent itself published in this session returns to it even when its privacy policy withholds repository excerpts, and tells the agent to embed it, rebuild it at run time or declare it, or the directory holding it, as a delivered output; when a name is withheld it says why and gives the agent's own shell command that lists the files its change created; disclosing the dependency does not clear it, and no path is remembered. Host decision for the tb4n5 naming: supported, same code path), at most once per ledger frontier and session (owner-only `observation/closure-gate.json`). Before that read the Stop pass drains this task's hook rows toward the current frontier (at most 2.5 s and 64 rows, keeping the gate's five-second reserve) and records `stop_drain_complete` or `stop_drain_incomplete`; rows of other tasks or unmapped sessions in the workspace do not hold the decision (#994). Verification items (planned verification and edits after the last verification run) are dropped only while this task's own hook rows are still draining after the Stop drain, and the text says so only then. The text pushes repair first: a receipt-blocking finding the agent repaired but FinishUP cannot prove (a FinishUP limit) is self-verified and answered with `respond` `self_verified`; `acknowledged_not_done` is the last resort; a FinishUP limit is never a `finishup-blocker`, and the blocker sentence appears only while obligations are open. An open obligation named by a `finishup-blocker:<kind>` decision is not listed as work, but each new `<obligation id>:<kind>` is re-asked once: the re-check names the obligation and claimed kind from the `blocker` entries of `closure_readiness.rechecks`, says recoverable data, a failing test, an infeasible-looking result or a FinishUP limit is not a blocker (finish the obligation and disclose the limit), and only there tells the agent how to confirm a genuine one: publish the same line again in a later decision whose rationale names what was re-checked, so the MCP bridge never refuses it as an unchanged id-less resend (the blocker offer never says so, and a confirmed row is never re-asked). Because blockers are usually published after the first gate, the re-check also runs on a Stop the host already continued: there it reads status, continues the agent only for a re-check key status announced that the gate has not asked, or a withdrawn deliverable not yet voiced (never for ordinary items), at most once per Stop and at most two gate continuations per turn (owner-only `observation/closure-gate-turns.json`, reset at every Stop the host did not continue; an unreadable counter counts as the cap), and lets the agent stop on any error, a short budget, or a memory write failure. Asked keys are remembered per session (owner-only `observation/closure-gate-blockers.json`, at most 64). Ordinary advice is never delivered at Stop; it waits for the next tool event or session start. Every outcome is a hook diagnostic (`closure_gate_continued`, `closure_gate_blocker_rechecked`, `closure_gate_active_stop_rechecked`, `closure_gate_memory_unwritten`, `closure_gate_not_required`, `closure_gate_repeat_suppressed`, `closure_gate_turn_end_after_continue` (an already-continued Stop that emitted nothing: the normal end of a continued turn, renamed from `closure_gate_loop_guard`), `closure_gate_budget_exhausted`, `closure_gate_unavailable`) in `finishup observe status`. The text also says an inherent verification limit or a best-effort choice is disclosed with a `finishup-assumption:` or `finishup-verification-limit:` decision line, never blocked, and names an obligation-level `acknowledged_not_done` as the last resort (#995, #997). Re-checks are not riders on other tokens (tb4n3 RC-8, #1031). Status announces them in `closure_readiness.rechecks` (acknowledgement, blocker, premise, each with a content key; the same list `status`, `closure_prepare`, the CLI and the TUI show, and the status directive names it: "At Stop you will be asked once to re-read: ..."), and the gate asks exactly the announced ones, each once per session and key (`ack:<obligation id>`, `<obligation id>:<kind>` for a blocker, `premise:<acknowledged count>`, all in the blocker-key file; closed items `acknowledgement_recheck`, `blocker_recheck`, `premise_recheck`). A readiness without the list (a service older than the gate) announces none, so the gate asks none. Acceptance provenance (ADR-033 amendment of 2026-10-18, owner decision D1): a resolved obligation the ledger flags (a requested item never attempted, evidence not linked to a declared item, or only self-asserted evidence) with neither an admissible observed verification link nor a recorded verification limit is never a Stop item. Status, `closure_prepare`, the CLI and the TUI name it once in the closure guidance (`closure_readiness.acceptance_risk`), and the receipt records it as the coverage limit `unresolved_verification_limitation` (the conclusion is at best `insufficient_coverage`). If an output does not meet its acceptance criteria, the agent republishes that obligation `acknowledged_not_done`; an acknowledgement that directly follows a `resolved` publication of the same obligation (an honest downgrade) is not challenged by the acknowledgement re-check. The gate drops an `acceptance` entry an earlier 0.3 service still announces and writes no `accept:` key and no `closure_gate_acceptance_rechecked` / `closure_gate_acceptance_covered` diagnostic (both names stay readable); `accept:` memory an earlier build wrote is still read, so an acknowledgement published after that invite is not challenged. Final message: Cursor's `stop` payload carries none (status and `loop_count` only), and since D1 no host's gate reads one, so Cursor no longer differs: the Cursor-only re-read wording is gone, and `afterAgentResponse` stays unregistered. Host decision: acceptance-provenance risk is never a Stop item on Cursor, the same as on Codex and Claude Code; the downgrade (`acknowledged_not_done`) and `finishup-verification-limit:` decision paths are the same on every host, and the rest of the gate is the same code path. The premise ask stays on Stops the host has not already continued; the acknowledgement re-check may continue an already-continued Stop within the same caps. A finding the agent rejected with a reason that awaits a reviewer ruling (`finding_rejection_awaiting_ruling`) sends the agent to `check` with `final_review: true` and never offers acknowledgement; `receipt_findings_unresolved` counts agent-work findings only, and `self_verified` is offered only while `finding_counts.self_verify_eligible` is positive. A deliverable that held content and is now empty or gone (`declared_output_emptied`, `declared_output_removed`) is voiced once per key (`emptied:<h8 of the declaring obligation items>`) even on an already-continued Stop, with the rule and obligation ids and never a path (every Stop after the first gate is an already-continued Stop in a single-turn run). The premise and acknowledgement texts say that if the agent cannot finish the work it keeps the working deliverable: acknowledgement never requires withdrawing or emptying it. Host decision: supported, same code path (the gate, its texts, its re-check list and its memory are shared by the Codex, Claude Code and Cursor Stop handlers; the only difference is how an already-continued Stop is detected, `loop_count > 0`). See ADR-033 and issues #977, #984, #985, #1031. `afterFileEdit`, `afterMCPExecution`, and `sessionEnd`
have no advice output channel and emit `{}`. Only a successfully written, nonempty `sessionStart`
object commits advice delivery; output-less events do not acquire the delivery lease. No hook
delivers a frontier-motion notice (issue #915), including the ordinary-profile `postToolUse`: every
such notice described observation-authored motion, which leaves a held frontier admissible.
Provider-repair advice uses that `sessionStart` channel only (#844).
A private or no-egress install, an install with no provider endpoint, and an install whose
verification is disabled do not put `connect_provider` or another provider-repair request in
`additional_context`. The service emits it only when verification is not disabled, a provider
endpoint is bound, network egress is permitted, and an LLM inference channel is enabled, and the
provider is still structurally unusable, including when no factory id is available. `stop` still
emits `{}` and leaves that delivery pending.

Mid-session, the agent can ask `check` to wait for this task's hook rows instead of polling `status`: `await_observations: true` (MCP) or `finishup check --await-observations` wakes the service sweeper and waits at most about 3 s (and a tenth of the request deadline) for the rows already pending, then reports `observations_awaited` (`complete`, `bounded_timeout` with the pending count, or `unavailable`). The decision is the same for Cursor: the wait reads the shared local outbox and lifecycle mappings, so it needs no host-specific hook; it never fails the check (ADR-029 amendment, #1012). The tb4n5 extension to rollout rows held for their hook post is Codex-only: Cursor has no rollout stream, so there is nothing held to release.

Workspace binding does not trust plugin-hook CWD. It selects a single `workspace_roots` entry first,
then `CURSOR_PROJECT_DIR`, then the explicit `--workspace` value. A multiroot workspace selects the
deepest root containing `CURSOR_PROJECT_DIR` or refuses. The reusable git-root helper walks safe
ancestors for the nearest `.git` directory or worktree file, without running Git, and refuses
symlinked ancestors, root/home locators, unsafe markers, or unbounded/control-bearing values.
`workspace_unresolvable` and `workspace_unconsented` remain distinct payload-free diagnostics
(with `paused` for a paused grant), recorded by the shared ingress for every host. A consented
`sessionStart` auto-attaches through the shared `start mode=create_or_attach` request, pairing the
resolved workspace root as `workspace_ref` with `cursor-session:<session_id>` as `external_ref`.
Before automatic new-pair admission, it checks private persisted mappings from eligible ended Cursor
sessions. Eligibility requires a received `sessionEnd`, every other bound session ended, and a
candidate bound only to this consented workspace. A unique eligible mapping is selected first: the
hook holds the workspace and lifecycle locks, revalidates ownership and state, and sends one
`mode=attach` request carrying that selector plus the new pair. The catalog requires the selected
root task to be active and non-quarantined, its canonical workspace and repository-privacy binding
to match, and no start already pending for that selected route. Other independent tasks in the same
workspace do not block this recovery (#814); a pair already bound to another task remains a conflict.
Delegated child routes require an authenticated attach handle or target selector. Recovery
revalidates unmapped sessions, cross-workspace ownership, mapping identity, and mapping recency; a
busy workspace reservation defers with `auto_attach_recovery_busy`, while candidate-lock contention
or changed state returns the closed `auto_attach_recovery_busy` boundary rather than creating work
from an unstable selector. A successful recovery rewrites every ended same-host predecessor mapping
for that task to
the rotated session and writer and drains pending rows on the successor route
(`session_superseded` is followed, not quarantined as `ledger_rejected`). With no usable persisted
selector, automatic `create_or_attach` admits the new pair as independent work, including beside a
dormant task. `workspace_task_exists` identifies only explicit `mode=create` colliding with an
identical pair; workspace membership never selects a task. Age alone never proves a host session
ended. A failed attempt records its typed cause (`auto_attach_workspace_unbound`,
`auto_attach_request_invalid`, `auto_attach_binding_ambiguous`, `auto_attach_conflict`,
`auto_attach_refused`,
`auto_attach_result_invalid`, `auto_attach_mapping_write_failed`, `privacy_authority_required`,
`service_unavailable`, `service_incompatible`, `vault_locked`, `timeout`, `storage_unsafe`, or
`storage_corrupt`) in the same diagnostics file, and the session keeps an observation-only binding
until a retry or an explicit `start` maps it. An explicit `mode=create` collision remains
`SESSION_CONFLICT` and is not a recovery selector. For `vault_locked` on a never-initialized
install, that explicit `start` returns the typed `vault_initialization_required` continuation (see
Troubleshooting) rather than a dead end.

Busy host lifecycle changes are durable local work. State schema `/11` adds bounded pending
session-lifecycle intents, and a READY or hook drain reconciles them under the workspace and
session reservations before routing their rows; busy mapping writes use an atomic per-session
handoff. Upgrade this state quiescently: stop the older FinishUP service and Cursor hooks, install
the new runtime, then restart the service and all Cursor integrations before writing `/11` state.
Mixed old and new writers are unsupported because a `/10` writer ignores the new pairing fields and
can erase a deferred intent when it saves.

The native Cursor MCP bridge has a separate workspace binding. It does not use the helper's process
CWD, because a Cursor MCP child can be launched from the user home directory. On the first workflow
tool call, the `--host cursor` bridge asks the active MCP client for `roots/list`. Its Cursor adapter
accepts safe local file URIs and strict absolute local paths. They must canonicalize to one repository,
or the validated owned project selector must match one repository in the returned inventory.
An unavailable, remote, malformed, nonmatching, or unresolved multi-repository response returns
`SESSION_CONFLICT` with
`safe_details.reason_code: repository_identity_required` before any local-service call. The bridge
retains and revalidates that binding before each workflow call; a changed or unusable root result
retires the session and its local client. A `notifications/roots/list_changed` message does the same,
so fully quit and relaunch Cursor or start a fresh MCP process before another workflow call.
The reviewed Cursor 3.19.7 host bundle advertises `roots.listChanged: false`, so the per-call
revalidation remains required even when no roots-change notification is sent.
`read_guidance`, tools discovery, and resource reads remain available without a project root. The
public workflow `workspace_ref` is never consulted for this binding. Keep that field equal to the
open repository root when using create/attach selectors, as the agent convention and guidance
require; a mismatch does not override or invalidate the trusted roots binding, but normal task
lookup can still follow the mismatching public ref pair. Auto-attach, queue admission, and mapping
diagnostics are separate hook lifecycle behavior and are not repaired by this MCP binding.

The `sessionStart` status probe for an already-mapped session connects with the resolved workspace
root as its repository locator, so a live mapping answers `active` and the `additional_context`
names the task, frontier, mapped `session_id` and `writer_id`, and the `start mode=attach`
continuation by that session id (issues #578, #580). A daemon fence refusal records
`status_workspace_unbound` / `status_workspace_mismatch` and keeps the mapping; only a replaced
session records `mapping_stale`. Cursor resolves its root from the host payload's
`workspace_roots` before the rendered `--workspace .`, so the Codex-specific issue #659 failure
(a probe with no usable repository context) does not reproduce here; an unresolvable root is the
typed `workspace_unresolvable` failure before any probe, and a fence refusal records the companion
`locator_source_explicit` diagnostic row.

A successful explicit FinishUP `start` now binds the canonical Cursor session before normal
observation handling (issue #661). The adapter transiently decodes `result_json` on
`afterMCPExecution`, or `tool_output` on an exactly server-scoped `postToolUse`, then passes the
result to the existing lifecycle binder. Only validated task/session/writer IDs and an optional
frontier token enter mapping storage. Task switching and same-task session replacement use those
returned IDs; the binder never guesses a task. Automatic admission follows the shared
ended-predecessor preflight, including the count-only ambiguity boundary described above.

[Cursor's hooks reference](https://cursor.com/docs/hooks), checked 2026-09-08, documents
`mcp_server_name` on `afterMCPExecution`. That hook admits bare `start` only for exact `finishup` or
`plugin-finishup-finishup` server keys. The adapter also accepts the existing fully scoped
`mcp__finishup__start`, `mcp__plugin_finishup_finishup__start`, `finishup:start`, and
`plugin-finishup-finishup:start` forms, rejecting a conflicting server field. Generic `MCP:start` alone
does not identify an owner and cannot bind. The ordinary profile therefore uses the MCP-specific
hook only for binding and keeps the generic hook as its sole tool-observation stream. Failed
results, foreign tools, malformed IDs, and contradictory session aliases cannot replace a map.
Unparsed or invalid admitted results and failed/deferred writes report the existing closed
`start_bind_unparsed`, `start_bind_invalid_ids`, `start_bind_write_failed`, or
`start_bind_deferred` diagnostics. Deferred writes follow the same lifecycle lock as recovery.

After upgrading, preview and apply the ordinary native plugin update so the binding-only hook is
installed, reconnect the MCP server with the intended project open, and call `start mode=attach`
using the known session ID. Check `observe status` for mapping and delivery separately: successful
MCP attachment alone is not observation recovery. Binding permits subsequent consented content
handoff; it cannot reconstruct content that an earlier unmapped call never delivered.

Cursor's hooks reference (re-read 2026-09-03) calls local `sessionStart` fire-and-forget: the hook
process can complete this mapping and drain, but the agent loop does not wait for it. Therefore a
rendered hook or passing local handler test does not prove the mapping existed before Cursor's first
agent action; verify eventual `mapping_present`, accepted envelopes, and drain separately. Cursor
cloud agents do not run `sessionStart` or `sessionEnd`, so this recovery is not claimed for that
surface.

The host-neutral `observe status` boundary also keeps storage layers distinct: unsafe state/lock
paths report `storage_unsafe`, bounded open/permission/read-only/missing-parent/lock-acquisition
failures report `storage_unavailable`, invalid stored data reports `storage_corrupt`, and other
defects retain the internal-error boundary. Fixed remediation omits the absolute state path. A
sandboxed Cursor-agent result does not establish unrestricted Cursor-terminal behavior; record
those proof cells separately.

Shared drain terminalization is host-neutral: `ledger_rejected` means the ready service rejected
one envelope non-retryably, so that row is retained in quarantine and later rows proceed. A task
bundle at schema 9 (bundle migration `0009`) stores `cursor_hook` rows; schema 8's source CHECK
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

`afterMCPExecution` of a FinishUP-owned tool follows the shared self-observation policy (issue
#564): an execution of `status`, `receipt`, or `read_guidance` under any FinishUP server spelling
(`mcp__finishup__*`, `finishup:*`, `plugin-finishup-finishup:*`) is ingested into the bounded local store but
not enqueued for delivery, while `start`, `publish_work`, `check`, and `respond` enqueue one row
each. Cursor's hook payload states no outcome fact for MCP executions, so a failed FinishUP call is
indistinguishable from a successful one at this ingress; the service's own record of the call is
the authority on its outcome. On the ordinary-work profile Cursor's generic `preToolUse` and
`postToolUse` spell every MCP call `MCP:<tool>` without a server, so the name alone cannot tell
FinishUP's `status` from another server's `status`, whose result is real evidence (tb4 n5 round 2).
FinishUP's MCP bridge on the Cursor profile therefore records a commitment to each read it served
successfully (`status`, `receipt`, `read_guidance`, `closure_prepare`: tool, FinishUP session and
writer, `request_id`; owner-only `observation/yoetz-served-reads.json`, newest 256) before it
returns the result. A `postToolUse` whose own `tool_input` matches a recorded read is FinishUP's and
stays local; the match claims the record, so it suppresses at most one post-event, and a record
older than 120 s proves nothing (a later call reusing the same request scope, in any session, is
delivered); every other `MCP:<tool>` event, including every `preToolUse` (the read is not served
yet) and every write, is delivered as before. Gap: a FinishUP read's `preToolUse` still reaches the
ledger on this profile (one row per read instead of two plus a result); owner: tb4 n5 follow-up.
The
shared advice guard recognizes both Cursor server spellings, so
a self-owned hook without an explicit failure does not lease pending frontier or recommendation
context for the call being observed; explicit failures remain eligible for pending advice.
This does not change local retention or explicit failure delivery. Cursor reports
`duration` as a finite decimal number of milliseconds
for MCP executions, while the canonical structural field is the bounded integer `duration_ms`.
Cursor ingress truncates that vendor value to whole milliseconds before structural filtering; the canonical parser
continues to reject floats on every ledger and non-Cursor host surface. Decimal values in discarded
vendor fields are replaced transiently and never reach the structural envelope. Execution and file
edit payloads use `model`, while lifecycle payloads may also provide `model_id`; a valid
`model_id` takes precedence when both spellings are present, and `model` is its bounded fallback.
Malformed or unsafe Cursor envelopes remain fail-open but record `cursor_payload_invalid` as a
payload-free hook diagnostic. `afterFileEdit` and lifecycle events are otherwise unchanged.

Cursor's currently reviewed native profile is post-only: `afterMCPExecution` and `afterFileEdit`
do not imply a missing `PreToolUse`, so accepted observations carry no synthetic `unpaired_event`
gap. Their `generation_id` is retained as bounded host metadata and is never used as a tool-call
identity; the materializer records metadata-only evidence instead of fabricating an action/result
pair. Codex's paired hook profile keeps its source/session/generation-scoped orphan diagnostics.
The historical 0.3 cell used control 2.5, which admits `pairing_mode`, `correlation_kind`, and
`generation_id` on structural observation payloads. Current control 2.7 retains those fields and
main's control 2.6 observation-selection projection alongside the 0.3 coordination surface; both
peers must use the same current manifest. An older development artifact omitted these fields from its
closed schema, so the client refused a valid Cursor-shaped frame before sending it and the hook
layer reported `ledger_rejected`. The frozen control 2.4 schema remains available for historical
validation; metadata is not stripped to disguise an incompatible contract.

Measured on 2026-08-28 with Cursor Agent CLI `2026.08.25-3e8eec8` (payload `cursor_version`;
`cursor-agent --version` printed `2026.08.11-e8db854`) loading the native plugin through
`--plugin-dir` in an isolated cell: the plugin-sourced `sessionStart` hook ran with `$PWD` equal to
the **plugin directory** (`<cursor-config-root>/plugins/local/finishup`), not the project, while
`CURSOR_PROJECT_DIR` and `CLAUDE_PROJECT_DIR` both named the project root and `workspace_roots`
was that single root. A bare `--workspace .` would therefore bind the wrong directory; the
`workspace_roots` → `CURSOR_PROJECT_DIR` → explicit order is what makes the rendered command
correct. The same payload carried identical `session_id` and `conversation_id` values. In that
cell, with observation consent granted, the model quoted the `sessionStart` `additional_context`
verbatim and `finishup observe status` reported `source_coverage.cursor_hook: true`; with consent
revoked, the hook emitted `{}` and recorded `workspace_unconsented`. The IDE cell (3.17.x) was
not measured in that run.

Measured on 2026-08-29 (issue #468) with the same Cursor Agent CLI build, loading a native
`plugin_managed`/`policy` tree rendered by a development checkout through `--plugin-dir` from an
isolated cell (`HOME` injected into the cell's `mcp.json` `env` and hook commands, which makes the
cell entry read `foreign` to status — read status before injecting): with `PATH` sanitized to
`/usr/bin:/bin` and a foreign `finishup` shim placed *first* on `PATH`, the plugin's MCP child ran
exactly `<checkout>/.venv/bin/python <checkout>/.venv/bin/finishup mcp serve --host cursor`, that
bridge spawned `<checkout>/.venv/bin/python -m finishup service run` from the same installation, the
foreign shim was never invoked, and a model-controlled `start` (`Mcp(plugin-finishup-finishup:*)`
allowed in `<project>/.cursor/cli.json`; the CLI names the plugin server `plugin-finishup-finishup`)
returned typed `VAULT_LOCKED` with a resolvable `correlation_id` — not `INTERNAL_ERROR` and not
`service_incompatible`. On the same machine the regular Cursor IDE's helper child was running the
maintainer's uv-tool channel (`~/.local/bin/finishup`, a shebang-expanded argv), and `status` for the
checkout's tree therefore reported `mcp.runtime.executable_activation: executable_mismatch` with
`activation: full_restart_required`, while `launcher.executable`, `mcp_binding`, and
`identity.matched` were `matched` / `exact_launcher` / `true` for the tree itself. The CLI's own
process is not a `Cursor`/`mcp-process` helper, so a CLI-only cell leaves `mcp.runtime` at
`unobserved` for its own child; the IDE cell's live executable match is the remaining
unmeasured facet.

Use the same selected path for `finishup observe grant|status|pause|resume|revoke`: operator controls
and setup probes apply the identical nearest-safe-Git-root normalization as hook ingress. A legacy
grant made against an exact Git subdirectory is intentionally not searched as an ancestor fallback;
run `finishup observe grant --workspace <subdirectory>` once after upgrade to record the canonical root.

Before local storage the adapter discards prompts, reasoning, response text, file paths/content/
edits, MCP arguments/results, transcripts, command output, email, and workspace roots. Fixtures
must place canaries in every denied field and prove absence from structural state, objects, logs,
errors, and hook output. Installation, hook configuration, or `sessionStart` earns no observation
coverage. Grant observation separately, prove accepted `cursor_hook` envelopes, pause, resume,
revoke, restart/replay, dedupe, and explicit gaps.

## Upgrade, rollback, and removal

Upgrade is a whole-directory previewed replacement. The preview binds the current tree digest,
future inventory, format, MCP owner/route, target identity, artifact digest, and request identity.
Do not mutate Cursor caches to force selection. Reload and re-prove source after replacement.

When the `finishup` runtime itself is upgraded (0.3.0 or later), nothing has to be stopped first. Open
Cursor sessions keep the running service; the bridge of the next session Cursor starts retires an
older service and starts the matching successor (ADR-007, 2026-09-24 amendment). A bridge that
predates the upgrade and finds a newer service reports that the session must be reopened instead of
replacing it. Runtime replacement, service switch, and Cursor/plugin activation are separate proof
facets.

Removal moves only an exact marker-verified managed tree and deletes it after the directory swap is
durable. Modified plugin bytes or recovery residue, including an isolated-root drift, are preserved
for review until an explicit replacement or removal preview is accepted. Foreign, dual, or
ambiguous MCP sources do not block exact plugin removal because the operation leaves every external
source untouched. Removal does not delete ledgers, vault/keyring state, provider credentials,
privacy grants, project/user MCP entries, or unrelated Cursor settings. After removal, independently check installed bytes,
discovery, activation, MCP sources, stale process/cache behavior, and regular-profile isolation.

## Troubleshooting

**Runtime another account can write.** A runtime another account can write (ADR-007, 2026-10-14) stops `finishup mcp serve` with `release_runtime_group_writable` or `release_runtime_world_writable` and the exact `chmod -R go-w` repair on stderr (Cursor lists the MCP server as failed and keeps its stderr in the MCP log). Its hooks exit 20 with no stdout, so they make no allow or block decision (exit 2 is the only blocking code); Cursor proceeds with the action; their stderr names the token without local paths and points at `finishup service run`, which prints the repair. Group write through the user's own private group (the Ubuntu/Fedora umask 0002 default) is accepted.

Cursor is not an allowlisted `finishup consent authorize` attestation client in v0.1. It may show the
agent-safe pending status and direct the user to a supported Codex attestation or local trusted
command, but it must not emulate `vault_initialize` or `vault_passphrase_rotate` authorization.
It still guides setup, installation, and settings choices in normal conversation and leaves each
supported product choice with the user. When AI-powered review is the stated goal, it recommends
Expanded first and explains Assisted as the lower-disclosure AI-powered option. It may show the full
v6 repository privacy preview, but its missing chat-authority capability is a technical boundary:
give the shortest exact trusted-local continuation and never silently downgrade the chosen recipe,
provider, or model.

First-run start continuation (issue #512): on a never-initialized install, the agent's first MCP
`start` returns non-retryable `VAULT_LOCKED` carrying
`safe_details.continuation: vault_initialization_required`. The `--host cursor` bridge profile
omits `authorize_command` entirely, so the continuation is trusted-local by construction: the
agent runs `finishup consent prepare vault_initialize`, shows the returned danger text, directs the
user to run `finishup consent review` on a local terminal, waits for the ceremony's terminal result,
then replays the exact original `start` request ID and body once. On denial or expiry the agent
states the boundary and continues without FinishUP. This supersedes the bare `VAULT_LOCKED` dead end
the 2026-08-29 measurement above recorded for a locked cell.

| Symptom | Interpretation |
|---|---|
| Skill appears but plugin identity is absent | fallback discovery; not a plugin pass |
| `tools/list` succeeds but owner is dual/ambiguous | source collision; do not choose silently |
| SDK fixture is present | metadata-only experimental scaffolding; no SDK activation or model-use claim exists |
| Model sees only a compact sentence and loses structured fields | the native plugin is stale or a portable/external route won; verify the winning source includes `--host cursor`, reload the isolated app, and retry |
| Installed MCP executable changed but Cursor still shows the old tool inventory | fully quit that exact Cursor testing app; Reload Window is not enough if a shared MCP helper survived. Verify its process exited, relaunch it with the same isolated profile, and re-prove discovery plus `tools/list` before claiming activation. `mcp.runtime.activation=full_restart_required` is this state. |
| `semantic_required` returns `route_semantic_ceiling` while plugin status says route `policy` | activation mismatch, not an owner privacy decision; inspect `mcp.runtime`, fully quit the host, and do not mint a fresh AI-powered check against the stale process |
| MCP resources load but every workflow call fails after a runtime upgrade | a pre-upgrade FinishUP service may still own the fixed endpoint; restart that exact service through the user-selected supervisor, then retry and require a returned task/session before claiming use |
| Hook fires but status stays published-only | configuration/trigger is not accepted observation evidence |
| Strict route has no AI-powered review | expected route ceiling; authorize a separate policy route when intended |
| Modified plugin cannot remove | preserved local change; inspect and resolve manually |
| Install refuses `authority_required` after `--accept` | no `plugin_artifact_apply` review is prepared for that exact digest |
| Install refuses `human_authority_unavailable` | the platform presence cell refused: on macOS LocalAuthentication was cancelled, unavailable, or timed out; on Linux or WSL 2 the password was wrong, empty, or cancelled, the command did not run from your own foreground terminal, or PAM is unavailable; any other platform has no cell; no mutation occurred |
| Install replay reports `preview_stale` | the inferred action became `replace`; replay with `--action install` |
| MCP entry looks right but reads `foreign` | route recognition is key-set exact; an extra key such as `cwd`, or an `env` object other than exactly `FINISHUP_ISOLATED_ROOT=<absolute printable root>`, is foreign, and an absolute `command` that is neither this runtime's launcher nor the installed marker's is another installation |
| Hooks observe but a model-controlled `start` returns `SERVICE_UNAVAILABLE` / `service_incompatible` right after install | the plugin's MCP process is another FinishUP installation; read `launcher.executable`, `launcher.mcp_binding`, `launcher.identity`, and `mcp.runtime.executable_activation`, replace a legacy `ambient_path` tree, then fully quit Cursor |
| `launcher.executable` is `drifted` or `missing` | the installed tree binds a launcher that is not this runtime's or no longer exists; one exact previewed replace re-binds hooks and MCP together |
| Delegated workers each report the same `correlation_id` with `availability_inherited: true` | expected: the bridge latched the parent's outage; repair once, replay the original `request_id`, and do not read those as fresh failures |

Always report what is proven and the remaining cells/gaps. A clean local test never proves Cursor
Cloud, a neighboring version, regular-profile isolation without a before/after check, provider
dispatch without provenance, or workflow completion without a current receipt.

## Codex subscription evaluator from Cursor

A Cursor policy route may request the service-owned `codex-chatgpt-subscription@1` evaluator, but
Cursor receives no Codex OAuth credential, home, app-server handle, or evaluator tool authority.
Cursor plugin/MCP/hook activation and Cursor model use do not prove that AI-powered review dispatch
happened. A strict Cursor route must return `route_semantic_ceiling` with zero child launch. Follow
the [subscription evaluator runbook](codex-subscription-evaluator.md) and keep host activation,
accepted observation, runtime evidence, privacy receipt, corrective influence, and workflow receipt
as separate cells.

Evaluator runtime retention and repair (issue #855) is host-independent. From Cursor, the prompt
menu, or `/provider`, `finishup provider codex-subscription repair` and `runtime
status|install|remove` behave exactly as documented in the
[subscription evaluator runbook](codex-subscription-evaluator.md#evaluator-runtime-retention-and-repair).
Decision for this host: supported through the shared provider surfaces, with no Cursor-specific
step. Native Cursor acceptance of a post-repair check is pending.
Capability admission of the evaluator's Codex release (ADR-006, 2026-10-13: the newest installed
Codex at or above `0.157.1` that passes the check, adopted by the next `repair` or `setup`) is
equally host-independent; nothing in the Cursor host integration changes.

Fallback endpoint pairing (issue #582) is host-independent: whether the evaluator or a paired
API provider serves a given attempt is a service-side dispatch decision recorded in provenance
(`fallback_from`), with no Cursor-specific behaviour, plugin, or route input — the route ceiling
applies to dispatch authority regardless of which endpoint serves.

Routine/final Codex review budgets (issue #571 item A1) are host-independent too. The service
selects the budget profile from the frozen case: `final` when the frontier carries a completion
claim, `routine` otherwise. It then dispatches with that profile's configured effort and output
limit and records them in provenance. Cursor gets no host-specific behavior, registration, route
input, or per-request selector, so the decision for this host is "supported, unchanged".
Recording a completion claim is the only way a check requests the final profile.


### Structural review progress (#571 A2)

Decision: supported through the shared MCP `status` tool with no Cursor-specific behavior,
registration, or route input. Call `status` with `view: "operation"` and the check request ID while a long review runs; the Cursor route receives the exact canonical JSON copy of the result as text, so `semantic_progress` is visible even when Cursor drops structured content. The phase vocabulary, deadline, and terminal outcome are
service facts, identical for every host; progress never includes provider text, tokens, reasoning,
or account identity. A read from a different session or writer of the same task may return
retryable `BUNDLE_BUSY` while the check runs. This is shared service behavior, not evidence of a
fresh installed native Cursor dogfood run.

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
`semantic_case_capacity_exceeded` mean the required packet could not fit before any provider
attempt. Select a smaller claim/obligation scope for a new check. Shorter prose alone need not fix
structural capacity.

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

The current Cursor MCP surface advertises the read-only `closure_prepare/1.0.0` support tool.
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

Cursor's paired ordinary profile can yield `unpaired_event`, lag, or drain gaps. The post-only
structural profile already resolves historical `unpaired_event`. Decision for this host: supported,
same rule as every host.
The rule is service-side and host-neutral: an observation-authored, non-actionable finding (the
"Observation coverage is incomplete or stale" advisory, including rows written by earlier builds)
never counts in `unanswered_finding_count` or `findings_unanswered`, and acknowledging it once is
optional and never supersedes a recorded check. It stays in `status view=findings` and on the
receipt as a disclosed limitation and does not become resolvable. `refresh_observation` remains
available in operator status and structured advice for recoverable source lag, stale cursors, drain
backlogs, service unavailability, and locked vaults, but it never enters Cursor `postToolUse`
`additional_context`. Hook context carries work advice only. The
shared guidance and this host's skill give the closure order: answer unanswered findings before the
final check (the current status frontier is a valid `finding_frontier`), answer only the findings
that check returns that are still unanswered, then `receipt`, then `work_closed`; no recheck follows
those answers, `work_closed`, or an `insufficient_packet` review without a new repair, while a
recorded repair still gets its re-check. Which conditions raise the advisory, and how the sticky
`unpaired_event` gap surfaces, are owned by issue #917. Verification: shared-path regressions cover
the ledger rule on the memory and SQLite backends; a live Cursor dogfood transcript on macOS, Linux
and WSL 2 is not yet recorded. That gap is owned by issue #911.

### Closure readiness and standing limitations (#913)

Cursor's hooks are post-only: accepted observations carry no synthetic `unpaired_event`. Its
standing set depends on the capture profile and privacy policy: content selection and capture
limits (`content_unselected`, `content_capture_unavailable`, `payload_content_omitted`,
`payload_too_large`), the AI-powered review bounds when a review ran, and
`semantic_review_not_requested` on a local-only route. A finished session whose remaining
conditions are only standing reads `ready_with_limitations`.

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

### What follows the last check on Cursor (tb4n3 RC-6, #1029)

The ordinary profile spells every MCP call `MCP:<tool>` and names no server, so FinishUP's own
calls are recognised by the closed FinishUP basenames (`start`, `publish_work`, `check`, `respond`,
`status`, `receipt`, `read_guidance`, `closure_prepare`). A foreign MCP tool with exactly one of
those names is treated alike; that loses only a later-material disclosure, never a supersession,
and is the cost of the missing server field (a paired `afterMCPExecution` owner would remove it;
follow-up owner: the Cursor ordinary-profile issue). The server-scoped spellings `finishup:<tool>`
and `plugin-finishup-finishup:<tool>` are exact. `Write` is an edit that supersedes a check;
`StrReplace`, `Delete` and any other tool the materializer records as an `other` action, and the
structural profile's `afterFileEdit` / `afterMCPExecution` post-only results (no tool identity),
are `other`: they keep the `check_current_as_of_earlier_frontier` disclosure and never supersede. A
record that names no tool (the structural profile's post-only result of every call, including each
check's own) is `other` too, so on that profile every receipt carries and is bounded by the
disclosure; status keeps it a standing limitation and never asks for a recheck, because every check
would regenerate it.
That is a known Cursor capability gap, shared with `edited_after_last_verification`.


### Inspection check on Cursor (#1048)

`check` with `"mode": "inspect"` is a read inside FinishUP: it records nothing, mints no finding, runs
no review and needs no FinishUP disclosure decision, so a lost answer is answered by asking again with
a fresh `request_id`. One call returns what is left to close (the `status` readiness split, then
every unresolved obligation and finding with what it lacks and whose move it is), the
hook-observed actions since the last check, and whether each obligation's resolution evidence links
to its declared deliverables or requested commands (`evidence_off_declared_items` when it does
not). Use it instead of a series of `status` reads; no status read or `dry_run` is required before
`publish_work`. The startup read is the operating card (`agent-instructions.md`); the larger pages
are read on demand. ADR-047. The mode needs no Cursor-specific step.

Host approval is per tool, not per mode. An inspection is a call of `check`, so Cursor admits it
exactly as it admits `check` ([Auto-review and host admission](#auto-review-and-host-admission)):
with admission (`finishup:check` in `mcpAllowlist`, `Mcp(finishup:check)` or
`Mcp(plugin-finishup-finishup:check)` in `.cursor/cli.json`) it is allowlisted like any `check`;
without admission (always so on the strict route) the classifier may allow, redirect or ask, as it
may for every non-allowlisted call, `status` included, and required startup mode may add native
approval prompts. Cursor publishes no hook for that decision, so a held inspection is visible only
in Cursor's approval control. Decision: supported behind the `check` gate. A held inspection leaves
nothing pending in FinishUP and no review to protect, so the agent reads `status` instead and
continues; the review-hold rules do not apply to it (guidance `review.md`).

Capability gap, same owner as the previous section's (the Cursor ordinary-profile issue): on the
ordinary profile `StrReplace`, `Delete` and other unclassified tools are listed as `other`
actions, and the structural profile's post-only results carry no tool identity, so those runs are
not listed at all; `action_count` counts only what the record holds.

### Guidance delivery on Cursor (tb4n5)

- **Closure trigger in the skill description.** The skill description ends "Also use when a
  FinishUP finding, Stop message or receipt needs an answer", so a host that selects skills by
  description can load the skill again at closure. Decision: supported; whether this host
  re-selects the skill at closure is unmeasured until its dogfood lane runs.
- **Initialize body.** Cursor serves the same compact body as Codex, which adds "Do not list
  resources; read the named topics" and leaves the cadence to the operating card (ADR-047
  amendment). The skill keeps one start sentence that names its antecedent, the card pointer and
  the closure judgment rules; the capacity procedure is the catalogued topic
  `workflow.md#change-local-retention-capacity`. Decision: supported.
- **Page-zero sections.** Cursor does not reliably deliver `structuredContent`, so the list rides
  the text channel: page zero appends it after its end marker (`FINISHUP_GUIDANCE_SECTIONS ...`, one
  `#<anchor> <bytes>` line each). It is outside the page bytes; `GuidancePageAssembler` accepts it
  only there. Decision: supported; the Cursor dogfood lane is pending.
- **Check-cell deadline at closure.** Not applicable: Cursor runs a tool call to completion and
  does not use code-mode `exec` cells. The close instruction is chosen from an observed capability,
  not the host brand, so Cursor gets the neutral sentence and no `yield_time_ms` pragma.

### Bounded workflow recovery examples (#613)

These examples use the existing MCP operations on the pinned local Cursor IDE or Agent CLI cell.
Replace placeholders with values returned by the current call or `sessionStart` context; do not
reconstruct them from memory, a remote URL, or the live store.

- **Read retry.** If a `status`, diagnostics, or `status view=operation` read times out, repeat the
  same read intent with a new read `request_id`. Preserve its view, operation filter, cursor, and
  limit. An unreadable read does not establish that an operation or task is absent.
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
- **Exact-session attach.** When `sessionStart` or recovery context provides a held `session_id`,
  use that exact value as the `mode=attach` selector. Cursor's canonical workspace fence comes
  from `workspace_roots`/`CURSOR_PROJECT_DIR`, not the plugin directory in `$PWD`; if the request
  carries identity refs, include the canonical `workspace_ref` + `external_ref` pair together,
  never `workspace_ref` alone. Use the returned successor `session_id` and `writer_id`, read
  `status`, and continue only from that binding. A bare `task_id` is not an attach selector.
- **Same-pair fresh conversation.** With no held session, call `start mode=create_or_attach` using
  the exact canonical project root as `workspace_ref` and the same stable `external_ref` pair, with
  no `session_id`. The same pair resumes; a different complete pair is independent work, even in
  the same workspace. A remote URL is not a workspace identity.
- **Explicit sibling handoff.** Use `start mode=create` only after same-task pair/session recovery
  is exhausted, every earlier write has a known terminal outcome, the Cursor binding is healthy and
  authorized, and the user has declared one bounded remaining or repaired verification scope. Keep
  the canonical project root as `workspace_ref`, choose a different stable `external_ref` such as
  `<work-item>-recovery-v1`, and bind the native mapping from the exact returned `start` result via
  `afterMCPExecution`/`postToolUse`. Verify `mapping_present` and the returned task/session/writer,
  then publish fresh plan, evidence, checks, and receipt for that scope. State that the predecessor
  receipt, findings, obligations, evidence IDs, and unresolved status remain separate; the sibling
  cannot make the predecessor look resolved. If no new scope exists, keep the old receipt and stop
  instead of creating another sibling.


## Observation recovery diagnostics

Cursor uses the shared selected-admission and outbox store. New native input obeys current hard
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
tool and file-edit events (5-second host timeout), 7 s for sessionStart and stop (10 seconds)
and 2 s for sessionEnd (3 seconds); each wait
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

The native Cursor profile repeats the exact canonical JSON wire body in text `content`, matching
`structuredContent`. Both channels carry `safe_details.continuation` when present; the consumer
must resolve that token separately. Cursor does not use the bounded summary renderer and receives
no additional summary fields or registry-resolved directive projection. The canonical body still
includes the public error's wire `message` field.

One host-specific fact already applies and is unchanged by ADR-030: the bridge does not carry
`authorize_command` to Cursor, because Cursor is never an agent-chat attestation client. The
canonical body carries only the commands admitted for that host, so it omits the authorize step
rather than naming a command the host cannot use.

### Project selectors in the Agent CLI (0.2.3)

New project registrations store the exact validated absolute project path. Cursor Agent CLI
2026.09.18-9a7762b passes the IDE placeholder literally, so a placeholder registration fails
before the bridge can initialize. Existing placeholder entries remain recognizable and valid
for IDE clients that expand them; an accepted install preview upgrades them in place. Moving
a project requires a new registration preview. The absolute selector only chooses among the
native client roots: it never replaces roots/list or relaxes the ownership and session fences.


### Explicit Agent CLI registration

Agent CLI clients that do not supply MCP roots/list use an explicit project binding. Preview it
with the intended installed launcher:

```text
finishup integrate cursor project-mcp preview --project-root /absolute/project --cursor-config-root /absolute/cursor-config --project-binding registered-project
```

Review the named project, launcher, instance and route. Apply with the same arguments, replacing
`preview` with `install` and adding `--accept --preview-digest <exact-preview-digest>`. Preserve or
explicitly choose the existing policy/strict route; this mode grants no content or review egress.
Restart the CLI MCP connection, enable the project source if the host requires it, and verify a
native `start`, not just `mcp list`. Model-provided paths and hook CWD do not select the repository.

Use `--project-binding mcp-roots` in a new accepted preview/install to return the entry to desktop
root binding. Omitting the option preserves the mode of an owned entry. `status`, `preview-remove`
and accepted `remove` remain supported. Moving/replacing the project or editing/replacing its
MCP registration retires the serving process and requires a new connection.

For a returned start error with `start_busy_same_identity`, the reservation remains durable and
only its fenced lease was yielded. Replay the exact start body and request ID once, without
inventing session or writer IDs. `start_pending_same_identity` instead means a live lease remains:
wait up to 60 seconds before the one exact replay. If still busy or pending, retain the original
request and report the unresolved start. These continuations do not authorize a new task.

**CLI JSON (issue #741).** When an agent in this host runs `finishup` in a shell with `--json`, a
CLI-owned JSON error body carries a `recovery` object resolved from the same registry. A workflow
command (`start`, `publish-work`, `check`, `respond`, `status`, `receipt`) also prints JSON when
stdout is not a TTY; its failure keeps the exact wire body on stdout and writes the directive
lines to stderr. This is CLI behavior shared by every host; no Cursor-specific behavior is
configured.

**Provider outcomes (issue #742).** A check whose AI-powered review failed resolves through the
same registry (`continuation_for_semantic_outcome`). Cursor's native MCP profile repeats the
canonical JSON body and does not use the bounded summary renderer, so the consumer still
resolves the check's `semantic_reason` and optional `failure_class` through this section. CLI
check output in this host shows the directive. Hook advisories never carry that token;
SessionStart's vault-locked advisory appends its own `vault_unlock_required` token after the
host-specific prefix (issue #739). No Cursor-specific recovery wording is configured.

**Bounded text (ADR-043, issue #1025).** The Cursor route receives the exact canonical JSON copy of
the result as text, which is not subject to the 4,096-byte summary bound and cannot fail to render;
if the copy ever could not be encoded, the bounded summary (with `summary_render_failed:...` named)
is returned instead. `closure_prepare` draft phases echo only the selected inventory rows on this
route as on the others, which keeps the canonical JSON copy inside the MCP frame at a long-run
frontier. Hook `additional_context` and `followup_message` over FinishUP's own 2,000-character cap end
with a cut marker (the cap is FinishUP's, not a documented Cursor limit).

## Post-compaction recap (issue #1027, ADR-044)

Decision for Cursor: **not supported here.** The certified profile (cursor-ide-3.17.8) registers
`sessionStart` once per conversation and documents no post-compaction event or context channel.
`sessionStart` is fire-and-forget (the agent loop does not wait for the hook), so even a start that
fired would not be guaranteed to land before the agent's next action. The agent re-grounds with
`status` and its held ids as before.

The shared observe pass is source-driven: if Cursor's `sessionStart` reports `source: compact` (the
wrapper maps it to `cursor_session_compact`) it composes exactly the recap Claude Code gets, within the
same bounds, and a hook-level test covers that path. There is no live Cursor evidence for it.
Follow-up: re-read Cursor's hooks reference for a post-compaction event with an injection channel
(a `preCompact`/`postCompact` hook with `additional_context`); if one exists, add it to
`CURSOR_ORDINARY_HOOK_EVENTS` and certify it before claiming support.

## Cold service attachment and recovery (issue #670)

Cursor sessionStart returns the shared result through Cursor's `additional_context` contract,
within the existing ten-second registration budget. Tool hooks keep their five-second budget.

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

With the ordinary content profile enabled, Cursor `Write` calls (Cursor's reported file-edit tool)
enter the shared encrypted capture lane as changed-file content from `postToolUse`; only the public
path and replacement fields (`path`/`file_path`/`target_file`, `contents`/`content`,
`old_string`/`new_string`, `edits[]`) are kept, and the JSON `tool_output` is not. A
`postToolUseFailure` marks the edit `failed`. Shell heredoc edits (`cat > path <<EOF`, `tee path
<<EOF`, `git apply <<EOF`) are also captured from the `postToolUse` `Shell` event as changed-file or
workspace-diff content, marked `edit_source: shell`; edits made by `sed -i`, scripts or `git apply
<file>` are not captured, but the check-time change below still shows their result. Separately, the
hook gives a `Shell` command that visibly writes the workspace `write_scope: workspace`, so the
stale-verification rule counts it as an edit, as for `Bash` and `exec_command` (ADR-045).

`afterFileEdit` is deliberately not subscribed by the ordinary profile. Cursor's hook reference
names `Write` as the file-editing tool on the generic `preToolUse`/`postToolUse` pair (and uses the
same `Write` matcher value for `afterFileEdit`), and `tool_input`
there is the tool's complete argument object (the object `preToolUse` may replace through
`updated_input`), so it carries the path and new text. The generic pair is the single paired owner
of each call; `afterFileEdit` has no tool-call identity, so under the paired ordinary profile it
would be an orphan (`unpaired_event`) and a second copy of the same edit. The documented
`afterFileEdit` body (`file_path` plus `edits[]`) is parsed by the same content rule, and the
structural profile keeps only its path commitment. Cursor does not document the `Write`
`tool_input` field names; the adapter accepts `path`/`file_path`/`target_file`,
`contents`/`content`/`code_edit`, `old_string`/`new_string` and `edits[]`. A `Write` call whose
input has none of these keeps its structural row but no edit content.

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

The directory is the one the check's own connection named: the workspace root the FinishUP MCP bridge
selected (`workspace_roots`, then `CURSOR_PROJECT_DIR`), or the working directory of `finishup check`.
The service reads that directory only when it resolves to the task's own repository, and never runs
a shell, hook, filter, external diff, credential helper or network transport. The task-start commit
is recorded when `start` creates the task. A task created before this version, or from a connection
that named no workspace, has none; its first check pins HEAD as the task's base, later checks diff
from that commit so work committed between checks stays in the change, and each such check reports
`check_time_change_base_unavailable` because work committed before that first check is not in it.
Because the ordinary profile does not subscribe `afterFileEdit`, this is how every Cursor edit
reaches review; it needs no hook at all, so MCP-only Cursor on macOS gets it too. The capture
honours the review recipe and privacy policy like any other excerpt, as `repository_excerpt` items:
a policy whose inference channel does not allow that category never sends them, and the check
reports `semantic_review_context_withheld`. Credential-like spans are redacted first
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
this host are Cursor `Write` changed-file captures under the ordinary profile (a whole capture or a
hunk-sized byte range of it) and shell heredoc captures. The follow-up owner is issue #912.

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

Cursor project setup, hooks and MCP use the shared project-root rule (ADR-007, 2026-10-14): a
non-root user may use a root-owned project root that no other account can write, or a sticky one.
Files FinishUP writes inside the project must still be the user's own. Verified for Codex in a Boat
container as `nobody` and `agent`; the same check path is unit-tested for this host.

**Runtime another account installed.** Decision for Cursor: same path as every host (shared entry
and setup code; no host-specific change). A runtime root installed and a non-root user runs stops
`finishup mcp serve`, `service run` and every hook with `release_runtime_not_owned` (exit 20) instead
of `release_runtime_unavailable: permission_denied` or "could not be verified". Cursor lists the MCP server as failed and keeps its stderr in the MCP log; its hooks exit 20 with no stdout, so they make no allow or block decision and Cursor proceeds with the action. Terminal
commands print the `.<prefix>-releases` directory the user must own; hook stderr carries the token
without local paths. Every connect path refuses to connect Cursor to such a runtime (or one another
account can write) with that reason and leaves status and disconnect available. `finishup instance create --bind-runtime` on such a runtime
is `runtime_pin_unwritable` and keeps nothing, so a retry after the repair succeeds (ADR-028,
2026-10-14 amendment). Install FinishUP as the user, or see the Linux runbook for the one-user
`.<prefix>-releases` layout. Verified on Linux as `nobody` against a root-owned runtime (entry and
hook paths, not a Cursor session); the Cursor connect refusal is unit-tested.

**Review fixes (independent review of #1071).** Decisions for Cursor: (1) a checkout root made
(`/app/.git` owned by root) is the project, used as a plain directory, through the shared
workspace binding (same path as every host); (2) Cursor-specific: project MCP status, preview and
apply now judge the project root by the project-root rule on the read path too (before, only the
write path did, so status, preview, connect and disconnect refused a root-owned project with
`cursor_project_mcp_target_unsafe`); the Cursor configuration root and the project `.cursor` stay
the user's own; (3) host admission never writes `.cursor/permissions.json` or `.cursor/cli.json` into a
`.cursor` another account created or others can write (same path as every host; refined in
round 2 below). Covered by tests through the public status/preview/apply functions and
the connect, disconnect and reconnect composition for Cursor IDE and Agent CLI, with simulated
ownership.

**Review fixes, round 2.** Decisions for Cursor (same path as every host unless named): (1) a
checkout root made (`/app` and `/app/.git` root-owned), or the user's own `git init` in a sticky
root-owned `/app`, now passes the service handshake: the service commits the plain directory
identity without running Git (Git refuses another owner's checkout), so hooks and MCP attach;
Git-based change capture reports `unsafe_root`. A root-owned `.git` file with more than one link
is not trusted. (2) A `.cursor` root committed to the image is read normally: admission status is
`absent` (typically) and host admission's own reverse sweep (the privacy ceremony) reports nothing to remove instead of `write_failed`; a
grant into it is refused `target_unsafe`. A `.cursor` another account made, or one others can
write, is `unknown` (`folder_not_owned`) in status and refused by grant and revoke; writes to
`.cursor/permissions.json` and `.cursor/cli.json` go through the host folder pinned by descriptor, never a link swapped in after the
check. (3) `setup run --host cursor-ide|cursor-cli` and the full-screen interface's `/connect` refuse before any registration is written. Covered by tests through the public paths with simulated ownership, and the
repository identity with a real Git checkout owned by another uid.

**Review fixes, round 3.** Decisions for Cursor: (1) the plain directory identity of a root-built
checkout is now its top's (the directory holding `.git`), the same from any subdirectory, so a
session started below the top meets its own hooks instead of `repository_identity_mismatch`
(same path as every host). (2) Check-time change capture reports `unsafe_root` for such a
checkout; the receipt reads "the repository failed a safety check (a link, another owner, ...)",
not "not a Git repository" (same path as every host). (3) `integrate cursor plugin preview|install` (install or replace) and `integrate cursor project-mcp
preview|install` now refuse a runtime that cannot serve this account with exit 20 and the token,
before any write; removal, its preview and status stay open. Known gap: a `.cursor` root committed
to the image is refused `target_unsafe` by project MCP status, connect and disconnect (they
require the user's own `.cursor`); have root make it the user's (`chown -R <user>
<project>/.cursor`). Follow-up: let status and removal read a root-owned `.cursor` no other account
can write.

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

Decision for Cursor: supported, service-side, identical on every host. The reviewer instruction, the
packet ranking (since #1108 the change's reserved share first, then task inputs within an eighth of
the excerpt room, the verification oracle, FinishUP's summaries of binary inputs, redundant captured
edits yielding to the latest verification) and the digest-only alias are composed by the service
from the ledger and the check-time read; Cursor needs no host step and nothing new is captured from
it. `admitted_input_roots` is a field of the current repository's privacy grant: `finishup privacy
input-roots add <dir>` is a widening that applies only after the trusted-terminal decision, `remove`
is an immediate tightening, and `status`, `finishup privacy show` and `/privacy` show it. Cursor
sessions, MCP tools and hooks have no write path to it; an agent learns from the review guidance
that only the owner can admit a folder. No Cursor capability gap. The consent-gated local copy of
each outbound packet is not part of this change (#1085).

## Reviewer instructions and packet order (n7, issue #1108)

Decision for Cursor: supported, service-side, identical on every host. A tool output a Cursor hook
captured reaches the reviewer behind `[FinishUP: observed output captured by a host hook (evidence
<evd_>)...]`, which the instruction treats as a witness; FinishUP's own records (an approved check's
result, an import report) carry their own labels; the agent's disclosures travel in one
`agent-disclosures` row marked as its assertion; and the packet lists the task, the change, task
inputs and observed output before the agent's account. Nothing is captured from Cursor beyond what
its profile already captures, and no host step changes. The label's run clause (command action,
host-reported outcome, exit status) appears only when the hook recorded both the action and its
result with a keyed `omitted:hmac-sha256:` command identity equal to the capture's. That identity
comes from the post-tool command context the hook keeps only for runs FinishUP classifies as test,
build, lint or typecheck, as on Codex; any other command's output gets the bare label, without the
run clause. The run clause has no Cursor host-payload test yet: the native capture test proves the label for Cursor tool
output, and a hook-recorded run with the keyed identity takes the same service path as on Codex, but
that parity is unproven. Open follow-up, owned by the workstream issue #1108: a Cursor host-payload
test of the run clause.

Issue #1102 (same decision for Cursor, service-side, no host step and no new host payload): a
directory the task names inside the repository reaches the reviewer as FinishUP's listing of its
unchanged files plus the members most likely related to the change (sharing names with it, or beside
the changed files); a quoted or escaped path with spaces is one candidate, and when only the disk
can tell a spaced folder from prose the whole path is looked for before its words; an admitted
outside directory named without a trailing `/` is listed; an `other` follow-up request is answered
only from rows FinishUP recorded for the run or edit it names. When the task names a file or folder
outside the workspace that no admitted root covers, the check records
`task_input_outside_not_admitted`, whose fixed sentence names the owner's step
(`finishup privacy input-roots add <folder>` on a trusted terminal); it is a disclosure only, never
a Stop-gate item or a continuation on Cursor. Cursor still has no write path to admitted roots,
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

Decision for Cursor: supported, service-side, identical on every host. `credential_heuristic` is a
field of the current repository's privacy grant that the service applies only to external
AI-reviewer egress; agent-context projection and the local model keep the filter. Cursor needs no
host-specific step and gets no write path: `finishup privacy credential-heuristic disable` is a
widening that applies only after the trusted-terminal decision (walking the grant-creation
ceremony when the repository has no grant), `enable` is an immediate per-repository tightening,
and `--machine-default` moves only the default for new grants. MCP `status` carries
`credential_heuristic` (`repository`, `machine_default`) before any check; MCP tools and hooks can
only see the setting (status, the `semantic_review_credential_heuristic_disabled` check gap, the
external receipt's `secret_scan.credential_heuristic`). No Cursor capability gap.

## Privacy receipts listing (issue #921)

`finishup privacy receipts list` and `get` are host-agnostic: every host's sessions write receipts
into the same local audit, and the operator reads them through the same CLI and control method.
Pages over 64 KiB now cross the local control socket in bounded chunks, an unreadable stored
receipt is skipped, counted and named (exit 40) instead of failing the page, and a store-side
failure is `privacy_audit_unreadable` rather than `invalid_request`. In-process tests drive the
real service, socket and client. Open evidence gap, owned by #921: a dogfood run on Cursor
(macOS, Linux and WSL 2) that completes an AI-powered review session and then shows that
session's `network_egress` receipts in `finishup privacy receipts list`.

## Status page cost (issue #916)

`status` pages and `closure-prepare` no longer pay ~18 ms per returned row: the shared service,
control and bridge path decides schema validity without rebuilding diagnostics for valid results,
with byte-identical pages and receipts. This host uses that path unchanged. Its per-host dogfood
timing on macOS, Linux and WSL 2 is not yet measured; issue #916 owns it. See
[status render performance](status-render-performance.md).

## Hook schema loading (issue #1083)

A Cursor hook process no longer builds the full schema catalog before its first control frame.
It parses only the control envelopes' schemas and their `$ref` closures, 92 of 232 documents,
with the same verdicts and errors ([interfaces](../INTERFACES.md)). Unchanged on this host:

- `hooks cursor-observe` and `hooks startup-context --host cursor`;
- hook registration, payloads, outputs, recorded events, ordering and timeouts.

Host decision: supported, same code path.

Latency: the #1083 replay drove 4 preToolUse and 3 postToolUse ordinary-profile callbacks from the
repository's recorded shapes through the build before and after the change on macOS arm64 (single
idle machine, shipped launcher). The median preToolUse fell from 1,926 to 1,284 ms and postToolUse
from 2,002 to 1,388 ms. Linux and WSL 2 timings are not yet measured; issue #1083 owns them.

Equivalence: the #1087 replay proof ([test instances](test-instances.md)) replayed the 13
ordinary-profile callbacks, and 9 malformed payloads, on Linux x86_64 on 2026-10-17 through the
merged predecessor (`0.3` at `c0198bb16`, with #1080 and #1086) and this change's head
(`ea1f6eda4`). Every exit code, stdout and stderr byte, drain, status read and ledger event with
its full payload compared identical after the normalization that runbook describes, which matches
run-generated values, such as task, session and result ids, one-to-one: 157 compared parts in the
Cursor workspace, including 13 ledger events. In the new build 7 of those callbacks parsed only
their schemas and none built the full catalog; the old build built it in the same 7. A second
replay of the new head compared identical with the first. One `postToolUse` payload carries no
exit code, so its result reads "(workspace unverified)" in every run.
The MCP bridge (`mcp serve --host cursor`) is not replayed: it builds the full catalog as it starts,
so its validation is unchanged by this change.

## Expanded excerpt count (issue #907 Phase 1b)

Decision for Cursor: nothing is host-specific, and the behaviour is identical on every host and OS.
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

Decision for Cursor: supported through the agent-supplied field, identical on every host and OS.
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

Cursor's structural adapter discards prompt text before local storage, and FinishUP does not keep `beforeSubmitPrompt` text. This is the parity path: Cursor uses the agent-supplied statement exactly like Codex and Claude Code. Keeping `beforeSubmitPrompt` text under the same consent rules (Expanded profile plus an explicit, off-by-default prompt-capture choice) is a follow-up owned by the Cursor adapter, tracked from issue #908.

Host-captured prompts (`host_captured_user_prompt`) are not used on any host in this version:
captured prompt text never enters the packet, and the Expanded-only, explicit prompt-capture
choice that would allow it is still open on issue #908.

Automatic attach does not record a task statement. The shared observation hook opens the task
with a generic title and no `task_statement`, so until the agent calls `start` with the user's
request the reviewer sees at most that title (`task_title_only`), and the receipt says so.
Recording hook text there would label it `agent_transcribed`, which it is not, and would bypass
the prompt-capture consent still open on issue #908.
For Cursor the structural adapter discards prompt text before local storage, so an attach has
no prompt to record.

### Tool-call records and orphan notices (#917)

Cursor's installed profiles are post-only: `postToolUse` and `afterMCPExecution` records are
byte-identical after #917 (pinned by a replay of real payloads), and generation-only posts stay
metadata evidence without `unpaired_event`. The opt-in ordinary profile
(`cursor-ordinary-observation-v1`) is on the conservative paired contract, so a paired pre and post
share one action and an orphan scope yields one informational notice rather than a recurring
advisory. Cursor has no code-mode cell, so the stream wrapper rule does not apply; for the same
reason the tb4n5 yielded- and tool-less-cell decisions (ADR-029 amendment of 2026-10-13) are
Codex-only, and Cursor has no `clock.sleep` tool (the `clocksleep` no-activity spelling is Codex's
hook name). The same amendment's rejected-call record is host-agnostic: on the paired ordinary
profile, a pending `yoetz:*` (or `MCP:*` FinishUP-basename) attempt whose call FinishUP's MCP server
answered with an error closes as `rejected_by_yoetz` after a 5 s grace (at once when the session
ends or its generation advances). The Cursor adapter commits to the call (tool, FinishUP session,
writer and `request_id`, or for a `publish_work` sent without one its canonical arguments; nothing
else) from the hook's `tool_input` before structural normalization drops it,
and passes only that commitment on; a body too large to keep its `tool_input` keeps the ordinary
expiry; `observe status` names
every ending under `pending_attempt_endings`, and local ring eviction is `local_retention`, never
`truncated_payload`. Post-only profiles keep no pending attempt, so nothing changes there. The hook
drain diagnostic `drain_budget_exhausted` is renamed `drain_pass_delivered_nothing` and `observe
status` reports the outbox `delivery_lag` (enqueue to acceptance) for Cursor hooks exactly as for
Codex (ADR-022 amendment of 2026-10-13).

### Limitation requests, `reopened` and one dialogue per concern on Cursor (tb4n3 RC-1 and RC-7, #1024, #1030)

Host decision: supported, no host-specific code. The change lives in the shared kernel, `respond`
and review paths (ADR-034 and ADR-040 amendments of 2026-10-11), so Cursor behaves exactly as the
other hosts. The stop hook and the MCP `respond` tool take the shared path; a Cursor session sees the same `respond` description and the same `closure_after`. What a Cursor agent can rely on:

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
check, respond, status and receipt operations with a compliant reviewer; a live Cursor transcript on
macOS, Linux and WSL 2 is not recorded for this change.

### Call-schema traps on Cursor (tb4n4, #1049)

Host decision: supported, no host-specific code. Every change lives in the shared protocol request
models, the MCP bridge's `read_guidance` dispatch and error hints, the status text and the kernel's
`command_attempts` rule, so Cursor takes the same path as the other hosts. What a Cursor agent can rely on:

- `decision_recorded` carries no id of its own; a `decision_id` in its payload is accepted and
  ignored (never recorded, and a retry with or without it replays the same request).
- A `status` `limit` sent as a JSON integer from 1 to 100 is read as its decimal string.
- A `read_guidance` anchor that names exactly one catalogued topic of its document (the heading's
  slug, an explicit anchor beside it, or words only that anchor contains) reads that topic; the
  result's `uri` is the catalogued one. An ambiguous or unknown anchor is still refused with the
  document's anchors, unless it is exactly the catalogued anchor of one other guidance document
  (n7, #1103; see below).
- A resolution without `resolution_evidence_refs` (omitted, empty or the wrong id kind) is refused
  with the sentence that says what the list holds; the recipe sentence rides the bounded status summary, which Cursor does not render (its text channel is the canonical JSON body), so a Cursor agent reads the same recipe in `request-templates.md#publish-work-plan-plus-obligation` and in that refusal.
- A run linked to a requested command with a `command` action (the PL6-3 link) is a disclosed
  equivalence: it reads `command_attempt_uncorroborated`, never `command_attempt_mismatch`, and a
  `self_verified` refusal on a remaining `command_attempt_mismatch` names that link as the exit.
- A `result_recorded` payload's `evidence_refs` still names evidence ids only; the refusal for a
  `res_` id names where a result id goes.

Verification: `tests/unit/mcp/test_tb4n4_call_traps.py`, `tests/unit/kernel/test_tb4n4_command_link.py`
and `tests/integration/application/test_tb4n4_decision_id_replay.py` replay the recorded shapes
through the bridge validation, `read_guidance` dispatch, the kernel and the real publish operation;
the tb4n4 exports themselves were not replayed, and a live Cursor transcript on macOS, Linux and
WSL 2 is not recorded for this change.

### Avoidable MCP rejections on Cursor (n7 RC3, #1103)

Host decision: supported, no host-specific code. Every change lives in the shared publish and
respond request models, the `respond` and `receipt` applications and the `read_guidance`
resolver, so Cursor takes the same path as the other hosts. What a Cursor agent can rely on:

- A `claim_recorded/1.1.0` draft may leave out an empty `limitation_refs` and
  `supersedes_claim_refs`, and a plan beside `no_obligations_reason` an empty `obligation_refs`.
  Each is the empty list: one request, digest and stored payload with the explicit `[]`, and not
  named in `server_filled`. It is judged like an explicit `[]`, so a completion claim that leaves a
  live failed, partial or unknown result out is still refused (`limitation_refs_complete`).
  `supporting_refs`, a revision's `obligation_changes` and evidence `observed_at` stay required.
- A `respond` answer may list its `evidence_refs` in any order: the request model sorts it before
  the schema check, so it is the same request as the sorted list. The service also drops a
  repeat, but the advertised schema keeps `uniqueItems`, so send each id once.
- A refused `respond` payload is `INVALID_REQUEST` with `safe_details.reason_code`, a `field`
  pointer from a frozen table and a continuation (`input_correction_new_identity` unless the
  reason maps its own), and its message states the rule. On Cursor, the text channel is the
  canonical JSON copy of the body, so the agent sees `safe_details` and the message, rule
  included.
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
`tests/unit/mcp/test_tb4n4_call_traps.py`; the n7 exports were not replayed, and a live Cursor
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

Owner-view presence decision for Cursor (#1073): same path as every host, because the owner view is
a CLI and terminal-interface flow, never an MCP tool or hook. On macOS the service itself raises a
LocalAuthentication dialog (Touch ID or the login password) showing the confirmation code the
command prints, on either vault mode, including setup's system-keychain choice. A vault passphrase
the owner chose is asked for once when the service cannot show a dialog, or directly with
`--use-passphrase`; a passphrase kept in the system credential store is never prompted for on its
own. On Linux and WSL 2 there is no presence provider: only a vault passphrase the owner types
completes it, and a vault without one, or with one kept in the credential store, fails closed with
`owner_view_unavailable`. When Cursor's agent runs the command in a pseudo-terminal, the dialog
appears on the owner's screen and the agent cannot answer it; a cancelled dialog is
`owner_view_refused` and shows nothing, and repeated dialogs back off. Without a terminal the command
ends with `owner_view_requires_terminal` before any dialog. If an agent's own ceremony is open, the
owner's command reports `owner_view_busy` with its own code, and any dialog on screen is not the
owner's. The dialog itself is covered only by stub-helper tests until
the manual check in [test-instances.md](test-instances.md#owner-view-with-touch-id-manual-check-on-a-real-mac-1073)
runs on a real Mac.
## Per-task review mode and agent opt-in (ADR-049)

**Decision for Cursor: supported, the same MCP path as every host.** A task starts with local
checks under the owner's recommended setting (`conversation_review = local_agent_opt_in`); the agent
turns on AI-powered review for its own task with one `publish_work` draft, `decision_recorded`
version `1.1.0` with `review_mode: "ai_powered"` (`"local"` turns it back off), and then checks
without `mode`. `check` and `status` carry `review_mode`; the receipt names each switch. Guidance:
`finishup://guidance/review.md` (when to turn it on, when to stay local, the exact draft). Nothing
Cursor-specific is involved: no hook, skill or registration field changes.

- **Owner setting.** `finishup privacy conversations agent-opt-in|owner-approval|local-only|ai-powered|status`
  for the current repository; first-run setup records it from its three answers. Owner approval
  makes each review the agent turns on wait for `finishup privacy decide-disclosure`, the same
  `awaiting_human` path as **Ask every time**.
- **Route.** Every interactive setup answer now registers the policy route. A registration made by
  an earlier local-only setup is on the strict route: an opted-in task there (or any task under
  "every task") runs local with `route_local_only`, and the check prints the fix,
  `finishup setup run --route-profile policy`; the Cursor form is
  `finishup setup run --host cursor-ide --route-profile policy` (`--host cursor-cli` for the Agent
  CLI). Then start a fresh Cursor session. Non-interactive setup keeps the strict default for a
  fresh registration. Cursor keeps the route in each project's own MCP entry, so another project
  of the same configuration root keeps its route (#1058).
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
  `/connect` for Cursor (IDE or Agent CLI) now runs the chosen answer's setup after connecting, as
  first run does (it asked the question and dropped the answer before).
- **Other repositories (review round 2).** A fresh install's first repository grant gives the
  installation row the hybrid (or the narrower answer), so another project or an independent clone
  starts local; a repository without its own privacy grant reports "AI-powered review is not set
  up for this repository" (`ai_review_available` false) and an opt-in there records
  `ai_review_not_set_up` until the owner approves that repository's grant (terminal or chat; a chat
  grant starts on the same first-grant default). Installations whose row already sent work keep
  the released repository-grant handoff.
- **Agent-driven setup.** Preview with `finishup setup run --host cursor-ide --route-profile
  policy --non-interactive --json` (`--host cursor-cli` for the Agent CLI) for every answer;
  without `--route-profile policy` a fresh non-interactive registration is strict and every task
  stays local (`route_local_only`).
- **Round 3.** In a repository without its own grant, `finishup privacy conversations
  agent-opt-in` (or `owner-approval`) walks that repository's privacy grant with the setting
  included (a local terminal is required; otherwise `local_terminal_required` and the command
  names `finishup --privacy`). With a reviewer bound, `finishup --privacy` lists the AI-powered
  review options (Assisted review by default) on a first grant and under agent opt-in or owner
  approval. Switching back to local after the closing review costs one more closing review
  (`review.md` says so). The MCP receipt summary's review-mode pointer is JSON-receipt only.
  Same path on Cursor (IDE and Agent CLI); no host-specific change.
- **Round 3 verification.** A first Private grant in a repository reads as local only (an explicit
  `local_only` where it inherits an earlier repository's hybrid). `finishup --privacy`'s
  AI-powered review listing words Assisted review for the route: on a route without reviewed
  data-use terms it is the default, not recommended, and its draft records no evidence
  requirement. Where the released carry-forward is pending, status says the installation's earlier
  permission is carried forward when a task first starts in the repository.
  Same on Cursor (IDE and Agent CLI).

## Setup refresh and suggested reviewer model (FinishUP 0.3, #1067)

Decision for Cursor (IDE and Agent CLI): supported. The shared setup path changed, and every
item below applies on macOS, Linux and Windows through WSL 2.

- **Plan summary.** The connection preview describes each change in a plain sentence, as Codex
  plans already did; the plan body's change tokens and its digest are unchanged.
- **Choosing a Cursor surface.** When both Cursor surfaces are present and none is named, the
  next step says to rerun with `--host cursor-ide` or `--host cursor-cli`.
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
sandbox walk had no macOS keychain), and no native Cursor IDE or Agent CLI session was recorded
for it.

## Pristine skill and rule upgrades across releases

Cursor delivers skills and rules as members of its managed plugin artifact rather than through the
Codex project-skill installer. Both portable and native projections validate the complete tree
against its own installed marker. An intact earlier portable tree is `portable_managed`; a native
one can report managed drift (`modified` with a valid marker). The connection permits marker-valid drift through its conflict check, and its reviewed replace
accepts these owned older trees and installs the current artifact. User edits invalidate the marker
and remain protected. No Codex-specific warning or overwrite flag is needed on Cursor.
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
PR #1080 round 5; ADR-033). Under the ordinary observation profile, the Cursor `preToolUse` and
`postToolUse` hooks fingerprint the workspace around every `Shell` call and every other tool except
FinishUP's own (in either spelling: the ordinary profile's generic `MCP:<tool>` for a FinishUP tool
basename takes no snapshot either, #1091 N6), native reads, edits and planning or web tools, and the
post envelope carries `workspace_effect`. A call without its `preToolUse` pass, or whose result
states no outcome, stays material. Host decision (n7 RC1, #1105): no change to the completion rule;
a `Shell` `postToolUse` without `exitCode` (#1091 N4) keeps its current reading until a payload
capture shows what Cursor sends, so it is not absorbed here. The structural profile
(`afterFileEdit`, `afterMCPExecution`) observes no shell calls. An unchanged command (`date -u`,
`rg`, `sed -n`, `git status`, a FinishUP CLI read) does not re-arm the closing review; a command
that changed the workspace does, and so does one whose effect FinishUP could not establish, which
the Stop text says. A command that backgrounds or detaches a process (`cmd &`, `nohup`, `setsid`,
`disown`, an `&` handed to `bash -c`, `eval` or `ssh`) is never established, because it may write
after the call ends; a quoted `&` in an argument of a program FinishUP knows does not run its
arguments or stdin as code in the form given (`curl 'h?a=1&b=2'`, `sed 's/x/&/'`, `rg 'a&b'` without
`--pre`) is not a background launch, while `sudo`/`doas`, `wget`, shells, interpreters, other
code-running programs, a wrapper or assignment in front of the program (`env -S`, `LD_PRELOAD=`,
`PATH=`), ANSI-C quoting (`$'...'`) and any `#` or `<<` in the text (a quote in a comment or
here-document body is one bash ignores) keep the cautious reading (#1089). Round 6: neither is a
call whose exit leaves a process it started still running in the project (a launcher whose
new-session child keeps working, with no background word in its text): before comparing, the
post-call hook reads the process table (`libproc` on macOS, `/proc` on Linux and WSL 2) for a
process of the same user that started during the call, is no longer parented by the host, and has
its working directory or a file open for writing in the project; one found, or a process table that
cannot be read, makes the call unverified. A directory that gains or loses an entry while it is
being compared does too. A pre-call snapshot that could not finish before the host stops waiting is
never stored, and the 0.75 s bound covers the whole pass, hashing included. Verification runs (test,
build, lint and typecheck runners, and the task's requested commands) and package installs stay
material whatever the workspace shows. The workspace is everything under the project root, ignored
files included; inside VCS metadata only the internal churn (objects, refs, reflogs, the index and
lock files) is skipped, so `git status`, a commit or a branch stays unchanged while a `.git/config`
or hook edit counts; `node_modules`, `.venv`/`venv`, `.tox`/`.nox` and tool caches are compared at
their first level (files by content, subdirectories by identity); `__pycache__` bytecode is skipped
but any other file there counts; FinishUP's saved receipts and state are skipped. A task that
declares a delivery inside the project where the comparison does not reach it (a VCS store such as
`.git/objects` or a skipped bookkeeping file such as `.git/HEAD`, below the first level of a
dependency environment or tool cache, `__pycache__` bytecode, a saved receipt) gets no unchanged
command; a declared `.git/config`, `.git/hooks/*` or `node_modules/x.js` is compared and does not.
Effects outside the root (databases, `/tmp`, the network, a deliverable path outside the root,
judged against the task's absolute `workspace_ref`) are out of scope, as before. `finishup observe
status` names a degraded comparison once as a `workspace_fingerprint_<reason>` diagnostic
(`too_large`, `timeout`, `unreadable`, `root_unusable`, `store_unusable`,
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
so Cursor takes the same path as every other host. What a Cursor agent can rely on:

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
- Cursor's native plugin copies the canonical result JSON into the text channel, so
  `server_filled` and the minted ids reach the model unchanged; the minted-id line of an id-less
  error, and the earlier id a repeat refusal names, are separate text blocks. The project-local MCP route uses the same bridge.
- The startup gate hook never sees a minted request id before the call, so in required startup
  mode an id-less `publish_work` is admitted with no pre-call ticket. Its ticket opens only when
  `afterMCPExecution` carries the structured result naming the minted `request_id`, and minted
  event ids are matched by position in `accepted_events`; a sparse first plan still releases the
  gate. An id-less publish whose error or reply does not reach that hook as a structured result
  holds no ticket, and a concurrent delegate's tool can pass while one is in flight (each tool is
  still live-probed against the current accepted plan); whether Cursor delivers an error's
  structured result there is not verified in this repository. The agent retries by the minted id
  the error names, which takes a ticket again. Owners who need fail-closed tracking have agents
  send their own `request_id` ([required startup](required-startup.md)).
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
MCP unit suites exercise the shared path. A live Cursor session on macOS, Linux or WSL 2 is not
recorded for this change; native Windows is not claimed.

### Verification recognition (n7 RC2, #1106)

Host decisions for Cursor:

- **Patch-then-test commands.** Shared classifier: a `Shell` command that applies a heredoc patch
  (`git apply <<EOF`, `patch -p1 <<EOF`) and then runs a test is a verification run even when
  the patch body holds an odd quote, and the patch is a write of the files its diff headers name.
  Supported.
- **Stream-first calls and hook outcome corrections.** Not applicable: Cursor has no second
  (session-stream) copy of a call, so its hook copy is the only record and keeps its own identity
  and outcome.
- **Documentation edits.** Cursor file edits and `Shell` writes of only project documentation
  (README, changelog, `docs/*.md`) are named `docs`: real work, never stale-making for an earlier
  verification unless a declared output is documentation or a directory. Nothing in a data
  directory (`tests`, `fixtures`, `golden`, `resources`, `prompts`, …) is documentation, and those
  directories are read inside the workspace only, so a host-managed worktree
  (`~/.cursor/worktrees/…`) is not data. A `Shell` write's relative target is placed under the
  payload's `cwd` when it states one and one leading `cd <dir> &&` (also inside a whole
  `bash -lc '…'` script); a heredoc body is data, so a README whose text says `cd repo` stays
  documentation. A target that cannot be placed (any other `cd`, `env -C`, a nested `sh -c` that
  changes directory), a fixture written after `cd tests`, and a heredoc patch with any file it
  cannot read (`patch -d`, `git apply --directory`, a pure rename, copy or mode change next to a
  README update, a binary file) are ordinary edits; `git apply --stat --apply` applies, so it is a
  write (#1106 r2, r3, r4).
  Unverified: no captured Cursor payload shows whether `cwd` follows a `cd` made by an earlier
  `Shell` call; if it does not, a relative README written by a later call from inside `tests/`
  reads as `docs` (gap kept; follow-up is the #1106 owner's). The exemption is lexical: a doctest,
  docs build or Markdown lint that reads the file is not made stale by a later edit of it unless
  the file is declared. A `docs` row's check inspection shows no `write_scope` (check-result 1.5.0
  keeps its list; follow-up is the #1106 owner's). Supported.
- **Background verification.** Gap kept: A background `Shell` process the agent polls from a later
  call is recorded when it starts; its completion is not a verification (output text is never read).
  Run verification in the foreground, in one tool call (the shipped guidance says so).
- **Upgrade.** The control-request 2.9.0 `write_scope` enum gained `docs` in place; a new hook
  and an older running service fail the handshake as `manifest_mismatch` before any frame, and
  hook rows wait until the next MCP bridge start or `finishup service restart` supersedes the old
  service. The hooks and the service also share one local observation store, which a service
  that predates `docs` cannot read once it holds a `docs` row, so a hook records `docs` only while
  the running service is stamped with this installation's schema manifest. Otherwise (no service
  running, or an older one) the write is recorded as an ordinary edit, as before #1106: a
  documentation edit then can still give one Stop prompt (#1106 r2).

## Review result lead and supply that counts (W6, #1107)

**Host decision: supported.** Cursor's text copy is the canonical JSON of the structured result
(sorted keys), so a check result's `agent_next` (ADR-043 amendment) sorts first or second, after
`advisory_notes` when that is present; the structured result carries the same field ahead of the
bulky ones. `status view=operation` for a finished check returns `check_outcome` with the same
verdict, lead, `overall_next` and missing items a same-id resend from the same session returns;
after an attach or a service restart it keeps only a `supply_missing_input` lead rebuilt from the
stored missing items and omits any other continuation (same gap as Codex, storage follow-up owned
by #1100). The captured output of a
shell re-run of the target's exact command the Cursor hook observed after the request counts as
supplying a targeted `verification_output` (or `other`) item once the reviewer was sent it (ADR-006
amendment).
That path exists only on the ordinary-work observation profile: the default structural profile
observes no shell calls, so there the agent publishes `result_recorded` of the target's action with
the output in `summary`, which `agent_next` says on every host (capability gap owned by #910). An
observed run never answers `command_identity`; a respond counts only for a finding target, and a
description never counts. Verified by
`tests/unit/mcp/test_codex_structured_head.py::test_cursor_canonical_copy_lists_agent_next_first_or_second`.
