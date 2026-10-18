# Codex integration runbook

For setup prerequisites, use `finishup setup status --next --host codex` with the same
executable, configuration root and project. `--operation connection` inspects installation without
provider sign-in; `local` and `review` inspect their respective vault/privacy prerequisites.
Storage-only continuation is `finishup setup vault` in a trusted terminal. This shared #737 path adds
no new native-session capability; Linux/WSL first-use and storage acceptance remain bounded by
[the platform runbook](linux-and-wsl.md#setup-and-vault-acceptance-still-owned-by-737).

## Guided desktop connection (issue #767)

`finishup setup run --host codex` exposes the existing project-skill, plugin, activation and MCP
composition through the common desktop connection plan. Discovery offers the installation;
`--host-path`, `--host-config-root`, and `--project` select exact alternatives. An agent requests
`--non-interactive --json`, presents the changes, then repeats the returned request ID and preview
digest with `--accept`. The selected home remains bound through every Codex probe and mutation.
The historical `--codex-path`/`--codex-home` wizard remains a compatibility path.

`setup status|disconnect --host codex` uses the same target options. Disconnect removes activation,
the owned MCP entry and exact project skill, retaining inactive plugin sources and FinishUP data.
Modified or foreign integration state is refused. When the selected project carries the FinishUP
admission table (`integrate codex admission grant`), the plan adds `remove_project_admission` and
apply sweeps it *first*, then reports `status.admission_cleanup`: a trusted project's
`[mcp_servers.finishup.tools.check]` that outlives the user-level `[mcp_servers.finishup]` transport makes
Codex 0.162.1 refuse to load configuration there (`invalid transport in mcp_servers.finishup` on
`codex exec`, `failed to load bootstrap configuration` on `codex mcp list`). After apply, FinishUP
runs `codex mcp list --json` from the project with the selected home and reports
`status.project_config_load` (`loads|fails|unknown`); `fails` ends `incomplete`
(`connection_project_config_unloadable`) with the exact admission revoke continuation. FinishUP runs
its own user-scope `codex mcp …` and `codex plugin …` commands from the selected Codex home, so a
broken project layer in the invoking directory cannot fail status or a repeated disconnect. A
transport-less leftover is reported by `setup status --host codex` (and on any failed Codex
setup command) as `status.project_mcp_leftover: "tools_only"` with the revoke continuation, under
either server key: `[mcp_servers.finishup.tools.check]`, or the Yoetz-era
`[mcp_servers.yoetz.tools.check]` that a Yoetz 0.2.x `integrate codex admission grant` wrote and a
Yoetz 0.2.x disconnect never removed (Codex then fails with `invalid transport in
mcp_servers.yoetz`); `status.project_mcp_leftover_servers` names the keys and
`project_mcp_leftover_retained_servers` / `project_mcp_leftover_tools_only_servers` name them by
kind, and the revoke removes the exact table under both. With an exact `finishup` table beside an
edited `yoetz` one, the step names each and still gives the revoke for the exact one.
Before any change, disconnect refuses an approval file it cannot read safely (a symlinked,
oversized or unparsable `.codex/config.toml`: `connection_admission_cleanup_failed`, rechecked
again before removal), and projects the project's `.codex/config.toml` after the sweep: if tables
FinishUP did not write or that were edited (a comment inside the generated table, your own
`[mcp_servers.finishup.tools.status]`) would still name the server, removing the registration would
stop Codex loading there, so it refuses with `connection_project_mcp_tables_retained` and names
the file; `setup status` reports `project_mcp_needs_registration` meanwhile, and an already broken
project with such tables reports `project_mcp_leftover: "retained_tables"` with the reconnect
continuation (a revoke cannot remove them). An edited Yoetz-era `mcp_servers.yoetz` table has no
FinishUP repair, since connecting again registers only `finishup`: the step names the file to edit
and gives no command. Disconnect also reads the projects this home knows
(its `[projects."<path>"]` entries, the FinishUP binding and the connected-projects record; missing
directories and other paths to this project are skipped first, then at most 32 are read; more are
reported as `admission_other_projects_known`/`_inspected` with the warning
`other_projects_partially_checked`, and because an unread project may depend on it the
registration then stays, and `--remove-shared` refuses; the same holds when the user
`config.toml`, the connected-projects record or a project path cannot be read,
`admission_other_projects_unread`, and the plan says which and names the explicit low-level
removal) and keeps the user-level registration when another project's
layer names the server without a transport of its own or cannot be read: the preview lists them
in `status.admission_other_projects` (with a revoke continuation where only exact FinishUP tables
remain) and warns `mcp_registration_kept_for_other_projects`. Projects with only the plugin-scoped
approval table or their own transport load without it and are not listed. `setup disconnect
--remove-shared` is the explicit home-wide disconnect: it also removes the shared plugin, binding,
cache, record and registration even while other connected projects use them (the preview lists
those projects in `status.shared_removed_from`, and any `possible_users`), and still refuses
(`connection_other_projects_need_registration`) while another project's configuration needs the
registration. It does not edit other projects. The preview's `status.admission_cleanup` names the selected project's surfaces. Record native installation, fresh-session
discovery/start, disconnect and reconnect for macOS, Linux and WSL 2 separately in #767. Desktop
app availability and CLI availability remain distinct; an untested version/platform does not
inherit certification from executable discovery or unit tests.

### Several projects in one Codex home (issue #1058)

One Codex home serves every project connected to it. Verified with Codex 0.162.1 against a scratch
`CODEX_HOME`: the installed FinishUP plugin (its hooks and plugin skills) loads from the home's plugin
cache whatever the working directory, and `[mcp_servers.finishup]` is user-level. The home has one
`[marketplaces.finishup]` binding, which names one connected project's `.agents/plugins` manifest;
rebinding it to another project with the identical manifest keeps the installed plugin, and a
binding whose project lost its manifest makes every `codex plugin …` command in that home fail
(`marketplace root does not contain a supported manifest`).

| Piece | Scope |
| --- | --- |
| `[mcp_servers.finishup]`, `[marketplaces.finishup]`, `[plugins."finishup@finishup"]`, `plugins/cache/finishup` | the Codex home, shared |
| `.agents/plugins/marketplace.json` and plugin source, `.agents/skills/finishup`, observation consent, check policy trust, `.codex/config.toml` admission | each project |
| `.yoetz-connected-projects.json` in the Codex home | FinishUP's record of the connected projects |

- `setup run --host codex` for a second project adds only that project's pieces and records it;
  the binding keeps naming the first project. Both projects read `active`. A project that only
  carries FinishUP's committed plugin source but never ran setup in this home stays
  `installed_not_activated`.
- `setup disconnect` while another connected project remains plans `detach_project`: the binding
  moves to a remaining project if it named this one, this project's manifest, skill and admission
  go, and the shared plugin, cache and MCP registration stay (`retained` says so, the preview's
  `status.shared_with` names who keeps them, and no `admission_other_projects` warning applies
  because the transport stays). The last connected project's disconnect removes the shared pieces
  and the record.
- `setup status --host codex` reports `codex_home_projects`: the *verified* members (the
  record's projects plus the project the binding names) whose checkout still exists and serves
  the manifest. A home connected before this release has no record; its bound project counts as
  connected and is recorded when a second project connects. Only a verified member is recorded,
  becomes the binding's anchor, or keeps a disconnect a `detach`. For a home Yoetz 0.1-0.2 set up,
  the bound project is the one a byte-identical `[marketplaces.yoetz]` table names while it still
  serves its exact Yoetz-era marketplace document: it uses the user-level registration, so it is
  listed in `codex_home_projects`, recorded when another project connects, and keeps the
  registration when another project disconnects (see [Legacy Yoetz
  registrations](#legacy-yoetz-registrations)).
- *Possible users* are live checkouts that serve the exact FinishUP manifest and a plugin source
  matching its own install marker, never a verified member under any spelling of its path:
  - the projects this installation of FinishUP recorded for the home and has not seen disconnect
    (its membership witness under FinishUP's state directory, `host-config-locks/<key>.members`),
    always, so deleting or losing the record never makes them disappear;
  - while the record is missing with shared pieces present, or marked `unknown_members`,
    `[projects."<path>"]` rows with `trust_level = "trusted"` (every FinishUP checkout carries those
    files, so this is not evidence of a connection).

  They are never recorded or chosen as the anchor; they only keep the shared pieces. Status adds
  `codex_home_possible_projects` and `membership_unknown`, with the exact `--remove-shared`
  preview command; connect and disconnect previews and `integrate codex plugin preview` carry
  `membership_unknown` and `possible_users` (a connect does not list the project it connects).
  Reconnecting a possible user records it. Not detected: a project connected only through
  another FinishUP installation, after the record is lost.
- A disconnect that would leave possible users but no verified member to carry the binding stops
  before any change as `membership_unverified` (adapter: `remove_refused`, `conflict:
  membership_unverified`). The continuation names the possible users and offers two ways on:
  connect again the project that uses FinishUP (that records it), then rerun the disconnect; or, if
  none does, preview `setup disconnect --remove-shared`. Verified natively below.
- A connected project whose checkout no longer serves its manifest and marker-valid plugin
  source already reads `installed_not_activated` and does not keep the shared pieces; reconnect
  it to restore both. When that project is the binding's anchor (deleted, or `git clean` removed
  its `.agents/plugins/marketplace.json`; Codex then fails every `codex plugin` command in the
  home), a disconnect moves the binding to a remaining verified member, or, with none left,
  removes the binding with the shared pieces directly (no `codex plugin` command); the same
  holds for `--remove-shared`.
- Refused: one directory under a second path (a symlink, a letter-case variant, the path it had
  before it moved) fails as `project_connected_via_other_path`, naming the path already
  connected. Disconnecting the project under its current path also clears the entry under the
  other path; then connect again. FinishUP-named configuration that FinishUP did not write or that was
  edited stays `destination_conflict`; another connected project never is.
- The review mode is part of the shared registration: connecting a project with a different
  `--route-profile` re-registers `[mcp_servers.finishup]` for every project in the home, which
  changes their review mode too (local only or AI-powered review). Every path that can do it
  names them (`route_profile_before`, `route_changes_for`, and `route_changes_possible_for` for
  possible users, plus a summary sentence): `setup run --host codex` (in `status`, digest-bound,
  also in text-mode previews), the TUI first-run preview ("registered again ... This also changes
  the review mode ..."), the historical wizard (`setup run` with Codex as the only host found, or
  `--codex-path`), whose bare `--accept` then refuses as `route_change_affects_other_projects`
  with the guided continuation, and `integrate codex mcp preview|install`, whose preview digest
  binds them and whose install needs it. No extra flag is required (ADR-012 amendment item 5).
  The current mode is read from the registration, not from the planned action, so a legacy bare
  `yoetz` strict entry stays local only. When the historical wizard or `integrate codex mcp`
  cannot read the projects using the home (an unreadable record, or a `--codex-home` reached
  through a symlink), a mode change reports `membership_unknown: true` instead of naming nobody:
  a bare `--accept` is refused and the digest binds it. The guided `setup run|status|disconnect
  --host codex` stop before any change instead (`connection_projects_record_invalid`, or
  `target_unsafe` for a symlinked `--host-config-root`). A damaged membership witness is only a
  safety net: it names no one. Without `--route-profile`, `setup run|status|disconnect --host
  codex` keep the home's current mode.
- The user-level MCP registration stays while another project uses the shared pieces (a
  serving connected project, a recorded project whose plugin files are absent right now, or a
  possible user), whatever the disconnecting project's own state: re-running the disconnect of
  an already detached project, or disconnecting one that never connected, leaves it and says so
  (`retained`, `shared_with`, also in the status and the text-mode line of an `unchanged`
  disconnect). When the pieces stay for the dangling binding's project and its directory is
  missing right now (an unmounted volume, a moved checkout), the disconnect names it
  (`members_missing`, "directory missing right now") rather than "other connected projects";
  if no live project keeps them, an `unchanged` disconnect also names the exact `setup
  disconnect ... --remove-shared` preview, since that project cannot disconnect itself while its
  directory is gone. A detached or
  never-connected project reports `configured: false` and `enabled: false` (with
  `shared_registration_retained: true`) in both `setup status` and the disconnect status. So does a
  project whose disconnect kept the registration for another project's own Codex configuration
  (`admission_other_projects`) or because not every project the home knows was checked.
- With the `[marketplaces.finishup]` binding removed by hand, disconnecting one of two connected
  projects detaches it and keeps the plugin table, cache and record for the other.
- Only a connected project may move or remove a binding whose anchor lost its manifest; a
  project that never connected removes only its own pieces. A removal of the shared pieces names
  connected projects whose plugin files are absent right now (`status.members_not_serving`), and
  a detach names where the binding moves (`status.rebind_to`).
- Low-level commands stay home-wide by design: `integrate codex mcp preview-remove|remove` removes
  the registration for every project of the home and says so (`shared_with`, `possible_users`,
  warning `mcp_registration_shared_with_other_projects`, and `membership_unknown` when they
  cannot be read; the preview digest binds them). `integrate codex plugin preview` names
  connected projects whose plugin files are absent right now (`members_not_serving`) and whether
  the plan keeps the shared pieces (`keeps_shared`). Use `setup disconnect` to disconnect one
  project.
- Every guided setup apply for the home (`setup run|disconnect --host codex`) holds FinishUP's
  per-configuration lock from plan revalidation through the record update: an exclusive `flock`
  on a 0600 file under FinishUP's own state directory (`host-config-locks/`), keyed by the home's
  resolved path, NFC, case-folded. The Codex activation and removal steps also hold the home's
  own `.yoetz-marketplace-activation.lock` across their plan, apply and record update; the TUI
  first-run connect, the historical `--codex-path`/`--codex-home` wizard, `recommend accept
  codex-plugin-activation` and `integrate codex plugin remove` hold only that in-home lock. A
  lock that cannot be taken stops as `connection_lock_unavailable` before any change, naming the
  lock folder. The state-directory lock does not serialise a setup run by another FinishUP
  installation; the record's compare-then-rename (which narrows but does not close that race)
  and the in-home activation lock do. Untested: a state directory on NFS, SMB/CIFS, WSL DrvFS
  (`/mnt/c`) or another network or FUSE filesystem, where `flock` may be refused (safe:
  `connection_lock_unavailable`) or hold only on the local machine (ADR-012 amendment item 7).
- Codex setup needs an existing Codex home: an absent one is refused as `target_untrusted`, and
  the continuation names the `mkdir -p -m 700` (Claude Code and Cursor create theirs).
- The record keeps the name `.yoetz-connected-projects.json` whatever the MCP server key is
  called, so an upgrade keeps the members it lists. A record that is not an owner-only regular
  file with valid content stops `setup run`, `setup status` and `setup disconnect` before any
  change as `connection_projects_record_invalid` (adapter: `source_invalid`, `conflict:
  connected_projects`). The continuation names the file: make it owner-only again (`chmod 600`)
  or restore it; if it must be removed, connect every project that uses FinishUP with this home
  again before disconnecting any of them.
- Terminal interface: `/connect` and `/disconnect` use the same plans, but `--remove-shared` is
  CLI-only, and the TUI shows a generic continuation for `membership_unverified`,
  `connection_projects_record_invalid` and `connection_lock_unavailable`; run `finishup setup status
  --host codex --project <project>` or `setup disconnect` from a terminal for the exact one.

Native evidence, Linux x86_64 (ext4), Codex CLI 0.144.6, scratch `CODEX_HOME`, `HOME`, XDG and
isolation root, through `finishup setup run|disconnect|status --host codex` preview and `--accept`
from this branch (2026-10-14 and, for the review fixes, 2026-10-15, #1058). These runs predate the
FinishUP rename (ADR-048) and used the Yoetz names; the names below are their FinishUP equivalents,
and the scenarios have not been re-run on the renamed build:

| Scenario | Result |
| --- | --- |
| Foreign clone: connect A; delete the record; add a never-connected trusted checkout `a-clone` with FinishUP's committed plugin files (sorts first); connect B; disconnect A; delete `a-clone` | B's connect records A and B with `unknown_members`, not `a-clone`; A's disconnect preview: `detach_project`, `shared_with` B, `possible_users` `a-clone`; the binding moves to B; after deleting `a-clone`, B reads `active` and `codex plugin list --marketplace finishup --json` and `codex mcp list --json` from B succeed |
| Lost record, no verified member left: connect A and B; delete the record; trust both; disconnect A | refused `membership_unverified`, nothing changed, continuation names B; reconnecting B records it, then A's disconnect detaches and the binding moves to B |
| Deleted record, no trust rows at all: connect A and B; delete the record; disconnect A | refused `membership_unverified` naming B (from the witness), `config.toml` byte-identical; reconnecting B, then A's disconnect detaches to B and B reads `active` |
| Anchor deleted: connect A and B; `rm -rf A`; disconnect B | status lists only B; disconnect plans `deactivate_plugin`, `remove_mcp_registration`, `remove_project_skill` and completes; `config.toml` holds no FinishUP table; `codex plugin list` works again |
| Anchor manifest removed: connect A, B and C; delete A's `marketplace.json`; disconnect B | `detach_project` with `shared_with` C; the binding moves to C and `codex plugin list` works from C |
| Review mode: connect A on `strict`; connect B on `policy`; preview C on `strict` | B's preview carries `route_profile_before: strict`, `route_changes_for: [A]`; the text-mode preview for C prints the change from AI-powered review to local only for A and B |
| Damaged record (mode 0644) | `setup run`, `setup status` and `setup disconnect` all report `connection_projects_record_invalid` with the `chmod 600` continuation |
| `--remove-shared` text preview | prints the home-wide sentence naming the connected project that stops using FinishUP |
| Re-run: connect A and B (strict); disconnect B; disconnect B again; disconnect never-connected C (2026-10-15, round 2) | B's detach discloses `shared_with` A; both re-runs are `unchanged` with the shared registration listed as retained; A's `[mcp_servers.finishup]` (strict, absolute launcher) is byte-identical and A reads `active`, `configured: true` |
| Historical wizard: `setup run --codex-path ... --codex-home ... --route-profile policy --non-interactive --accept` with A on strict | refused `route_change_affects_other_projects` naming A, with the guided `setup run --host codex` continuation; the registration stays strict |
| `integrate codex mcp preview|install --route-profile policy` with A on strict | the preview names A (`route_profile_before: strict`, `route_changes_for`) with a bound digest; `install --accept` without it exits 2 (`mcp_registration_route_change_affects_other_projects`) and changes nothing |
| Dangling binding: only A connected; A's `marketplace.json` moved away; disconnect never-connected C | only C's own manifest goes; in this scenario `config.toml` stays byte-identical (C had no shared piece to remove), cache and record kept; when A's manifest returns, A reads `active` |
| Member files absent (round 3, 2026-10-15): connect A and B (strict); disconnect B; move A's `marketplace.json` away; disconnect B again; disconnect never-connected C | both are `unchanged` with `shared_with` A and the shared plugin and registration listed as retained; text mode for C prints "The shared FinishUP pieces stay for the other projects using this configuration: A"; `config.toml` (same SHA-256) and the record keep A; `setup status` for B reads `configured: false`, `enabled: false`, `shared_registration_retained: true`, for A (manifest back) `active`, `configured: true`. At e63baed10 C's disconnect planned `remove_mcp_registration` and removed it |
| Missing directory (triage, 2026-10-15): only A connected; move A's directory away; disconnect never-connected C; then follow the named `--remove-shared` preview | `unchanged`, retained "shared Codex plugin and MCP registration, kept for a connected project whose directory is missing right now", `shared_with` and `members_missing` A; text mode prints "... A (directory missing right now)" and the exact `setup disconnect ... --remove-shared` command; that preview plans `deactivate_plugin`, `remove_mcp_registration` and, applied, leaves no FinishUP entry in `config.toml`. At 394e544e4 the same disconnect named no one and offered no way out |
| Binding removed by hand (round 3): connect A and B; delete `[marketplaces.finishup]` from `config.toml`; disconnect B | `detach_project`, `remove_project_skill` with `shared_with` A; `[plugins."finishup@finishup"]`, `[mcp_servers.finishup]`, the plugin cache and the record (A) stay |
| Legacy bare strict entry (round 3): connect A; rewrite the registration to `command = "finishup"`, args `mcp serve --host codex --semantic off`; `integrate codex mcp preview` (no route); historical wizard `setup run --codex-path ... --codex-home ... --project B --non-interactive --accept` | the preview is `reregister` with `route_profile_before: strict` → `route_profile: strict` and an absolute launcher; the wizard re-registers on `strict` (`--semantic off` kept). At e63baed10 the same wizard run re-registered on `policy` with no disclosure. `--route-profile policy` names A in `route_changes_for`; the refusal's preview command, followed literally, then installs with its digest |
| Unknown membership (round 3): connect A (strict); record mode 0644, or `--codex-home` through a symlink to the home; `integrate codex mcp preview|install --route-profile policy`, `preview-remove`, historical wizard with `--accept` | preview reports `membership_unknown: true` (digest bound); bare `install --accept` exits 2 `mcp_registration_route_change_affects_other_projects` and the registration stays strict; `preview-remove` reports `membership_unknown` and `mcp_registration_shared_with_other_projects`; the wizard refuses `route_change_affects_other_projects` with `membership_unknown: true`; guided `setup run --host codex --route-profile policy` stops as `connection_projects_record_invalid`. At e63baed10 the bare install switched the home to `policy` |
| Missing `--route-profile` (round 3): connect A with `--route-profile policy`; `setup run --host codex --project B --non-interactive` (preview); `setup status --host codex --project A` | B's plan uses `policy` with no route change (at e63baed10: `strict`, `route_changes_for` A); A reads `configured: true` (at e63baed10: `false`). A fresh home still registers `strict` |
| `integrate codex mcp preview-remove` with A connected | `shared_with` A and warning `mcp_registration_shared_with_other_projects` |

## Linux and WSL

This integration uses the standalone Codex CLI installation path on Linux and WSL 2. This runbook
does not configure or certify a Linux desktop application. The TUI labels a Linux executable as
`Codex CLI` and reserves `Codex Desktop` for an application bundle path, describing the installation
shape rather than activation or session capability. The common setup flow, service, and project binding still require the same
explicit target and fresh-session evidence as macOS. Native Linux/WSL capability remains bounded
by its recorded evidence; installation discovery and TUI labels do not imply a native-session
capability. Shared facts are in the [Linux/WSL runbook](linux-and-wsl.md), and the installation
evidence is recorded in #767.

## Conditional agent guidance

Every advertised MCP input schema has a CI-enforced 4,800-byte target, below Codex 0.162.1's 5,000-byte
schema compaction threshold. Direct-tool mode receives inline request fields, required lists and
enums without that size-triggered rewrite. Event payload variants and complete examples are in
`read_guidance` at `finishup://guidance/request-templates.md`; read the matching template before
authoring a payload. Server validation and output schemas remain unchanged. This shared
advertisement also serves code mode, Claude Code and Cursor; a capture of the model request
proves schema delivery only, not a completed workflow or platform certification.

Field descriptions are preserved within that budget, with priority rules restored first for
larger tools. A future description-free schema exceeding the target logs
`mcp_advertised_input_schema_over_budget` and serves the minimal form so the bridge remains
available; CI rejects that regression, and Codex may apply its rewrite to the oversized fallback.

The skill keeps its activation boundary, core workflow, and safety floor in the entrypoint.
Before `start` read the core, `agent-instructions.md`: it is the operating card and is enough for
ordinary work. Workflow, publication policy, and coverage and receipts are read only when a result,
error or continuation names them, or when unsure; no status read or dry run is required before a
write, and `check` with `mode: inspect` gives the picture in one read (ADR-047). Setup/consent, vault/credential operations, transcript import, and
recommendation decisions route to the corresponding sections of request templates only when
needed. Already-read guidance need not be fetched again while present in context.

Use `semantic_if_configured` only when AI-powered review is known to be optional; omit `mode` when
relying on the configured default. Select `semantic_required` for an explicit user requirement,
effective policy, or named acceptance criterion requiring independent AI-powered judgment. Preserve
required review and all host/disclosure approval boundaries. Installed guidance bytes alone prove
neither activation nor AI-powered review dispatch.

The Codex skill routes to the existing five MCP guidance URIs with installed reference fallbacks.
The server initializes only a compact summary of the safety floor, which names all five URIs and
says to read `agent-instructions.md` before the first `start` (see
[code-mode host profile](#code-mode-host-profile-issue-918)). Consumer source-inspection
restrictions do not prohibit developing or debugging FinishUP itself against isolated test state.

A new Codex session reads guidance and discovers tool schemas before calling MCP `start` as
its first workflow operation, before substantive research, commands, edits, or delegation.
Guidance reads (including `read_guidance`), discovery commands, and necessary bootstrap clarification
remain permitted. Hook auto-attachment is a cue, not proof of a current-scope plan: mapped
SessionStart context directs cooperative `start mode=attach` before `status` with the returned
ids; unmapped context directs `start` before material work. Same-session compaction uses held
current ids for `status`. Both startup messages route failures through exact continuations,
same-request recovery, and a named one-time repair before a blocked-startup user handoff.
A first non-retryable failure alone does not permit continuing without FinishUP; see
[startup failure precedence](../../guidance/coverage-and-receipts.md#startup-failure-precedence).
Codex has no demonstrated PreToolUse deny gate; instruction delivery is not enforcement (#692).
`--startup-mode required` is refused for Codex. The [native Claude/Cursor gate](required-startup.md)
does not expand Codex capability claims.

The Codex entrypoint is written directly for Codex and selected by its installer. The other native
installers select their own skills. Keep installed-source evidence separate from compatibility
directory discovery; a project skill discovered elsewhere is not proof of this integration.

Design basis, checked 2026-09-09: OpenAI's
[Skill Creator](https://github.com/openai/codex/blob/main/codex-rs/skills/src/assets/samples/skill-creator/SKILL.md)
assumes Codex is capable and recommends task-specific constraints, precise discovery metadata,
and conditional references. Its
[PR comment skill](https://github.com/openai/skills/blob/main/skills/.curated/gh-address-comments/SKILL.md)
uses a short operational sequence and a helper for repetitive mechanics. FinishUP keeps its exact
MCP read fallback and bounded closure composer because those address demonstrated authoring
failures; generic host-identification instructions are unnecessary. The five protocol references
retain one canonical owner and are copied into each installed skill.

Cursor's explicit-start repair (issue #661) leaves Codex's lifecycle binder and hook subscription
unchanged. [The official hooks reference](https://developers.openai.com/codex/hooks), checked
2026-09-08, specifies `tool_response` containing the MCP call result on `PostToolUse`, with
canonical `mcp__server__tool` names. Codex keeps its existing result unwrapping and lifecycle
locking; Cursor-only response fields and server identities are normalized only in Cursor's
adapter. The Codex lifecycle and observation regression tests remain the compatibility check.

### Reconnect after an upgrade and disconnect

Reconnect previews and replaces a pristine earlier FinishUP skill automatically. Ownership is
checked against the complete size/digest inventory in its own `.yoetz-install.json`, rather than
against the new release alone. Status still reports `modified` when the installed bytes differ
from the current release; a valid recorded inventory distinguishes an owned update from user
edits. The skill preview names `owned_skill_update` for that case, and its digest binds every
installed member, including obsolete references and the marker. The approved replacement removes
obsolete references and installs the current set. A current plugin/cache alone does not make
reconnect a no-op: the project skill must also be current. Repeating reconnect changes nothing.
The standalone skill service uses the same owned-update distinction while retaining its existing
harness compatibility, exact-preview and explicit-consent requirements.

Edited files, missing recorded members, extra files, invalid markers and linked paths are not
pristine upgrades. Connect preserves them. Move the affected `.agents/skills/finishup` directory
outside `.agents/skills` to keep your changes, then rerun the connection for the same project and
Codex home. A rerun with the conflicting directory still in place refuses again. An approved
disconnect can also remove an intact earlier skill without requiring an upgrade first.

A fresh **policy** connection uses the plugin activation cache's pinned `.mcp.json` registration
alone; it creates no direct `[mcp_servers.finishup]` table. A **strict** connection keeps a direct
registration with `--semantic off`, which shadows the plugin's policy entry. Older 0.3 homes may
have both a direct table and the plugin cache; reconnect preserves the owned direct transport and
updates pristine skill/cache copies through the same approved connection.

Disconnect removes the activation cache first, then reconciles MCP removal. If the plugin was the
only registration, Codex's positive absence observation completes that removal without a second
host mutation. A direct registration is removed explicitly, including on older homes with both
forms. Changed or foreign registrations still refuse removal. The same apply removes the project
skill; no retry is needed merely because plugin removal also removed its MCP entry. The preview's
continuation names the route observed on the registration being disconnected. Shared-project
retention and user-edited-file protections still apply, and portable inactive project plugin
sources remain. A fresh Codex process is required to observe removal; a running bridge is not
proof of persistent configuration.

This runbook guides you through previewing, installing, checking, replacing, and removing the
canonical FinishUP Codex skill in one explicitly trusted project, while preserving any files you have
modified. It also separates four facts that are easy to conflate: skill/source installation, Codex
plugin activation, MCP registration, and Codex's tested capability for a given Codex version.

## 1. What integration installs — and does not

The standalone `finishup integrate skill` surface installs only the canonical `SKILL.md`, its named
references/compatibility data, and a nonsecret managed marker, at exactly:

```text
<explicit-trusted-project>/.agents/skills/finishup/
```

It does **not** edit Codex's global or project configuration, register or start the MCP server,
install or update FinishUP or Codex, touch your Git index/ignore/remote/branch, scan your repository
contents, install globally, manage any other skill, or make FinishUP mandatory for your project. The
project root must be explicitly supplied and trusted by you — there is no current-directory,
parent-directory, fuzzy discovery, or symlink-target resolution.

The installed files are byte-identical to the packaged wheel resource. The managed marker records
only versions and sorted digests — never a path, username, timestamp, or repository reference.

ADR-023 (issue #149) accepts a portable Agent Plugins carrier design. Issue #150 implements its
skills-only renderer and whole-directory migration/rollback at the same
`.agents/plugins/finishup` root; see the
[portable plugin authoring runbook](portable-plugin-authoring.md). Until that projection is
capability-proven and explicitly approved by a later host cell, the native behavior in this
runbook remains the shipping control and nothing here changes.

Issue #151 adds an optional generated plugin-managed MCP mode to that portable artifact. It is not
the default rollout and does not change the native control. If selected by a later proven host
cell, preflight must show no external/global `finishup` registration, bind strict or policy before
preview, and install the full digest-bound artifact without invoking `codex mcp add`. Dual,
foreign, or unobservable ownership stops the operation. `finishup provider status --json` reports
`owner_source`, `ownership_state`, and the observed route profile; only one exclusively observed
policy owner can make `agent_route_semantic_ready` true. When several Codex versions are installed, the report reads the registration through each
against the selected home. Agreeing readings are usable without a selector. It reads the configured
Codex runtime first when discoverable, otherwise the newest reported release; this preference does
not prove which executable a host session launched. Disagreeing or failed readings require
`--codex-path <exact-executable>` and retain the selected home, launcher and isolation root in the
continuation. `integrate codex admission status|preview|grant|revoke` accepts both `--codex-path`
and `--codex-home`; preview/grant refuse disagreement with `host_admission_codex_binary_inconsistent`,
and revoke remains available. Admission
output uses path-free placeholders for these selectors; repeat the exact values from your preview.

## 2. Prerequisites and exact supported scope

### Explicit attach under observation contention

An explicit `start mode=attach` can meet an existing observation/advisory runtime lease.
The service waits at most five seconds for same-bundle use to drain. A retry-ready start
reason retains the reserved operation and releases only its lease; replay the identical
request body and ID once. `start_lease_pending` instead means a live owner still holds the
operation: wait up to 60 seconds before the same replay. A repeated busy/pending answer remains
unresolved. No returned writer ID is needed for this recovery, and no replacement task should
be created. Both structured errors and the compact MCP text carry the bounded continuation.
Hook auto-attachment uses the same service path; a hook deadline may expire before the service
wait finishes, so a lost response remains an exact-request recovery case, never proof of failure.
These runtime tests do not qualify a new native Codex version or prove source-content delivery.

Check `finishup version --json`, the installed resource set, and the current compatibility/capability
matrix. Confirm owner permissions on the target project, that you trust this repository, and the
expected Codex version. Codex support is the exact tested set in the packaged manifest; an empty
set means no Codex release currently carries automatic-activation support evidence. A version
string or successful file install never promotes an unprofiled release to supported.

Session-stream (rollout) parsing is a separate, narrower fact. `0.148.0` and `0.150.1` each have
an exact fixture-proven rollout grammar profile (`codex-rollout-jsonl/<version>/v1`, ADR-005).
That parser proof is what lets an isolated dogfood run advertise the `session_stream` facet for
that exact release; it is not host support, and it says nothing about skills, MCP, hooks, or
activation. Any other release is admitted under the structural compatibility profile
(`codex-rollout-jsonl/compatible/v1`, ADR-005 structural admission amendment, issue #656): the
version is recorded as provenance, lines whose wrapper/item structure FinishUP already understands
are observed, and unknown or malformed lines stay bounded `unsupported_event` gaps. The reconcile
result reports `admission` as `structurally_supported` (exact profile, every line understood),
`partially_understood` (compatible profile or any unknown line, with `admission_reasons` naming
the affected family), or `incompatible` (a header that is not `session_meta`, a non-object
payload, or an unknown `history_mode` — refused as `unsupported_format`, cursor kept). A
compatible release still earns an exact profile and the `session_stream` facet only through its
own fixtures. Explicit-path recovery uses the same atomic cursor, profile, source identity,
and tool-pairing frontier as automatic reconciliation, including mapping upgrades and delivery
backpressure.

## 3. Status and preview

Always run status first:

```text
finishup integrate codex skill status --json
```

Destination states: `absent`, `installed_exact`, `modified`/`unmanaged`, `partial`, `unsafe`.
Compatibility is reported separately as `supported`, `unsupported`, or `untested`.
A symlink at `.agents` or `.agents/skills` is `target_unsafe` and is never followed (issue #396).
Status is read-only — it never repairs or updates anything. An identical directory without a valid
managed marker is treated as unmanaged/modified and is protected from removal. `installed_exact`
does **not** by itself prove Codex has discovered the skill or that MCP is available.

## 4. First install

```text
finishup integrate codex skill preview --json
finishup integrate codex skill install --json
```

1. Preview shows the fixed destination and scope, the source skill/protocol/resource/Codex-tested
   identities, the current state, the create/replace/no-op file digest and size changes, warnings,
   and a preview digest.
2. For an absent target, explicitly confirm the exact preview digest to install. Non-interactive use
   requires the acceptance flag plus the plan digest — there is no implicit prompt or hang.
3. An already-`installed_exact` target returns a no-op. An incompatible or unsafe target stops
   without a force option.
4. If a timeout or cancellation happens around the file swap, run `status` again with the same
   target before doing anything else — do not start a new preview until you know whether the old,
   new, or a partial state is on disk.

## 5. Upgrade or replace a modified or partial copy

Default install **never overwrites**. If your copy is modified or partial, inspect and retain it
using your normal source control or a manual copy first. If you deliberately want the packaged
source to replace it, request `replace_modified` before preview, review the exact current
digest/diff, and confirm that exact preview — a generic `--yes` is not sufficient. Any concurrent
edit makes the preview stale and preserves your files untouched.

Replacement stages and swaps the **whole directory**, never merging individual files. An
interrupted, ambiguous old/new state remains preserved and requires a fresh `status`/preview and
manual review — never delete staged or rollback content blindly.

## 6. Verify Codex discovery and FinishUP availability

After an exact install, launch the exact tested Codex version in this trusted project and
explicitly invoke `$finishup` (implicit discovery is not assumed unless the current capability matrix
advertises it). Confirm the skill is recognized, its version is compatible, and the workflow
guidance appears. **Installation alone is not evidence of discovery.**

## 7. Optional versus required MCP behavior

MCP registration is a separate step from skill installation:

```text
codex mcp get finishup --json
codex mcp add finishup -- finishup mcp serve --host codex
```

Codex uses the explicit `--host codex` serving identity. This declaration binds route-drift
diagnostics to the Codex carrier; it does not grant host admission or current-chat attestation,
which retain their independent client allowlist. Decision for Codex (issue #579):
supported here — the same bounded text `Reason:` clause as Claude Code names frozen `reason_code`
and `field` on `EVENT_INVALID`, because this host also relies on the privacy-minimized summary
rather than a full JSON text copy.

Run `codex mcp get finishup --json` first. A nonzero result does not prove absence: FinishUP follows it
with `codex mcp list --json` and continues only when that command succeeds with no `finishup` entry.
A failed/malformed list or duplicate matching names fails closed; a single matching entry is
classified by its exact command. Strict parsing also rejects duplicate JSON keys, nonstandard
constants, and truncated output. If an entry already exists, preserve it and stop unless a
separately reviewed operation proves it is the exact FinishUP-owned registration being intentionally
replaced. Current Codex `mcp add` behavior replaces a same-name global entry, so this positive
absence check matters. Codex exposes no compare-and-add token: keep other MCP configuration writers
quiescent during an accepted apply, because FinishUP cannot atomically exclude a non-cooperating write
inside the final subprocess window.

The registration check-then-add flow is available as
`finishup integrate codex mcp status|preview|install` and is what `finishup setup run` performs after
Codex discovery (ADR-012). The separate removal check-then-remove flow is
`finishup integrate codex mcp preview-remove|remove`. Both flows are gated by an explicit
digest-bound confirmation, preserve entries already observed as foreign, and verify the final
state by re-reading it. A "registered" result still never implies Codex will successfully connect
at runtime.

### Code-mode host profile (issue #918)

Codex `0.157.1` runs in code mode: the model has one `exec` tool and calls FinishUP from JavaScript as
`tools.mcp__finishup__<tool>(...)`. Raw MCP results stay in the script sandbox; only what the script
prints reaches the model. Each `ALL_TOOLS` entry's description is composed by Codex from the
initialize instructions, the tool description and a generated declaration, so the instructions
are charged once per advertised tool (eight copies on the current surface). The `--host codex` profile keeps every
ceremony step and makes each one cheaper:

- **Compact initialize body.** The bridge serves `COMPACT_INITIALIZE_INSTRUCTIONS` instead of the
  19,835-byte `agent-instructions.md`. The stated 2,048-byte cap (`COMPACT_INSTRUCTIONS_BUDGET`)
  covers the packaged body alone, currently 1,991 bytes. The served block adds the route line and,
  on the policy route, the destination disclosure (#479), which is appended whole as before: 2,074
  bytes on the policy route without a disclosure, 2,098 bytes on the strict route, and at most
  3,132 bytes (`max_encoded_bytes`) with the longest admissible disclosure. The packaged
  advertised surface falls from 223,627 to 99,300 bytes. The body keeps the start trigger and
  late-start rule, the schema-load step, all five guidance URIs and when to read each (never by
  listing resources, tb4n5), the no-false-activation and no-fabrication rules, typed continuations, the
  unavailable-service statement, the disclosure, consent and recovery boundaries, and
  coverage-honest wording. It tells the agent to read `agent-instructions.md` with `read_guidance`
  before the first `start`, so the full safety floor is one call away.
  `tests/packaging/test_compact_instructions_cap.py` gates the stated cap next to the Claude cap
  gate; `tests/unit/mcp/test_compact_host_instructions.py` and an import-time lint pin the cap,
  those rules and the shared tail. A legacy registration without `--host codex` keeps the generic
  body.
- **Code-mode section in the skill.** `skills/codex/finishup/SKILL.md` shows a declaration-only
  `ALL_TOOLS` discovery helper, reading guidance from `structuredContent.text`, a UUIDv4 helper
  that works without `crypto`, and `yield_time_ms` sized to the bridge deadline of the FinishUP call in
  that cell (`check` 300,000 ms; `respond` and `receipt` 50,000 ms; `start`, `publish_work` and
  `status` 30,000 ms; see [response and receipt timeout recovery](#response-and-receipt-timeout-recovery)).
  The yield guidance is scoped to FinishUP cells; builds and tests keep their own cells. The helper
  takes the strongest entropy the cell has: `crypto.randomUUID()`, then `crypto.getRandomValues()`
  with the version-4 and RFC 4122 variant bits set, and only without `crypto` a `Math.random()`
  fallback that the snippet labels as not cryptographic. A collision on that fallback can make two
  requests share an idempotency identity, so native dogfood should record which source the code-mode
  runtime provides; service-minted ids (#919) remain the stronger answer. The helper is tested by
  running its exact snippet 10,000 times per id prefix under Node, in a fresh context and an ES
  module without `crypto`, with only `getRandomValues`, and with `randomUUID` (the latter two with
  `Math.random` disabled to prove the fallback is not used), against the `req_`, `evt_`, `act_`,
  `res_`, `evd_`, `clm_` and `obl_` patterns in `schemas/`; the patterns stay strict.
- **Single-copy guidance.** On this profile only, a `read_guidance` result's `content[0].text` is
  the bounded pointer `Guidance <uri>: <n> bytes; full text in structuredContent.text.`;
  `structuredContent` and the output schema are unchanged. Outside code mode, Codex hands the
  model the serialized `structuredContent` and ignores `content` whenever `structuredContent` is
  present (upstream `CallToolResult::as_function_call_output_payload`, read 2026-09-30 on the
  `main` branch, not pinned to `0.157.1`), as it already does for every other FinishUP result, so the
  pointer is not the model-visible copy there either. This is the lowest-priority item and is
  revertible: if a Codex dogfood run shows additional guidance re-read turns, restore the full
  text in `content`. The other items stand alone.

Large guidance reads use the `read_guidance/1.1.0` page route when the host response cap could
clip a full document. Request a canonical `page` and bounded `page_size`; carry the returned
revision/digest continuation; and verify the structured page bytes, offsets, page set, and final
digest with `GuidancePageAssembler` before treating the document as loaded. Generic, Claude, and
Cursor page text carries explicit begin/end markers. On Codex, `content` remains only the bounded
pointer and `structuredContent.text` is the page body. A final `complete` page proves service
emission only, so a missing or clipped host result is retried or restarted at page zero.

Lifecycles: a running Codex session keeps the instructions it received at `initialize`; a fresh
session, which starts a new bridge, picks up the compact body after an upgrade. Skill changes take
effect when the plugin or skill is reinstalled or updated through the normal upgrade path.

Evidence boundary: the changes above are verified by unit tests only. The Codex code-mode dogfood
acceptance (0 `crypto is not defined` failures, 0 `request_id` pattern rejections, a semantic
`check` that completes without a `wait` turn, and no extra guidance re-reads) is pending on the
dogfood lane for macOS, Linux and WSL 2. Codex does not document a maximum `yield_time_ms` for code
mode; a run observed 120,000 ms honored. If a cell still replies `Script running`, the skill directs
one covering `wait` rather than repeated short polls. The Claude Code body and `read_guidance`
results are unchanged; the Cursor decision is recorded in the Cursor runbook.

## Auto review and host admission

Under `approval_mode = auto` (the default), Codex needs approval for an MCP call iff
`destructiveHint == true`, else never for `readOnlyHint`, else
`destructive.unwrap_or(true) || open_world.unwrap_or(true)` (`codex-rs/core/src/mcp_tool_call.rs`).
Applied to FinishUP's frozen descriptors, only the policy-route `check` (`openWorldHint: true`)
needs approval; with `approvals_reviewer = "auto_review"` that approval goes to the guardian,
whose bundled policy requires authorization for sensitive egress to name payload and destination
"from trusted user content" — no descriptor wording can satisfy it. `approval_mode = "approve"`
for one tool means the reviewer is never invoked for it; `prompt` forces it every time.

Codex copies the initialize `instructions` into every tool description, so the guardian reads them.
Since issue #479 the policy-route instructions name the AI-powered review destination read at bridge
startup (provider, endpoint profile, and host, or the Codex runtime class) and the payload bound.
That gives the reviewer a named destination to score instead of nothing; it is still not trusted
user content, admits nothing, and goes stale until Codex restarts the bridge. Admission remains the
lever.

Host admission (issue #467) writes the per-tool override into the trusted project's
`.codex/config.toml`, which Codex loads only when the project is trusted, deep-merges over the
user-level `[mcp_servers.finishup]` (`codex-rs/config/src/merge.rs`), and which cannot carry
provider or credential keys (`mcp_servers` is not on the project-layer denylist):

```toml
[mcp_servers.finishup.tools.check]
approval_mode = "approve"
```

or, for a plugin-managed route, `[plugins."finishup@finishup".mcp_servers.finishup.tools.check]`. The
form follows the exclusively observed owner (`finishup provider status --json`
`mcp_route.ownership_state`):

```text
finishup integrate codex admission preview --project-root <project> --json
finishup integrate codex admission grant --project-root <project> --accept --preview-digest <digest>
```

A strict registered route, a missing or non-permitting grant, or an unreadable service refuses
before any write. A same-name table that is not byte-exact (another `approval_mode`, an extra
key) or a server-level `default_tools_approval_mode` is `foreign`: reported, never edited.
An exact table for only the inactive owner does not make the active owner present; grant adds the
applicable table instead of returning a false no-op. Removal strips every exact generated owner
form; a config that held nothing else is deleted.

A mutating preview warns `host_config_not_compare_and_swap`; keep Codex and other settings writers
quiescent during apply. FinishUP rechecks the exact preimage immediately before mutation and verifies
the result, but an ordinary file cannot exclude a non-cooperating same-UID writer in the final
syscall window.

Reverse: `integrate codex mcp install --route-profile strict --project-root <project>` and
`integrate codex mcp remove --project-root <project>` sweep the project's entry and report
`admission_cleanup` (the registration is global and the admission is project-scoped, so without
`--project-root` nothing is swept and `provider status` reports `host_admission_drift` — that
report walks from the launch directory to the repository root, so a subdirectory cwd does not
read as `absent`);
`integrate codex plugin remove` sweeps it for the bound project; `setup disconnect --host codex`
sweeps it for `--project` (default: the current directory) before the registration is removed;
a privacy commit that stops external review sweeps it in the ceremony. `mcp remove` likewise
sweeps before unregistering. The sweep still runs when MCP install/remove is already
a no-op, because the route state and the project admission state are independent.

Codex exposes no typed denial signal for a guardian refusal: its `PermissionRequest` hook fires
before the decision and may allow, so it is not a denial. A held check is visible only as the
#187 pause/approval flow in the transcript. This is a documented gap, not a FinishUP diagnostic.
For the same reason the host-hold advisory that Claude Code's `PermissionDenied` hook emits
(issue #857: a first-hand grant notice for the user and a separate host retry cue)
has no Codex carrier. The shipped skill and guidance require a current first-hand grant read
before asserting existing authorization, and the durable answer remains admission above. If a later Codex release publishes a
post-decision denial event, mirror the Claude ingress (`cli/host_hold_advisory.py`) onto it.
The 2026-08-30 source read is not a live cell; the `auto_review` acceptance cell in issue #467
remains to be run.

The Codex session-start context can also name `finishup integrate codex admission grant`
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
first MCP tool call (on-demand startup) replaces that service automatically: it asks the stale
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
hosts that use this bridge, not Codex-specific.

The accepted setup path composes four separately reported layers in order: it installs the project
skill at `.agents/skills/finishup`, installs managed structural plugin/hook sources at
`.agents/plugins/finishup`, applies an explicitly approved Codex activation, then verifies the MCP
entry. The plugin source directory, marketplace entry, or enabled config table alone is not
evidence that Codex activated a plugin.

Activation is a standing-trust mutation for future sessions in one owner-selected Codex home. The
owner must explicitly supply an existing absolute, non-symlink home; setup never derives it from a
wrapper basename, ambient environment, or a pre-consent Codex diagnostic. Setup binds the exact
selected executable path and SHA-256 and obtains its version by running only `--version` with both
`CODEX_HOME` and `CODEX_TESTING_HOME` redirected to a fresh owner-private temporary home. Codex may
create scratch even for that command, so the temporary home is removed afterward. No selected-home
inventory command runs before approval.

The preview digest also binds the trusted project root, repository marketplace, and selected-home
config preimages/proposals, managed source-tree digest, cache root
`<selected-home>/plugins/cache/finishup/finishup`, cache preimage/intended install-tree digest, the
temporary-private-home probe environment, the forced selected-home environment for mutation, and
the exact post-consent commands `plugin list --marketplace finishup --json` and
`plugin add finishup@finishup --json`. Review the displayed targets, environments, commands/digests,
resulting marketplace/config bytes, possible selected-home scratch/cache effects, and warning
before approving; do not substitute a manual `plugin add` for that ceremony.

After consent, apply forces both home variables to the approved home, re-probes bound state under
an owner-only home lock, CAS-fences each write, invokes the exact selected executable for scoped
inventory/add, and validates its reported installed path/version. A later failure preserves any
already-approved marketplace/config/cache partial state for an honest retry; it does not attempt a
pathname rollback that could delete or overwrite a concurrent change. `active` means all of these
agree: managed source installed, repository marketplace and selected-home config exact, canonical
inventory says `finishup@finishup` is installed and enabled from this repository, and the installed
version cache is byte-identical to the host-specific render of the managed source. Other closed
states are `installed_not_activated`, `not_installed`, and `foreign`. `not_installed` is source
absence only; a modified or untrusted byte-present tree is `installed_not_activated` and is never
`active` (issue #347). None of them—and not even
`active`—proves a later Codex process loaded a hook or delivered an observation.

Complete Codex's own trust step in a fresh native process before testing hook delivery. Open
`/hooks`, review the commands from the intended FinishUP plugin, and approve those hooks through
Codex's normal review UI. Those commands name `finishup` by basename. They are not the absolute
launcher written into the cache `.mcp.json`. Approving them trusts that basename; editing the
command later marks the hook modified and inactive until this review is repeated. Confirm the
hooks are active, then start a fresh session so its
`SessionStart` runs with that trust. New or changed hooks can remain installed but inactive;
the plugin's skill and MCP tools may still work in that state. A non-interactive run with no
observation rows is therefore not, by itself, evidence of a FinishUP ingestion failure. Installation
inspection reports hook trust as unknown because it does not inspect Codex's effective trust
decision. Do not replace this check with a hook-trust bypass flag.

Project trust is a separate gate for the project-local MCP admission table above. When a check
returns `MCP tool call requires approval, but approval policy is never`, it was refused by Codex
before FinishUP dispatched it. Confirm the project is trusted in the selected Codex home and test a
fresh process with the intended MCP owner and per-tool policy. An installed admission entry or
`codex mcp get` output alone does not prove the running process applied that policy. A normal
interactive process can present any remaining approval request without changing the sandbox.

The managed project source always carries the canonical async-free render; the host-specific form
(async pure-ingress hooks from Codex `0.148.0-alpha.6`) exists only in the versioned activation
cache, which apply seeds and verifies against the previewed install digest. Because the package
version stays constant while plugin content drifts, a previously activated home's cache can
legitimately differ from the fresh render: a cache tree that carries a valid
`.yoetz-plugin-install.json` marker and byte-matches that marker's own inventory is a prior
finishup-managed render, previewed as a same-version refresh and replaced atomically on apply.
`destination_conflict` is reserved for foreign, marker-inconsistent, or modified cache trees and
for FinishUP-named configuration FinishUP did not write — those still require the owner to resolve the
conflict by hand. A binding to another connected project is the shared marketplace, not a conflict
(see [Several projects in one Codex home](#several-projects-in-one-codex-home-issue-1058)). An exact
Yoetz-era activation of the same project is migrated, not a conflict (see
[Legacy Yoetz registrations](#legacy-yoetz-registrations)).

Registration also decides *which* route the agent gets. Both owned serve commands classify as
`yoetz_owned`, so the state alone cannot tell a strict registration from a policy one. Read the
route from `finishup integrate codex mcp status --json` (`route_profile`) or from `finishup provider
status --json` (`mcp_route.registered_profile`). The route is explicit input: pass `--route-profile
strict|policy` to `finishup setup run` or `finishup integrate codex mcp preview|install` to choose it.
Without that flag an existing finishup-owned registration keeps its current route (non-interactive
`--accept` never changes it): the historical wizard, `integrate codex mcp`, and non-interactive
`setup run|status|disconnect --host codex` all read the route from the registration itself, so a
re-registration that only changes the launcher, isolation root, or key (for example a bare `yoetz`
launcher or an entry under the earlier `yoetz` key, migrated under ADR-048) keeps it. Only a fresh
home registers `strict`. An interactive review-mode answer is explicit input (under the hybrid
default, #1068, every interactive answer registers `policy`). A route transition is shown in the
preview and reported as `route_profile_before` → `route_profile`. The registration is shared by
every project of the home: when a transition would change other connected projects (or projects
that may use FinishUP), the preview names them (`route_changes_for`, `route_changes_possible_for`),
or reports `membership_unknown: true` when the projects using the home cannot be read; its
`preview_digest` binds them, and `install` refuses without that exact digest
(`mcp_registration_route_change_affects_other_projects`, whose message names the exact
`integrate codex mcp preview --route-profile <requested>` command to run). Before running a session that will report a finding about
FinishUP's AI-powered review behaviour, walk the [AI-powered review dogfood
runbook](semantic-dogfood.md) — it declares up front which claim the run is allowed to make, and
refuses to score AI-powered review quality when no provider attempt happened. To measure whether
feedback **changed the work product** (not merely whether FinishUP was healthy or authorable), use the
[influence dogfood runbook](influence-dogfood.md).

### Applied-route record and registration drift (issue #537)

Decision for Codex: this host gets the state-root applied-route record. Every accepted
`mcp install` writes the applied route profile, the exact serve command, the post-write
observation, and structural digests to the owner-only state-root record
(`integrations/applied-mcp-routes.json`); later installs overwrite it, and `mcp remove`
clears it — removal ends the install it recorded, so absence with no record reads as no
drift and a later install writes a fresh record. `finishup integrate codex mcp status --json` and `finishup provider status --json`
(`mcp_route.applied_profile`, `mcp_route.drift_since_install`) join that record against the
live host resolution, fail-soft: an unreadable record reads as no applied route and never
reports drift. `finishup setup status --json` stays discovery-only by design: it reports
discovered binaries and live registration state without the applied-route drift join, which
lives in `mcp status` and `provider status`. An accepted install that had nothing to write
(`action: noop`) still refreshes the record, so a deliberate re-registration of the route the
host already serves never leaves an earlier entry behind to report as drift.

The MCP bridge (`finishup mcp serve --host codex`) is the sole emitter of the closed `registration_drift`
hook diagnostic: at startup it compares its own serving argv against the applied record and
records the mismatch under the `mcp_serve` event. The hook paths deliberately emit nothing.
A hook process has no serving route of its own, so the only comparison available there is a
`codex mcp get` subprocess plus the PATH version probes needed to find the binary, which
costs a large fraction of the end-to-end hook budget and is bounded only by the adapter's own
10s command timeout — the failure mode of #209-#213. The bridge starts for the same Codex
session and answers the same question for free, against stronger evidence (what this process
actually serves, not what the host would resolve for the next one).

A strict-ceiling check served while the applied record says `policy` carries the
`optional_semantic_review_registration_drift` coverage gap so its receipt names the recovery
(re-register the policy route, start a fresh Codex process). A genuinely applied strict route
keeps the terminal ceiling wording. The drift gap is never carried onto a later
local-only check: it is re-added fresh on the strict-ceiling path only, after reading
the live record.

If the host is configured with FinishUP as an optional server and it is unavailable, Codex work
continues and the skill discloses no live ledger/check/receipt data. If configured as required,
server failure blocks only the Codex surfaces that the tested capability profile proves are
affected. Installing the skill never itself changes MCP configuration or produces a receipt.

The exact capability profile also reports whether a compaction-recovery trigger hook and/or a
first-party observation arm is present. A present v0.1 trigger only prompts the agent to re-ground
by calling `status` — it records no observation, changes no coverage, and remains optional. When
the cell advertises observation, enablement requires one workspace-level observation consent
(workspace commitment, never a raw path in logs); live ingest uses local control methods
(`observation_ingest|status|pause|resume|revoke`), not an MCP tool. `hook_observed` is earned
only from real observation evidence. `AdviceSnapshot` surfaces via nonblocking hooks and ordinary
`status`. Skill installation never configures hooks. If the profile is absent or a trigger/observation
path fails, use the ordinary manual resume/compaction procedure and cooperative publication; do not
infer support from a different Codex version.

Codex setup's consent step is a structural grant. It uses the same path from `finishup setup`, host
connection, and the terminal interface. When the workspace already has live consent (for example,
from a Claude Code or Cursor connection), the step keeps that consent: the original grant time,
every approved Claude Code or Cursor content profile, selection and capacity settings, and the
unchanged content fence. Capture already in progress for the other host therefore stays authorized
(#835). The setup report's `observation_consent.transition` reads `unchanged` and lists the retained
`content_capture_profiles`. A paused workspace is resumed (`resumed`). With no prior consent, or
after a completed revoke, consent starts fresh (`granted`) with no content profile. While a revoke's
project fence is pending, the consent step reports `failed` and leaves consent revoked. Only
`observe content-disable` or `observe revoke` removes a host's content arm.

### Subagent correlation (#507)

The Codex native hook artifact includes `SubagentStart` and `SubagentStop`. Their structural
identifiers are normalized as `subagent_id` plus the optional `parent_tool_call_id`; the 0.150.1
rollout grammar also exposes a `SubAgentActivity` record whose bounded `agent_thread_id` maps to
the child identity and whose closed `kind` (`started` or a terminal state) selects the phase. Raw
agent paths, prompts, and summaries are discarded. These mappings are service inputs, not caller
authorship.

The service records one provisional annotation per observed child correlation, keyed by one
correlation identity, with `origin=host_observed`, `acceptance=pending`, and no child bundle. The
materializer retains the host observation as evidence, and the durable registry exposes its
bounded annotation through lineage status. A
parent may mint an accepted child with `mode=delegate` before spawning; a cooperative child may
self-register with the parent session. Either accepted path binds the
existing annotation and never creates a second record. A stop replay after session rotation must
resolve through the same child/parent-tool aliases; an event with no usable child identity remains
the permanent `missing_subagent_identity` gap and does not also produce an annotation. Parent
advice and frontier delivery are never redirected to the child.

#### Issue #509 qualification boundary

The supported Codex paths are the two above: parent `mode=delegate` before the spawn, or a
cooperative child that self-registers with the parent session. A `SubagentStart` annotation stays
`host_observed` and `pending` until one of those paths binds it. A helper that never calls FinishUP,
and a second root created with `mode=create` in the same workspace, are not children. The
executable fixture names and the native acceptance table are in
[multi-agent-conformance.md](multi-agent-conformance.md#host-qualification-rows). A green fixture
does not pass the native macOS or Linux/WSL Codex cell. #841 rollout reconciliation stays a
separate owner.

The #509 source guidance repair puts the no-selector helper rule in the workflow and host skill.
The shared initialize safety floor has no room for the same sentence under its advertised-surface
budget, so the parent must state that rule explicitly in the helper assignment. This run does not
qualify spontaneous adoption of the repaired guidance.

When a retained child stop reports a finding, `subagent_finding_unaddressed` advice names the
registry's annotation ID, or the bound child task ID when available. Advice refresh resolves that
identity through a read-only, parent-scoped lookup; it does not update the annotation's timestamps
or session ownership. The original observation reference remains attached as evidence. If no
unambiguous annotation is available, advice retains that observation reference without inventing
a lineage identity.

Stale-verification advice is scoped to the logical tool call, not to the observed phase. A Codex
`function_call`/`function_call_output` pair, and the hook pre/post pair, share one correlation
identity, so one edit reports one `edit_after_successful_check` finding whose evidence refs name
each observed phase; the originating call's tool name resolves the pair exactly as it already does
for unresolved-command advice (issue #680).
A successful Codex `shell` call is a command outcome, not a check. Local advice moves its
verification baseline only on a current `passed` approved-check fact or an explicit success from a
dedicated verification tool, and a routine read never moves it — including in Detailed mode, where
a routine read keeps its `function_call_output` action and carries no routine marker (issue #681).
Unresolved-command advice (policy `0.1.7`) reads the outcome Codex states for each `Bash`,
`exec_command`, `local_shell` or `shell` call, as
described in [Tool outcomes](#tool-outcomes-issue-910) below. Before issue #910 no Codex shell call
had a recorded outcome, so this advice never fired on Codex. A call whose outcome Codex did not
state is `unknown`: it neither opens nor resolves a failed command.

**Failure supersession (#909).** A later run of the same command (only the latest run of a command
is judged; a pass clears it), or an observed edit that reported success (an `apply_patch` whose
result starts `Exit code: 0`), retires an earlier observed failure before a completion claim: no
`failed_work_omitted`, no `material_limitation_omitted`, no `failed_command_unresolved`, and a v1.1
claim need not list it in `limitation_refs`. The receipt still names it once as history. The hook
commits to the command inside the hook process (`tool_input.cmd` for `exec_command`, the `command`
argv for `shell`, with `/bin/bash -lc` and `bash -lc` wrappers stripped) using the installation key
and forwards only the `hmac-sha256:` `command_commitment`; the command text is never stored or sent.
`apply_patch` carries none. Decision: supported on the hook and stream paths. With #910 the Codex
hook records each shell outcome, and a rollout `CommandExecution` item commits to its `command`
argv with the same normalization and key, so a later run seen on either path judges a failure
seen on either path.
Edits written through shell commands (for example heredocs in `exec_command`) are commands, not
observed edits, so a failure followed only by such edits stays live unless the command is rerun
(for the stale-verification rule a shell command that visibly writes the workspace does count as an
edit, ADR-045); the
DeepSWE dynamodb-toolbox B attempt edited mostly this way (owner: #909 follow-up). `status
view=results` shows each observed run's tool, occurrence, commitment, and exit status. Native
dogfood acceptance of this path on macOS, Linux and WSL 2 is not yet recorded (owner: #909).

Native child tool callbacks can carry the parent's host session ID together with a child
`agent_id`. A successful delegated `start` preserves the parent mapping: its task result names the
reserved child, but its session and writer still belong to `parent_task_id`. A successful child
attach establishes a separate local route scoped to the host session and child identity. A shared
session without a validated child identity remains an attribution gap. Conflicting aliases or a
callback naming an unbound child also produce a gap; they cannot enqueue parent work or consume
parent advice and frontier notices. Pending lifecycle writes and existing alias ownership are
checked before publishing a child route. A contended write leaves a durable retry for that single
route; replay cannot change its task owner. `SubagentStart` and
`SubagentStop` remain parent lineage signals. Local routes by themselves do not mint cooperative
children or establish registry correlation, and they are excluded from parent session recovery and
parent stream reconciliation.

The #507 source repair adds a Codex bridge for the blessed handle-only flow. A native successful
child `start` callback carries its host subagent identity and bounded returned task, session,
writer, and parent identities. The service validates those fields against the admitted child
mapping and persisted lineage before binding the annotation. A callback that arrives before
`SubagentStart` can establish the same correlation for the later lifecycle hook. Missing or
conflicting identity cannot bind another child. The parent does not need to know an ID before the
host spawns it, and the capability handle is not added to observation payloads. On `PostToolUse`,
`tool_use_id` and `tool_call_id` identify the attach call and must agree when both are supplied;
`parent_tool_call_id` independently identifies the spawn call and may differ. Any explicitly
malformed call identity blocks binding and persists `missing_subagent_identity` in the task
observation ledger, including when the registry sidecar is unavailable. Session-stream
`SubAgentActivity` records follow the same rule: conflicting or malformed parent-call aliases
cannot degrade to a child-only identity, so the `SubagentStart`/`SubagentStop` envelope drops
the child token and records the same durable gap instead of a weaker annotation.

Explicit cooperative correlation fields are validated before consuming the attach handle. A
post-attach transient registry error remains recoverable with the exact request and consumed
handle, including after expiry; a fresh request cannot reuse that capability. A crash after the
child start committed but before handle consumption is recovered the same way: the exact
request finishes consumption after expiry, while any other request is refused as expired. Subagent evidence
under `obs-ledger/1.7.0` distinguishes different parent tool calls. Copies that omit the parent
call may produce separate evidence, while the registry merges only unambiguous aliases. Once a
child-only annotation is bound, a later strong parent-call pair creates a separate annotation:
the shared child token does not prove the call belonged to that previously bound child. Strong
cooperative selectors and advice lookups use the same boundary. A new
observation does not reuse a historical child-only evidence key when the missing discriminator
cannot prove equivalence. Missing or malformed child identity is retained as a durable
`missing_subagent_identity` gap without also creating an annotation for that event.

**2026-09-16 source-only repair boundary (#499/#507):** isolated source fixtures cover the
lifecycle and correlation changes above. No native Codex process, FinishUP workflow, live receipt,
or cooperative-child proof was produced during this repair phase. Fresh installed native
validation with the corrected candidate and the requested independent semantic review remains
required. E-013 and host capability cells are unchanged. The historical native records below
retain their original limits.

### Multi-agent v2 (0.153.4, #754)

Codex `0.153.4` with `multi_agent_version=v2` expresses a delegation in two places, and FinishUP
reads both:

- the **parent** rollout carries `SubAgentActivity` nested in `event_msg` → `item_completed` →
  `item` (never as a `response_item`). Its `agent_thread_id` is the child thread, its `kind` is
  `started` once per delegation and `interacted` for every later exchange, and its `id` is a
  `call_…` token that is not published as `parent_tool_call_id`: only an explicit parent alias
  ever fills that field. `interacted` is an understood kind that names no lifecycle transition,
  so it opens no second annotation and is not an `unsupported_event` gap;
- the **child** rollout's own `session_meta` header carries `thread_source: subagent`, `id` (the
  child thread), `parent_thread_id`, `agent_path`, `agent_nickname`, and `multi_agent_version`.
  Its `session_id` is the *parent* thread, so only `id` is ever the child key. FinishUP maps that
  header to a `SubagentStart` whose `subagent_id` is the child thread; both spellings of the
  spawning thread (`parent_thread_id` and `source.subagent.thread_spawn.parent_thread_id`) must
  agree, and a header naming itself is refused. A header that declares `thread_source: subagent`
  with no usable distinct identity is the one shape that earns `missing_subagent_identity`; an
  ordinary user thread declares no child and earns no gap.

Because the child observes that header in its own session, filing it the ordinary way would name
the child as its own parent. The parent task therefore comes from admitted catalog lineage, never
from the host's `parent_thread_id` token, and the annotation is then bound to the observing child
task — the same shape as the native `PostToolUse` child-start bridge. With no admitted lineage the
observation keeps a bounded `host_lineage_child_not_found` gap instead of inventing attribution.
Both sources produce the same correlation identity for one delegation (the child thread), so a
parent-observed spawn and a child-observed header merge into one annotation rather than two.

`agent_path` and `agent_nickname` are **not** lineage identity. `agent_path` names an agent
definition, not a delegation instance: the same path repeats across every exchange with that agent
and across repeat delegations to it, and its `/root/…` shape is barred from structural payloads by
design. `agent_message` `author`/`recipient` carry the same paths and are treated the same way.

Two record families 0.153.4 adds are admitted as structurally ignored rather than mapped:
`inter_agent_communication_metadata` (already in the vocabulary) and `token_usage_record` (new,
admitted on the structural compatibility profile only). 0.153.4 also added fractional leaves to
ordinary rows — `internal_chat_message_metadata_passthrough.create_time` on every `response_item`
and `rate_limits.*.used_percent` on `token_count`. The canonical value model has no float, so the
parser normalizes such a leaf to `null` in the mapped record and keeps the line; before that, one
fractional leaf refused the whole line as `json_profile_unsupported`. No structural field FinishUP
maps is ever a float, and the line's commitment is still taken over its raw bytes.

**2026-09-16 v2 observation cell (`multi_agent_v2=true`, read-only, not a certification).** Source
`12796f74` (PR #752 head), wheel `yoetz-0.2.1`, pinned test instance `df507f`, Codex `0.153.4`,
originator `Codex Desktop`. Read from the stopped instance's artifacts after the run:

| Fact | Observed |
|---|---|
| Parent rollout record families | `event_msg` 152, `response_item` 118, `token_usage_record` 36, `inter_agent_communication_metadata` 8, `world_state` 3, `session_meta`/`turn_context` 1 each |
| Parent `SubAgentActivity` | 8, all nested in `event_msg.item_completed`; `kind` `started` 2, `interacted` 6; 0 as `response_item` |
| Child rollouts | 2, each `thread_source: subagent` with `parent_thread_id` equal to the parent thread and `session_id` equal to the parent thread |
| Annotations produced | 0 host annotations, 0 aliases, 2 consumed attach handles |
| Parser result at that revision | 174 of 319 parent lines refused (138 `json_profile_unsupported` from the new fractional leaves, 36 `unknown_wrapper_type` from `token_usage_record`) |
| Parser result after this change | 319 of 319 parent lines and 218 of 218 child lines mapped, no per-line reason codes, no `unsupported_event` |
| Stream cursor at stop | event position 77, byte 956,771 of 2,268,686 — the first `SubAgentActivity` is at line 91 |

The 50 `unsupported_event` rows in the parent ledger are exactly the 40 fractional-leaf refusals
plus the 10 `token_usage_record` lines inside those first 77 positions. The run produced no
annotation for two independent reasons: the delegation rows were past the last consumed position
(the hook-driven reconcile stalled, #753), and neither child's own session observed its own
rollout, because the observation cursor and workspace binding for a child thread are established
by that thread's hooks and no hook reached those child sessions (0 observation events, 0 cursors
in both child ledgers).

**Not established by that transcript.** Whether `0.153.4` still emits `SubAgentActivity` with
`multi_agent_v2=false`; whether the v2 `SubagentStart` hook payload carries `subagent_id` (every
hook after 14:39:59Z hit the degraded path, #753); whether `agent_path` is stable across session
rotation; and whether a delegated child thread ever runs the hook bridge, which is what would let
the child-header identity source fire natively. The child-header path is proven against fixture
IMP-015 and the registry bridge, not against a native v2 run. `0.153.4` remains admitted under the
structural compatibility profile: it earns no exact rollout profile and no certified host cell from
this evidence, so its admission stays `partially_understood`.

**Child lanes under the shared root session (#841).** The 2026-09-25 follow-up to #823 ran the
0.3.0 package (`2e9b35ce`, wheel SHA-256 `09e507d3…7588`) on a disposable ADR-028 instance with
Codex Testing `0.153.4`. A parent delegated and one native child attached with the handle,
published, checked, and obtained a receipt. The parent saw that accepted child, but its lineage
view also kept one pending unbound provisional annotation, and one supported `observe reconcile
--session-file <child rollout>` returned `observation_reconcile_failed:mapping_missing` (exit 20).
The raw run evidence is private; only these structural facts are recorded here.

The source analysis names two boundaries, both reproduced from the exact IMP-015 records:

- **Callback identity.** v2 writes the same root `session_id` into every thread of one delegation
  tree (the child header's `session_id` is the parent thread). A delegated child's own callbacks
  therefore arrive under the parent's session. With no host child alias (`subagent_id`,
  `agent_id`, `agent_thread_id`), the child's successful attach `PostToolUse` cannot publish a
  child lane (`start_bind_child_lane_unbound`), so the native child-start bridge never binds the
  annotation, and the child's other callbacks were ordinary parent callbacks.
- **Rollout routing.** A v2 child rollout is named by the child's own thread, never by a host
  session, and an accepted child's route is the digest lane derived from the root session and the
  child thread. Hook-driven stream reconcile skipped every child lane, and manual reconcile only
  matched raw host sessions by filename. The child's own `session_meta` header — the #754
  child-observed delegation signal — could therefore never be delivered natively, and every child
  rollout was refused as `mapping_missing` whether or not a child route existed.

Which callback shape the native run produced is visible in that run's private
`hook_diagnostics.reasons`: `start_bind_child_lane_unbound` on the child's attach means the child
callbacks carried no alias; no child callback diagnostics at all means no hook reached the child
thread. The public issue does not establish which.

The repair keeps every existing authority rule and adds no inference from workspace-wide stream
state or annotation counts:

- A Codex tool, permission, prompt, `Stop`, or compaction callback whose `transcript_path` (or
  `session_file`) is not the session's own rollout reads only that file's first line. When it is
  a safe owner-private `.jsonl` beneath the Codex home's `sessions` root, its v2 header declares a
  delegated child, the filename carries that child's thread, and the header names the callback's
  session as the spawning root, the child thread becomes the callback's host child identity —
  the same fact a native `agent_id` supplies. The attach then publishes the child lane, the native
  child-start bridge binds the annotation, and the child's command, file, and advice evidence
  stays on its own lane. A transcript that proves a delegated child but cannot name it for this
  session, or that contradicts a host alias, keeps the callback an explicit attribution gap with
  the hook diagnostic `child_transcript_identity_conflict`; it never becomes parent work. Session
  lifecycle and `SubagentStart`/`SubagentStop` hooks are never re-attributed.
- A callback routed to a validated host-identity child lane reconciles that child's own rollout
  into the lane. Its header is filed under the parent named by admitted catalog lineage and bound
  to the observing child, so the parent's provisional annotation, the child-header signal, and the
  attach callback merge into one annotation bound to exactly one accepted child.
- `observe reconcile` of a child rollout resolves it through its header to the one lane derived
  from a spawning session bound to that workspace alone and already mapped to a child task. The
  result carries `mode: recovery_child_lane` and shares the automatic cursor, so repeating it
  accepts nothing new. A child rollout that cannot be proven is refused with a bounded reason
  instead of `mapping_missing` (see troubleshooting below). An ordinary unmapped rollout still
  reports `mapping_missing`.

Evidence boundary: a source repair proven by focused unit rows and a composed-READY conformance
row over the exact IMP-015 parent and child records, including idempotent recovery and the
parent's recorded rollup of the child. It assumes the v2 child callback shape the header implies
(root session plus the child's own transcript) and has not been rerun natively. When a child
thread's callbacks carry neither a child alias nor their own transcript, or no hook reaches the
child thread, the child route stays unprovable and recovery reports `child_route_missing`.
`0.153.4` remains admitted on the structural compatibility profile only: this repair earns no
exact rollout profile, formal parity-gate cell, or E-013 capability cell.

Admitted native hook activity on the current mapped session is contact evidence at its own
receipt time (#837). A row the hook drain, sweeper, or legacy spool delivers late still counts from
when it was received. A duplicate replay re-offers the same evidence without extending it, and
`Stop` counts as contact while `SessionEnd` ends it. Stream history and predecessor sessions do not
renew. Codex registers no subagent lifecycle hook for the parent, so no in-flight hold applies. A
parent's own `PreToolUse` and `PostToolUse` still count, but one `wait` or other tool call that
runs past the lease plus the recovery window, with no other parent event, loses contact and
abandons the work after `lineage.contact_lost_recovery_seconds`. That is the recorded Codex gap,
and raising the window is the supported mitigation. A silent child still enters contact loss and
the configured recovery window; source edits by themselves cannot prove continuing contact when
observation is unavailable. Terminal parents are refused new child work with
`lineage_parent_work_terminal` and continue through a successor task (`lineage_successor_task`).

The isolated native cell below exercises the parent-minted path for the reviewed legacy
`codex-cli 0.150.1` profile. Broader host profiles need their own execution evidence; host hooks
alone never mint a child.

A fresh project-marketplace carrier requires the supported TUI **Trust all and continue**
ceremony. Before native verification, inspect app-server `hooks/list`: the reviewed carrier has
13 enabled, trusted hooks, including `SubagentStart` and `SubagentStop`, with no warnings or errors.
An active marketplace entry and `features.hooks=true` establish configuration; actual hook
diagnostics and admitted observations establish execution. Keep source-stream coverage separate:
a rollout may contain `spawn_agent` and `wait_agent` records without a usable subagent identity.
Such a stream cannot establish a parent lineage annotation or a late-stop replay by itself.

The 2026-09-07 native cell used source `80d0d94c` and the development `0.1.0` wheel at SHA256
`18b0e5ecd9cc09acb06dd805d90c01dc506241a26e2405b152dec36a51ec6f9d`. All 475 installed package
files matched the wheel. `codex-testing 0.150.1` ran in an isolated home and workspace, with a
trusted project-marketplace carrier, a strict owned MCP route, `multi_agent_v2=false`, and a
synthetic loopback Responses provider. The native process exited `0`; parent start, delegation,
one legacy child, child attach, publication, local check, receipt, and child terminal
completion were recorded. The check and receipt returned structured success with local
coverage and matching child/check frontiers. Parent mapping snapshots remained stable and a
separate child route appeared after attach.

Actual native hooks recorded one `SubagentStart` and one `SubagentStop` with the same child
identity and no gaps on those events. Parent lineage showed one accepted `parent_minted` child and
one provisional `host_observed` annotation. The native payload omitted `parent_tool_call_id`, so
the annotation remained unbound. Two native rollout streams contained 39 and 29 records but no
`SubAgentActivity` or usable child identity fields. Replaying the exact captured streams accepted
zero new records; this proves cursor idempotency, not a newly emitted late stop or session rotation.
The host supplied no structural child-finding outcome, so synthetic advice-policy checks remain
separate from this native evidence.

The native record retains `content_capture_unavailable`, `unpaired_event`, and `unsupported_event`
coverage gaps, plus four bounded `drain_budget_exhausted` diagnostics. A later manual-reconcile
pass on that artifact exposed UUID truncation and left 62 stream rows with `mapping_missing`;
those rows were not native hook or provider failures. The child remained open with contact lost
after host exit, and its recorded receipt did not close work or erase incomplete coverage. This
cell does not prove production model behavior, semantic review, or other Codex profiles.

Manual reconciliation of a native `rollout-*` file requires one full session identity already
bound to the selected workspace, or, for a v2 delegated child's own rollout, one validated child
lane resolved through its header (#841, above). It shares the automatic stream cursor and refuses
an unmapped, ambiguous, or foreign-workspace session as `mapping_missing` before ingesting it. Compressed
`.jsonl.zst` files retain the bounded `unsupported_format` result. Existing truncated aliases are
left visible as legacy recovery gaps; a filename cannot authorize rebinding or deletion of their
pending rows.

The repair was installed from source `931acec4`, wheel SHA256
`1a378d66b71c945a1f2d507f8534f0308265ec7c7fc238f500559539a2956a3a`; all 475 installed package
files matched the artifact. Two public `observe reconcile` calls over the captured parent rollout
returned exit `0`, accepted zero new records, and retained event position 39 and generation 1
without rotation or truncation. The unmapped captured child rollout returned `mapping_missing`.
Full-row digests confirmed all 62 historical pending rows and the four existing bindings remained
unchanged. Before/after file digests also confirmed the original capture and mappings were
unchanged. This installed CLI replay used copied structural state and read-only captured inputs;
it did not launch another native host or service.

The composed READY regression separately exercises parent session/writer rotation, a late
`SubagentStop`, service close/reopen, and a subsequent parent `Stop`. Public lineage and advice
retain the same annotation ID, without a duplicate annotation or changed observation timestamps
from rebuilding advice. This is service conformance evidence; the native cell above did not emit
a child-finding outcome.

The rendered `SessionStart`, `UserPromptSubmit`, tool, and turn-boundary commands bind
`--workspace .`. Codex's hooks contract (re-read 2026-09-03) gives every hook the session `cwd` and
runs command hooks from that directory, so `.` is the current project/subdirectory and the shared
canonicalizer resolves it to the safe Git root. `UserPromptSubmit` must keep that explicit argument:
without it, a fresh unmapped session has no older session binding from which to recover the
workspace and its bounded auto-attach retry stops before a service call.

For supported content-bearing Codex hook events, the native adapter reads the documented
`PostToolUse.tool_response` output and the explicitly linked code/diff fields. The ready service
secret-scans and encrypts selected tool output, changed-file/code, and workspace-diff bytes before
materializing their exact digest/object bindings as `observation_captured` ledger evidence. This is
the source-qualified,
profileless `codex_hook` arm: active observation consent and the exact hook source bind it; no
Claude/Cursor content profile is inferred or accepted. Inspection facts and bounded excerpts
receive separate evidence records. This proves retained byte identity only; it is not an approved
check, artifact verification, independent reproduction, or permission to send the bytes to a model.
Installation, an object header, a successful structural receipt, and a typed MCP response are
separate evidence; none proves that the provider selected native Codex bytes.

The Codex hook capture arm is eligible only for content explicitly linked to the hook event and its
exact task, workspace, host/FinishUP session, source generation, tool-call correlation, multipart set,
object kind, and digest. Codex session-stream records remain outside the native ticket lane and are
excluded from AI-powered review selection. Generic tool input and path/locator content are excluded from
AI-powered review selection. Recognized `apply_patch` arguments are captured as workspace-diff
content from the post-tool event, with workspace-relative locators and the host-reported outcome
(see "Reviewable native edits").
Encrypted capture and AI-powered review disclosure have separate authority: selecting these
bytes into a frozen AI-powered review case still requires the effective repository privacy grant and
the independently authorized provider attempt.

For the supported native `hooks observe` path, the hook first closes its local structural envelope,
pairing, lifecycle intent, and outbox state, then presents eligible content to the service-owned
capture lane before the structural FIFO advances. The capture acknowledgement follows durable
encrypted object/manifest and metadata-ticket publication; native content is never copied into the
structural spool. If authenticated staging cannot complete during the bounded pass, a completed hook
records `content_capture_unavailable` alongside the structural record. A host process killed before
that boundary may still leave the honest content gap; after the ticket is durable, a later
structural retry can reuse its fenced manifests without rereading a plaintext spool. Advice
selection remains after drain, and advice is committed only after the host output is emitted.
`SessionEnd` records its lifecycle intent and defers service delivery without rebuilding local
advice, because the closing host cannot receive it. A later hook or the service sweeper drains the
end event and refreshes advice. The encrypted capture-ticket handoff does not change Codex's
historical session-stream path. Session-stream reconciliation remains a separate source and cannot
supply content to a `codex_hook` ticket; session-stream, generic input, and locator content remain excluded
from AI-powered review selection. Codex keeps its existing replay semantics; the
shared operation-replay, source-generation fencing, and teardown repairs apply to all host adapters.

Provider-repair advice is standing advice, so Codex delivers it only at session boundaries (#844).
`SessionStart` carries it in `hookSpecificOutput.additionalContext`. `Stop` no longer carries it
(#985): Codex can show Stop text only as `decision: block`, which continues the agent and spent the
turn's continuation the closure gate needs. A Stop that finds it pending marks the session, and the
first later `PostToolUse` carries it once in `additionalContext`.
Any other `PostToolUse` and `UserPromptSubmit` do not carry it. A private or no-egress install, an install
with no provider endpoint, and an install whose verification is disabled do not emit
`connect_provider`, `renew_provider_sign_in`, or `repair_semantic_provider`. The service emits
that advice only when verification is not disabled, a provider endpoint is bound, network egress
is permitted, and an LLM inference channel is enabled, and the provider is still structurally
unusable, including when no factory id is available. `SessionEnd` still emits `{}` and does not
consume a pending delivery.

**Stop-time closure gate (host decision: supported).** When a mapped session stops while closure
still requires agent action, the `Stop` hook continues the agent once with `decision: block` and a
`reason` naming what remains. Codex honours every Stop block in a turn and sets
`stop_hook_active` on each Stop after the first (codex-rs `turn.rs`; its test
`stop_hook_can_block_multiple_times_in_same_turn`), so the cap below is FinishUP's own: a
single-turn `codex exec` run gets the gate once and at most one further continuation (an announced re-check or a withdrawn deliverable not yet voiced).
Ordinary advice is withheld at Stop because Codex can only render it as `decision: block`. The decision reads only the service's compact `status` for the mapped session (`closure_readiness`, read on the route the session's MCP server named on its last successful `status` or `check`, remembered across service restarts); it fires when `agent_actionable` holds open obligations, an unconfirmed blocker, an unrepaired receipt-blocking finding (agent work only), a finding the agent rejected that awaits a reviewer ruling (`finding_rejection_awaiting_ruling`), a planned verification that was not observed, failed, or ran before the latest edit, an edit to the work after the last verification run (`edited_after_last_verification`; temporary scratch and FinishUP-owned writes such as a saved receipt never count, ADR-042), a git-ignored requested output, or a declared deliverable deleted or renamed away (`declared_output_removed`, ADR-035), or a declared deliverable that held content and is now empty or truncated (`declared_output_emptied`, ADR-041 and ADR-045: keyed on the file, not the obligation, so acknowledging or republishing the obligation does not clear it; the gate text says why from the file's recorded history and names the one exit, a `finishup-assumption` decision that names the file; a standing `declared_output_content_moved` disclosure adds an informational note to gate text that fires anyway, never a token), or a delivered source file that may read a file the agent created and no requested item declares (`deliverable_references_undeclared_file`, #1044, ADR-035 amendments: a name the deliverable provably only writes does not count, and a bare file name a declared file shares, or that nothing ties to the file's directory, is counted on the receipt as `deliverable_references_ambiguous_name` instead; the text names each such file, quoted and bounded, from `closure_readiness.undeclared_references`, where a name the agent itself published in this session returns to it even when its privacy policy withholds repository excerpts, and tells the agent to embed it, rebuild it at run time or declare it, or the directory holding it, as a delivered output; when a name is withheld it says why and gives the agent's own shell command that lists the files its change created; disclosing the dependency does not clear it, and no path is remembered. Host decision for the tb4n5 naming: supported, same code path), at most once per ledger frontier and session (owner-only `observation/closure-gate.json`). Before that read the Stop pass drains this task's hook rows toward the current frontier (at most 2.5 s and 64 rows, keeping the gate's five-second reserve) and records `stop_drain_complete` or `stop_drain_incomplete`; rows of other tasks or unmapped sessions in the workspace do not hold the decision (#994). Verification items (planned verification and edits after the last verification run) are dropped only while this task's own hook rows are still draining after the Stop drain, and the text says so only then. The text pushes repair first: a receipt-blocking finding the agent repaired but FinishUP cannot prove (a FinishUP limit) is self-verified and answered with `respond` `self_verified`; `acknowledged_not_done` is the last resort; a FinishUP limit is never a `finishup-blocker`, and the blocker sentence appears only while obligations are open. An open obligation named by a `finishup-blocker:<kind>` decision is not listed as work, but each new `<obligation id>:<kind>` is re-asked once: the re-check names the obligation and claimed kind from the `blocker` entries of `closure_readiness.rechecks`, says recoverable data, a failing test, an infeasible-looking result or a FinishUP limit is not a blocker (finish the obligation and disclose the limit), and only there tells the agent how to confirm a genuine one: publish the same line again in a later decision whose rationale names what was re-checked, so the MCP bridge never refuses it as an unchanged id-less resend (the blocker offer never says so, and a confirmed row is never re-asked). Because blockers are usually published after the first gate, the re-check also runs on a Stop the host already continued: there it reads status, continues the agent only for a re-check key status announced that the gate has not asked, or a withdrawn deliverable not yet voiced (never for ordinary items), at most once per Stop and at most two gate continuations per turn (owner-only `observation/closure-gate-turns.json`, reset at every Stop the host did not continue; an unreadable counter counts as the cap), and lets the agent stop on any error, a short budget, or a memory write failure. Asked keys are remembered per session (owner-only `observation/closure-gate-blockers.json`, at most 64). Ordinary advice is never delivered at Stop; it waits for the next tool event or session start. Standing advice a Stop withheld rides the first later `PostToolUse`. Every outcome is a hook diagnostic (`closure_gate_continued`, `closure_gate_blocker_rechecked`, `closure_gate_active_stop_rechecked`, `closure_gate_memory_unwritten`, `closure_gate_not_required`, `closure_gate_repeat_suppressed`, `closure_gate_turn_end_after_continue` (an already-continued Stop that emitted nothing: the normal end of a continued turn, renamed from `closure_gate_loop_guard`), `closure_gate_budget_exhausted`, `closure_gate_unavailable`) in `finishup observe status`. The text also says an inherent verification limit or a best-effort choice is disclosed with a `finishup-assumption:` or `finishup-verification-limit:` decision line, never blocked, and names an obligation-level `acknowledged_not_done` as the last resort (#995, #997). Re-checks are not riders on other tokens (tb4n3 RC-8, #1031). Status announces them in `closure_readiness.rechecks` (acknowledgement, blocker, premise, each with a content key; the same list `status`, `closure_prepare`, the CLI and the TUI show, and the status directive names it: "At Stop you will be asked once to re-read: ..."), and the gate asks exactly the announced ones, each once per session and key (`ack:<obligation id>`, `<obligation id>:<kind>` for a blocker, `premise:<acknowledged count>`, all in the blocker-key file; closed items `acknowledgement_recheck`, `blocker_recheck`, `premise_recheck`). A readiness without the list (a service older than the gate) announces none, so the gate asks none. Acceptance provenance (ADR-033 amendment of 2026-10-18, owner decision D1): a resolved obligation the ledger flags (a requested item never attempted, evidence not linked to a declared item, or only self-asserted evidence) with neither an admissible observed verification link nor a recorded verification limit is never a Stop item. Status, `closure_prepare`, the CLI and the TUI name it once in the closure guidance (`closure_readiness.acceptance_risk`), and the receipt records it as the coverage limit `unresolved_verification_limitation` (the conclusion is at best `insufficient_coverage`). If an output does not meet its acceptance criteria, the agent republishes that obligation `acknowledged_not_done`; an acknowledgement that directly follows a `resolved` publication of the same obligation (an honest downgrade) is not challenged by the acknowledgement re-check. The gate drops an `acceptance` entry an earlier 0.3 service still announces and writes no `accept:` key and no `closure_gate_acceptance_rechecked` / `closure_gate_acceptance_covered` diagnostic (both names stay readable); `accept:` memory an earlier build wrote is still read, so an acknowledgement published after that invite is not challenged. Final message: Codex's Stop body still carries `last_assistant_message`; the hook no longer reads it, and a `finishup-acceptance:` or `finishup-verification-limit:` line in it is ignored (a `finishup-verification-limit:` decision published through `publish_work` is still recorded and lifts the coverage limit). Host decision: acceptance-provenance risk is never a Stop item on Codex, and the hook does not read the final message. The premise ask stays on Stops the host has not already continued; the acknowledgement re-check may continue an already-continued Stop within the same caps. A finding the agent rejected with a reason that awaits a reviewer ruling (`finding_rejection_awaiting_ruling`) sends the agent to `check` with `final_review: true` and never offers acknowledgement; `receipt_findings_unresolved` counts agent-work findings only, and `self_verified` is offered only while `finding_counts.self_verify_eligible` is positive. A deliverable that held content and is now empty or gone (`declared_output_emptied`, `declared_output_removed`) is voiced once per key (`emptied:<h8 of the declaring obligation items>`) even on an already-continued Stop, with the rule and obligation ids and never a path (every Stop after the first gate is an already-continued Stop in a single-turn run). The premise and acknowledgement texts say that if the agent cannot finish the work it keeps the working deliverable: acknowledgement never requires withdrawing or emptying it. Host decision: supported, same code path (the gate, its texts, its re-check list and its memory are shared by the Codex, Claude Code and Cursor Stop handlers; the only difference is how an already-continued Stop is detected, `stop_hook_active`). See ADR-033 and issues #977, #984, #985, #1031.

Mid-session, the agent can ask `check` to wait for this task's hook rows instead of polling `status`: `await_observations: true` (MCP) or `finishup check --await-observations` wakes the service sweeper and waits at most about 3 s (and a tenth of the request deadline) for the rows already pending, then reports `observations_awaited` (`complete`, `bounded_timeout` with the pending count, or `unavailable`). The decision is the same for Codex: the wait reads the shared local outbox and lifecycle mappings, so it needs no host-specific hook; it never fails the check (ADR-029 amendment, #1012). On Codex the wait also covers this task's rollout rows held for their hook post (tb4n5): one read at least 10 s earlier is released by the wait with `unpaired_event`, so it lands before the check instead of minutes after it (biped S: 12m55s), and a younger one counts in the `bounded_timeout` pending count. `finishup observe status --json` shows the held account as `held_rollout_items`.

Legacy synchronous `hooks spool` is a separate structural fast path. It only appends the owner-only
structural spool record and returns; it does not normalize or pair the event, open the service, drain
an outbox, or carry native content. The READY forwarder later consumes the spool and performs normal
service-side normalization, pairing, and forwarding.

FinishUP's own MCP tools fire these same `PreToolUse`/`PostToolUse` hooks, and the hook process that
records them also drains the outbox, so the prescribed start/status/check/respond/receipt workflow
used to feed its own backlog: two rows plus a captured result per `status` read (issue #564). The
ingress now delivers a FinishUP-owned call only as distinct evidence — an explicit host failure or
denial in either phase, or the `PostToolUse` of `start`, `publish_work`, `check`, or `respond` —
and keeps the pre-event of every FinishUP call and the post-event of a non-failed `status`, `receipt`,
or `read_guidance` in the bounded local store only. FinishUP tool input/output is never captured as
content. The same policy applies to the legacy spool replay and to the Codex session stream, so
neither path reintroduces the rows. The shared host-spelling advice guard suppresses pending
recommendation delivery on a FinishUP-owned hook without an explicit failure; no hook delivers a
frontier-motion notice at all (issue #915). Explicit
self-call failures stay retained, enqueued, and eligible for pending advice. Ordinary tools are
unchanged. The rollout's completed `McpToolCall` item (`event_msg`/`item_completed`) is read in the
`PostToolUse` phase for this policy (tb4 n5): before, it had no phase, so every successful `status`
read reached the ledger as action, result and evidence (about twelve events per read on the S
arm) and changed the very task the agent was polling. A FinishUP read item is also never held for its
hook post, and one an earlier build held is settled locally when released, never delivered. A
failed FinishUP item (`error`, `isError`, or a non-success `status`), FinishUP writes and other servers'
items are delivered as before. To confirm closure converged,
run `finishup observe drain --workspace . --json` after the agent stops and require
`terminal: drained` with `pending_after: 0`; `retry_pending` names the retryable head cause in
`reasons` (a check barrier's `operation_pending` clears when the check completes), and
`pass_limit` means a producer is still adding rows.

### Cold parser startup (N5 robustness)

The native stream parser imports its structural values and exact profiles without loading ledger
publication models. `finishup.adapters.importers.codex_jsonl` and `finishup.ports.importer` retain their
public names and lazily load mapping/publication implementations when those names are requested.
The original class lookup paths remain usable for older serialized values. No profile, parser
rule, stream-reconciliation cadence, capture scope, privacy decision or wire byte changes.

The cold-hook process regression still enforces 1.5 seconds including startup and verifies that
the realistic observation store changed. Its temporary home and workspace are mode 0700, so a
shared-group umask does not turn the measurement into a workspace-safety refusal. A separate
fresh-process regression parses a malformed rollout and checks that ledger events, ledger ports
and public request models were not loaded. Parser and mapper suites still exercise both paths.
The measured profiled pass fell from 1.39 seconds to 0.67 seconds on the development Mac; these
are individual observations, not a latency guarantee for every host or installed package path.

### Legacy synchronous-hook latency

Codex versions older than `0.148.0-alpha.6` use a synchronous `hooks spool` command for
`PreToolUse`, `PermissionRequest`, and the ingress half of `PostToolUse`. It performs one fsync'd,
structural-only append and must not connect to the service, drain an outbox, or hydrate the local
observation store. The READY service forwards those records asynchronously through the normal
fenced outbox path. The proposed (issue #362) host-visible budget is p95 `<=250ms`, with a hard
`500ms` cap per synchronous leg including process startup. `finishup observe status` reports pending
spool work as a coverage gap (`source_lag`). Every spool pass feeds the `sync_fallback_spool` entry
of `hook_diagnostics.pass_timings`, which reads the p95 target and the hard cap against every pass
(`p95_target_ms`, `hard_cap_ms`, `hard_cap_breach_count`); only a pass over the hard cap also keeps
a timing row and a `hook_slo_breached` reason, so a busy legacy host no longer evicts the
failure-reason history one row per tool call (issue #915). Do not treat a pending spool as
delivered evidence; keep the service running and wait for it to drain before making receipt
claims.

### Hook cost and timing aggregates (issue #915)

Every Codex observation hook pass (`hooks observe` and the legacy `hooks spool`) folds one sample
into a bounded aggregate that `finishup observe status --json` reports as
`hook_diagnostics.pass_timings` and the text form prints as `hook_pass_timing`. Entries are keyed
by host, raw event and path (`codex PostToolUse observe`, `codex PreToolUse sync_fallback_spool`,
...) and carry `count`, `sum_ms`, `mean_ms`, `p50_ms_at_most`, `p95_ms_at_most`, `max_ms`, an
`outcomes` tally (`ingested`, `followup_deferred`, `not_ingested`, `failed`), the histogram
`bucket_counts`, and a `recent` view over the current and previous clock hour. Read these limits
before quoting a number:

- A sample runs from the console entry to the end of the pass, after the hook's stdout was
  written. Python interpreter start and process exit are not in it (`excludes`), so the
  host-visible cost per call is the sample plus that start/exit term. Measure the term on the same
  machine as the wall time of a bare `python -c pass` from the runtime's interpreter, or from host
  timestamps (the session rollout's nested-call spacing).
- `p50_ms_at_most` and `p95_ms_at_most` are histogram bucket bounds, not interpolated values.
  150 ms is an exact bucket edge, so the share of passes within the per-call goal is exact: sum
  `bucket_counts` through the 150 ms edge (`bucket_upper_bounds_ms`).
- `hooks session-start` (resume/compact re-ground), the `start`-scoped `hooks post-tool-use`, and
  `hooks user-prompt-submit` are not in the aggregate. None of them runs per ordinary tool call,
  but each is a synchronous host-visible process (per resume or compact, per `start` call, per
  prompt), so the aggregate is the cost of the observation hooks, not of every Codex hook. Do not
  use it alone to claim Codex hook overhead is understood or to decide the async split.
- An entry's cost is host-visible only when Codex runs that hook synchronously: `PreToolUse` is
  registered async from `0.148.0-alpha.6` on, so its entry measures work the host does not wait on.
- The aggregate spans every pass since `since`; a fresh test instance starts empty. It is local
  diagnostics: owner-only, fixed-size, and not fsynced, so a crash can restart it (`since` moves).
- A hook waits at most 100 ms for the aggregate's lock. A pass that cannot take it is not in the
  counts; it is tallied in `dropped_sample_count` instead, so a nonzero value means the counts
  undercount that many passes. `observe status` takes no lock and creates no state; it reads the
  last complete aggregate.

Registration decision on Codex (issue #915, recorded 2026-09-30): the `PostToolUse` observe
handler stays synchronous for now. The DeepSWE v2 run inferred about 0.6–0.9 s per nested
code-mode call from rollout timestamps; the aggregate is what confirms or refutes that on a
product-side measurement, and the issue orders measurement before any registration change. The
candidate change, async ingress behind the same `0.148.0-alpha.6` gate as `PreToolUse` plus a
synchronous advice handler scoped to the FinishUP MCP tools or a minimal-import fast path, is not
shipped: making both halves of a tool call async lets Codex run them concurrently, which can store
a `PostToolUse` before its `PreToolUse`, and the `unpaired_event` contract that must absorb that
belongs to #917. The frontier-motion notice no longer rides `PostToolUse`, so on a session with no
pending advice the synchronous handler now returns `{}`. The per-call goal is ≤150 ms added latency
(a goal, not a merge gate). Measured numbers per OS (macOS, Linux, WSL 2) from a code-mode dogfood
run are not recorded yet; that gap is owned by issue #915, together with the async split.

### Capture and compare the live tool boundary

When a supported Codex build renders a FinishUP argument as `unknown`, capture the client inventory
before reading implementation source or changing a schema. Use a new scratch testing home; the
`codex-testing` launcher derives its real `CODEX_HOME` from `CODEX_TESTING_HOME`, so setting only
`CODEX_HOME` is not isolation.

```text
FINISHUP_CODEX_SCRATCH="$(mktemp -d /private/tmp/finishup-codex-boundary.XXXXXX)"

CODEX_TESTING_HOME="$FINISHUP_CODEX_SCRATCH" codex-testing mcp add \
  --env UV_CACHE_DIR="$FINISHUP_CODEX_SCRATCH/uv-cache" \
  finishup -- uv --directory /absolute/path/to/finishup-core run finishup mcp serve --host codex --semantic off

CODEX_TESTING_HOME="$FINISHUP_CODEX_SCRATCH" codex-testing mcp get finishup

python scripts/capture_codex_mcp_surface.py \
  --codex-binary /absolute/path/to/codex-testing \
  --codex-testing-home "$FINISHUP_CODEX_SCRATCH" \
  --output "$FINISHUP_CODEX_SCRATCH/mcp-server-status.json"
```

Confirm `mcp get` names only the scratch registration before capturing. Record the exact Codex
build, FinishUP commit or artifact digest, route profile, capture digest, and whether the evidence is
raw `mcpServerStatus` inventory, a declaration actually delivered to a model, or both. Compare
`start`, `publish_work`, and `check` for local references, union-only array items, and conditionals
in object-shape position. A raw inventory proves what Codex received from FinishUP; it does not by
itself prove what a model was shown. Keep before and after captures side by side and state that
evidence boundary explicitly.

Claim correction is an ordinary `publish_work` capability, not a Codex-hook mapping. A current
descriptor advertises `publish-work-request/1.1.0`, which admits `claim_recorded/1.1.0`; older
descriptors remain limited to the frozen v1.0 draft union. The CLI command uses the same public
request and service boundary. Neither Codex hooks nor imported observations synthesize, replace,
or supersede claims.

## Legacy Yoetz registrations

FinishUP was named Yoetz through 0.2.5 (ADR-048). A Codex home and project connected by Yoetz carry
the MCP key `yoetz`, the `[marketplaces.yoetz]` and `[plugins."yoetz@yoetz"]` tables, the cache
`plugins/cache/yoetz/yoetz/<version>`, the project trees `.agents/plugins/yoetz` and
`.agents/skills/yoetz`, and admission entries under the `yoetz` server name. FinishUP reads all of
them; it writes only the `finishup` spelling. Owned-but-outdated state keeps working until it is
migrated: the hooks, start binding and tool classification accept `mcp__yoetz__*` and the `yoetz`
launcher.

**MCP registration.** Each observation reads the `finishup` key and the legacy `yoetz` key together
(`codex mcp get finishup --json`, then `codex mcp list --json`). `finishup integrate codex mcp
status --json` keeps the released `state` values (`yoetz_owned` still means "FinishUP's own") and
adds `legacy_registration`:

| `legacy_registration` | Meaning | What FinishUP does |
|---|---|---|
| `none` | No `yoetz` entry. | Nothing. |
| `legacy_only` | The only FinishUP-owned entry uses the `yoetz` key: owned but outdated. | Integrate (or the guided connection) migrates it under one preview: it writes `finishup`, re-checks the legacy entry, then removes `yoetz`. Preview warning `legacy_registration_owned`. While a project still needs the `yoetz` key (below), it writes `finishup` and keeps `yoetz`. |
| `duplicate` | Owned entries under both keys. | Integrate removes the owned `yoetz` entry unless a project still needs it (below); remove and disconnect take both once nothing needs either. |
| `foreign` | A `yoetz` entry FinishUP cannot prove is its own. | Reported (warning `legacy_registration_foreign`) and never touched. |

Remove and disconnect select the owned entries independently: an owned `yoetz` entry can be
removed beside a foreign `finishup` entry. The interactive removal preview names the owned keys
and explicitly says the foreign `finishup` entry is retained. After that removal, guided
disconnect reports `configured: false`; the retained foreign entry is not a FinishUP connection.

A `yoetz` entry is owned only with proof: a bare `finishup` or `yoetz` launcher, this runtime's
proven launcher, or this runtime's `yoetz` alias. `<scripts>/yoetz` is FinishUP's when the
transitional `yoetz` distribution's installed RECORD proves it, digest included; while any `yoetz`
distribution is installed nothing else proves it, so a modified, symlinked or loosened script is
foreign. The exact sibling of the proven `finishup` script counts by location alone only when no
`yoetz` distribution is installed or nothing is at that path. Isolated entries may carry
`FINISHUP_ISOLATED_ROOT`, `YOETZ_ISOLATED_ROOT`, or both with the same value; new registrations
write both, a single-name entry re-registers to the both-name form, and two different values are not
FinishUP's. A migration-only re-registration keeps the existing `policy` or `strict` route
(`route_profile_before` in the preview). A legacy entry bound into a preview digest uses the tags
`yoetz.mcp-registration-preview/5` and `yoetz.mcp-unregistration-preview/5`. If the legacy-key
removal cannot be verified, or the entry changed after preview, the error's safe details carry
`legacy_state` (`yoetz_owned|foreign_present|absent|unknown`).

**A project that still needs the `yoetz` key (#1073).** Yoetz 0.2's `integrate codex admission
grant` wrote `[mcp_servers.yoetz.tools.check]` into a project's `.codex/config.toml`. That table has
no transport of its own; Codex takes it from the user-level `yoetz` entry, and once that entry is
gone Codex refuses to load the project ("invalid transport in `mcp_servers.yoetz`"). So before it
migrates an owned `yoetz` entry, the adapter reads every project this home knows (its trust rows
and verified members, including the Yoetz-era bound project; each project file is a bounded 64 KiB
read, and the user `config.toml` is read within Codex's own 1 MiB bound). The entry stays beside
`finishup` when a readable `.codex/config.toml` names `mcp_servers.yoetz` without a transport
(`depends`), when a project's file cannot be read safely (a symlink, not a regular file, over
64 KiB, or not valid TOML), or when the home's own inputs cannot be read: the user `config.toml`,
the connected-projects record, or a project path holding a control character (that path is never
read or echoed). The preview then writes only `finishup` (warning `legacy_registration_kept`,
`legacy_kept_for`, `legacy_kept_unreadable`, `legacy_kept_unchecked`, `legacy_kept_unread`,
digest tag `/6` binding them all), apply leaves `yoetz` alone, and a connect that finds
`finishup` already current changes nothing more. The guided connect plan drops
`migrate_legacy_mcp_registration`, warns `legacy_registration_kept`, and lists
`legacy_registration_kept_for`, saying for each project what holds the entry and what releases it:

- only exact earlier-name approval tables: the revoke (`next_arguments`)

  ```text
  finishup integrate codex admission preview --project-root <project> --action revoke
  ```

- a file it could not read (`dependence: "unknown"`, `unreadable` names why): make it a regular
  file you own, under 64 KiB, with valid TOML, or remove that project's trust entry from
  `<codex home>/config.toml`;
- tables you edited under `mcp_servers.yoetz`: remove them yourself.

`legacy_registration_kept_unread` names what of the home could not be read, with what makes it
readable. "After those revokes, connect again" is promised only when the revokes are all that
hold the entry; otherwise the step says to connect again once nothing listed holds it. Every kept
case also names the explicit way out, as the owner's choice: remove FinishUP's MCP registration
from this Codex home under both names with the low-level preview and its digest, then connect
again (`mcp_removal_preview_arguments`, `reconnect_arguments`):

```text
finishup integrate codex mcp preview-remove --codex-path <codex> --codex-home <home>
finishup integrate codex mcp remove --codex-path <codex> --codex-home <home> --accept --preview-digest <digest>
finishup setup run --host codex --host-path <codex> --host-config-root <home> --project <project>
```

Every project of the home loses FinishUP until one connects again, and a project whose Codex
settings still name the removed `yoetz` server stops loading its Codex configuration until those
tables go (`setup status --host codex` there names the step); the text says so. `setup status
--host codex` reports the same facts (read now) while the owned `yoetz` entry exists, and the
menu summary and the terminal interface's `MCP registered` line say the entry is kept, and
whether a project still uses it or only not every project could be read. The interactive `finishup
setup` approval and `integrate codex mcp install` say it is kept (with the same lines), and their
results carry the facts. A disconnect keeps both keys while any project needs either
(`admission_other_projects`), and the last one, after its own sweep removes the exact earlier-name
table, removes both. The kept `yoetz` entry serves every project of the home on its own review
mode, so a connect that would register `finishup` on another one stops before any change with
`connection_legacy_registration_route_kept` (`route_profile_before` is the kept entry's mode). The
refusal keeps either mode reachable: the same command on the kept mode (`keep_route_arguments`,
built with the selected `--host-path`, `--host-config-root` and `--project`), or the way out above
and then the requested mode. The terminal interface blocks before its approval screen, the shared
integration step behind the wizard and both applies fails with that reason, and `integrate codex
mcp install` exits 2 with `mcp_registration_legacy_registration_route_kept`, naming its own
`install` rerun on each mode.

**Plugin activation.** The project's Yoetz-era activation (the exact legacy
`.agents/plugins/marketplace.json`, byte-identical `[marketplaces.yoetz]` and
`[plugins."yoetz@yoetz"]` tables in the selected Codex home, and the marker-validated
`plugins/cache/yoetz/yoetz/<version>`) is reported as `legacy_activation` and is replaced in the
same digest-bound activation preview. As its last step, after the legacy tables, document and cache
are gone, that activation also deletes a marker-consistent `.agents/plugins/yoetz` tree, and the
preview digest binds that deletion. The tree is kept whenever any row of the activated repository
marketplace document is not exactly FinishUP's own row (named `finishup`, source `{"source":
"local", "path": "./.agents/plugins/finishup"}`), whatever that row's name, source form or path
spelling, and whenever the activation step is skipped (no `--codex-home`, or a non-interactive
`--accept` without activation approval). `finishup integrate codex` and plugin install never delete
it on their own.

Every surface that approves an activation shows these deletions before approval: the interactive
setup preview and `finishup recommend accept codex-plugin-activation` print the exact legacy tables,
the plugin cache versions and the plugin source tree line (the recommendation refuses with
`activation_preview_invalid` when the preview lacks one of them), and the terminal interface's
connect preview lists them as `~` lines. The guided connection plan (`finishup setup run --host
codex`) adds the change token `remove_legacy_plugin_sources` when the approval deletes
`.agents/plugins/yoetz` and `remove_legacy_project_skill` when it deletes an owned
`.agents/skills/yoetz`, even on a tree-only Yoetz 0.2 install with no legacy registration or
activation; either keeps the connection from reading as already complete. The removal preview
(`finishup integrate codex plugin preview --json`) reports the legacy activation it also deactivates
as `legacy_removed_block`, `legacy_cache_versions` and `legacy_marketplace_json_planned`. A legacy
table for this project that is not byte-identical is refused as a conflict
(`legacy_config_marketplace`, `legacy_config_plugin`). Another project's legacy activation,
unmanaged cache content and a modified legacy tree (`legacy_plugin_tree_retained`) are left alone.
FinishUP removes the legacy tables and cache directly; it does not run `codex plugin remove
yoetz@yoetz` or `codex plugin marketplace remove yoetz`, and other Codex-internal state for the
legacy plugin is not observed. A live check on a real 0.2.x activation is open on #1056.

**Several projects in one home (#1058).** A project's Yoetz-era activation is that project's own,
not a shared piece: Yoetz 0.1-0.2 bound one project per home, and the legacy tables name it. The
user-level registration it used is shared, though, and Yoetz kept no record of who used it. So the
project a byte-identical `[marketplaces.yoetz]` table names, while its checkout still serves the
exact Yoetz-era marketplace document, counts as a connected member of the shared registration:
another project's connect records it beside itself, `setup status` lists it in
`codex_home_projects`, and another project's disconnect keeps the registration for it (`retained`
"FinishUP MCP registration used by other connected projects", `shared_with` naming it). It never
becomes the FinishUP binding's anchor, since it does not serve FinishUP's manifest: when the
disconnecting project anchors the binding and no other project serves that manifest, the disconnect
removes the FinishUP plugin pieces (`deactivate_plugin`) and keeps only the registration: the
preview adds `shared_plugin_removed: true`, `shared_with` names only the projects the registration
stays for, a recorded FinishUP project whose plugin files are missing right now is listed in
`members_not_serving` (it loses the plugin and connects again later), and the summary reads "The
shared FinishUP plugin is removed from this home; only the MCP registration stays for: <projects>".
Yoetz-era shared pieces found without a record (an exact legacy marketplace or plugin table, or a
FinishUP-shaped `[mcp_servers.yoetz]` entry) also make membership uncertain, as an earlier release's
pieces do: trusted checkouts that serve FinishUP's manifest are possible users, a connect records
`unknown_members`, and a disconnect that would leave only them stops as `membership_unverified`.
Without such a checkout or another member, an ordinary disconnect removes the registration, also for
a single Yoetz-era project (unlike Cursor's `plugins/local/yoetz`). A disconnect that only detaches
the project (other connected projects keep the shared FinishUP plugin, cache, binding and
registration) still deactivates its own legacy activation in the same digest-bound plan: the exact
tables leave with the approved `config.toml` write (also when the binding moves to another project),
then the exact legacy document and the marker-validated legacy cache go, and the result must read
`legacy_activation: false`. The detach preview reports them in `legacy_removed_block`,
`legacy_cache_versions` and `legacy_marketplace_json_planned` beside `shared_with`. The user-level
`yoetz` MCP entry is shared like the `finishup` one: a disconnect that keeps the registration for
other projects keeps an owned `yoetz` entry too (`remove_legacy_mcp_registration` appears only when
the unregistration runs), and the last disconnect or `--remove-shared` removes both. When it does,
the check that no project's `.codex/config.toml` still needs the user-level transport covers
`mcp_servers.yoetz` tables as well, after the admission sweep has removed the exact legacy entries;
the sweep runs for a project whose only entry is an exact legacy one, and the plan's
`admission_cleanup` names it under `legacy_entries`. On a foreign approval file (an approval table
you edited, or a server-wide default) the sweep edits nothing, so exact legacy entries there neither
plan `remove_project_admission` nor count as removed when the disconnect checks what still needs the
transport.

Decisions from the 0.3 port review (2026-10-15), per host: for Codex, Yoetz-era pieces found
without a record do not by themselves keep anything. They make trusted checkouts that serve
FinishUP's manifest possible users (which keep the registration, or stop the disconnect as
`membership_unverified`), and the bound Yoetz-era project is a member; with neither, an ordinary
disconnect removes the registration, also with a single project. Cursor's rule for
`plugins/local/yoetz` is stronger (found without a record, it stays until `--remove-shared`),
because Cursor has no binding that names a project. Claude Code lists every project's install
itself and needs neither. The `mcp_servers.yoetz` leftover diagnosis, keeping an owned `yoetz`
entry a project still needs, and the post-disconnect `shared_registration_retained` status are
Codex-only, since only Codex has a user-level transport a project table depends on.

**Project skill.** Skill install and remove also take a `.agents/skills/yoetz` tree that matches its
own install marker (preview warning `legacy_skill_tree_owned`; disconnect removes it too, change
`remove_legacy_project_skill`). Anything else under that name is reported as
`legacy_skill_tree_retained` and kept.

**Admission.** Grant writes only `[mcp_servers.finishup.tools.check]` or
`[plugins."finishup@finishup".mcp_servers.finishup.tools.check]`. The exact legacy forms
`[mcp_servers.yoetz.tools.check]` and `[plugins."yoetz@yoetz".mcp_servers.yoetz.tools.check]` are
reported as `legacy_entries` and `legacy_grant` (`absent|in_use|stale|unverified`). The external
form is judged on the legacy MCP key alone. The plugin form reads `stale` only when no Yoetz-era
plugin activation can be enabled: FinishUP reads the default Codex home's `config.toml` and the
project's `.codex/config.toml` without running Codex. A `[plugins."yoetz@yoetz"]` table counts as
an activation when it sets `enabled = true` (what a Yoetz-era activation wrote), or when it holds
keys other than the `mcp_servers` subtable the plugin-form admission entry implies and does not set
`enabled = false`; another project's activation counts too. The admission entry alone is not an
activation, so with no other activation it reads `stale` and a grant retires it. TOML cannot tell an explicit but otherwise
empty `[plugins."yoetz@yoetz"]` header written next to that admission subtable from the implicit
table the subtable creates, so that pair also reads as no activation; an explicit empty table on its
own still counts. If one may be enabled it reads `in_use`; if a config cannot be read, or the
`yoetz@yoetz` entry is not a table, it reads `unverified` and a grant keeps the table.
`admission status|preview --json` reports that fact as `route.legacy_plugin_activation` (`true`,
`false` or `null`; always `null` on other hosts). Revoke and the MCP and plugin removal sweeps
remove the legacy forms; a grant retires them once nothing FinishUP owns uses the `yoetz` name
(preview warning `legacy_entries_removed`; otherwise `legacy_entries_retained`), refuses with
`legacy_registration_active` while Codex still serves FinishUP only under `yoetz` (migrate the
registration first), and refuses with `host_admission_preview_stale` if the legacy entries change
between the command's own observation and the preview's. A non-exact legacy table is not FinishUP's
and stays. These facts come from the default Codex home; a Codex run under another `CODEX_HOME` is
not observed, and the result fails safe (legacy entries kept, or `unverified`).

**Write scope.** The `.agents/plugins/yoetz` and `.agents/skills/yoetz` trees and `yoetz_receipt.*`
or `yoetz-export.*` artifacts are still classified as FinishUP's own (`yoetz_owned`, non-counting).

An owned registration under `yoetz` beside a foreign `finishup` entry can still be removed:
remove and disconnect delete only the owned `yoetz` entry, and their preview warns
`foreign_entry_present`. Register refuses to overwrite the foreign `finishup` entry. To migrate
instead, remove or rename the foreign entry yourself, then integrate again.

**Manual steps for state FinishUP cannot prove.** FinishUP never removes these; inspect each one and
remove it yourself only if it is a leftover:

- A `foreign` `yoetz` MCP entry, including one whose absolute launcher points at a runtime that no
  longer exists (for example a pre-upgrade tool path): `codex mcp remove yoetz`.
- A non-identical legacy table, a modified `.agents/plugins/yoetz` or `.agents/skills/yoetz` tree,
  or unmanaged content under `plugins/cache/yoetz/`: review and edit or delete it by hand.

Because the observation now always runs `codex mcp list --json` after a successful `get`, a Codex
build whose list fails reports `harness_unavailable` or `parse_failed` instead of a state.

## Tool outcomes (issue #910)

Codex states a tool call's outcome only inside the `PostToolUse` `tool_response`, never as a
top-level field. For each tool family FinishUP reads only closed facts. It records them as the result's
`outcome` and, when the host states one, its `exit_status` in the range `-1..255`:

- **Shell and exec calls** (`Bash`, `exec_command`, `shell`, `local_shell`, including each nested
  `tools.exec_command` in a code-mode `exec` cell): only the `exit_code` of a host-structured exec
  result *object*. Codex hook stdin never carries a shell exit (n7 RC1, #1105; Codex rust-v0.120
  through v0.159 source, fixture OUT-004): a `Bash` `tool_response` is a JSON string holding the
  command's own (possibly truncated) output and nothing else. The `Exit code: N` and `Process
  exited with code N` headers and the nested exec JSON are rollout function-output shapes; on hook
  stdin they appear only when the command prints them (`printf 'Process exited with code 0\n'`
  before a failing `pytest` would forge a success), so a shell call's text response is never read
  as an outcome, and neither is a string result read as JSON by the routine-read classifier (output
  that is itself `{"success": true}` proves nothing). The exit comes from a joined session-stream
  item that states it: a `CommandExecution` item, whose id is the hook's `tool_use_id` (below). A
  call the rollout carries only as `function_call` / `function_call_output` rows gives no exit
  until the stream reader reads Codex's own header on that row (n7 W2); until then the failed call
  stays `unknown`, never a success. The code-mode `exec` cell itself is never read: its result is
  model-authored. A result sent as a JSON object with a fractional number is refused whole by the
  strict hook parser (`float_forbidden`).
- **`apply_patch`**: the `Exit code: N` header.
- **MCP tools**, including FinishUP's own: only the protocol-level `isError`. The result body is
  tool-domain data.

Output text is never searched for words such as `FAILED`, and conflicting facts resolve
failure-first. A result that states no fact stays `unknown` and carries `host_outcome_unavailable`
for that record only. Examples are every Codex `Bash` post (its exit arrives with the rollout
item), an MCP result without `isError`, and a shape outside this list. The gap therefore
leaves a session's coverage only when every observed call had an outcome. Outcomes are structural
facts: they are read whether or not content capture is granted, and no command or output text is
kept.

The session stream carries the same facts. A rollout `event_msg` whose payload is
`item_completed` and whose item is a `CommandExecution`, `McpToolCall` or `FileChange` is a
completed tool call, and its `status` (`completed`, `failed`) and `exit_code` are its outcome. A
command item names no tool, so it is recorded as `command_execution` (a patch item as
`file_change`). An `exit_code` of `null`, as on a declined command, states no outcome. When a
hook call id equals the rollout item id, the stream fact appends a correction to an `unknown` hook
result and never rewrites it (ADR-022 decision 15). In 0.159 the ids join: the item id is the
dispatch `call_id` the hook's `tool_use_id` carries (`core/src/tools/events.rs`), and a code-mode
nested call uses its `exec-<uuid>` dispatch id for both. A build whose item did not join would
leave the stream copy as a second, fact-less action that stays material (a documented residual).

Whether or not the ids join, the rollout item is a second copy of a hooked call: in 0.159 under
the same id, and in an older or derived shape (and in the residual above) under a different id
(`exec-<uuid>`), so it follows the same rule as a code-mode `exec` cell (#917). Once this session's
tool hooks (`PreToolUse`/`PostToolUse`) have fired, the reader keeps a completed command, MCP or
patch item in the local store and does not deliver it, unless the item is the only carrier of a
hooked call's outcome. The reader pairs items with hook posts per call, in arrival order. An item
whose id is an outcome-less hook call, for example a process still running when its hook fired, is
that call's exit: ADR-022 decision 15 appends the correction to the hook's `unknown` result. A
command item whose exit matches an unpaired stated hook post of the same command commitment is that
post's copy and stays local. Otherwise, while an outcome-less hook call of the same commitment is
unpaired, the item records that call's exit as its own result. That run is then two actions, a
disclosed trade-off, and #909 judges the later one. Because pairing is counted per call, a later
call's stated outcome never withholds an earlier same-command call's only exit. A rollout item can
be read before its own hook post is stored, for example when another call's hook reconciles the
stream while the call is still finishing. Such an item stays local as pending until a later hook
row decides it. A post with the item's own call id decides it directly: a stated post makes it
that post's copy, and an outcome-less post makes it the call's only exit. A stated post of the
same command commitment takes a pending item with the same exit as its copy. An outcome-less post
of that commitment takes its pending items only once no other call of the same command is still
open (its `PreToolUse` seen, its post not yet). A call whose `PreToolUse` the local envelope ring
evicted stays open until its post is seen, its post is evicted too, or the turn ends. With
parallel runs of one command, an open call's post may still claim one of those items, so the
reader waits for it instead of guessing by age.
When more items remain than outcome-less calls, every one is delivered: a second record, judged by
#909 as the later run, is disclosed, while a lost failure would not be. `Stop` or `SessionEnd`
closes the turn. Outcome-less calls then take every pending item of their command. Any other
pending command item stays local only with a proof of copy still in the ring: a stated post with
the item's call id, or with its command commitment and the same exit. Without that proof (the
post was evicted, stored after `Stop`, or never fired) the item is delivered with
`unpaired_event`. A
carrier is delivered once on the next stream reconcile, with delivery and settlement committed
together. It is stamped with the session's committed stream frontier at release time, so a later
stream row already delivered cannot make the task refuse it as `cursor_stale`.

The pending account keeps each item's structural record beside the local envelope ring (64
items per workspace). An item leaves the account when a hook post or a proof of copy settles it,
when it is delivered as a carrier, or when it is delivered with `unpaired_event`, which happens
when:

- the ring evicts it before it is paired;
- the turn ends without a proof of copy;
- it is the oldest past the 64-item bound;
- it survives 8 reconciles of its workspace while its session stores no new tool hook or stream
  row (a crashed session, or a call that never finishes).

An item delivered this way becomes unpaired evidence that names its exit, not an attributed run,
and the receipt carries the `unpaired_event` coverage limitation. Two cases leave no ledger
record of the item itself. A command item proven a copy by a stored stated post has its outcome
recorded by that post. Past a hard bound of 256 items the oldest is dropped, recorded only as a
local `unpaired_event` gap for its session. Entries of an ended session are
decided by the reconcile that its `Stop` or `SessionEnd` hook triggers; no separate
end-of-session pruning exists. A session whose tool hooks never fired delivers every item with its outcome, as the only
record of those calls. One hooked command with
a stated outcome is therefore one action and one result, and a red-latest claim names it once. Like
a retained cell, a retained item counts in `observed_count` without an admitted, summarized or
intentionally omitted bucket. A call in a hook-observed session whose own hook did not fire (an
unhooked tool or a lost hook) is not recorded from the rollout; this limit is owned by #910. An
`McpToolCall` or `FileChange` item has no command commitment, so in a hook-observed session it
pairs with a hook post only when its id equals the hook's call id. An item under a different id
is settled as its hooked call's copy when the turn ends and stays local by design, and its status
is not delivered even when the hook post stated no outcome.
Releasing such items at the end of a turn would record every hooked MCP or patch call twice,
because the reader cannot tell a copy from an only carrier without a join key. This limit stays
open on #910 until a native capture shows how Codex identifies those items.
Outside code mode, a stream-only session records a direct `exec_command` twice, once from its
`function_call` pair and once from its `item_completed` item, because their ids differ. #917 owns
that pairing.

An `McpToolCall` item fails when it names an `error` or its result carries `isError: true`,
whatever its `status` says. A `FileChange` item is recorded in the edit family (tool
`file_change`), so a stream-only patch retires an earlier failure under #909's edit rule. Mapping
versions are intentionally unchanged: already-stored envelopes keep the facts they recorded.

A delivered `CommandExecution` item carries the hook's installation-keyed `command_commitment`,
computed from its `command` argv with the shell wrapper stripped, so failure supersession (#909)
treats hook and rollout runs of one command as the same command. The item is recorded as tool
`command_execution`, which the unresolved-command advice does not read. A command whose rollout
text was redacted for a secret commits differently from its hook copy and relies on the edit rule.

These shapes are pinned by `fixtures/observations/codex-post-tool-outcomes-0.157.1.case.json`,
which is derived from recorded Codex 0.157.1 rollouts. The benchmark that exposed the defect did not
archive raw hook stdin, so a raw-stdin capture is still owed on a machine with Codex, owned by issue
#910. It should cover a nested `exec_command` with exit 0 and non-zero, a direct shell call,
`apply_patch` success and failure, and a FinishUP MCP call. Until that capture lands, the reader
accepts both the structured and the header forms. Source tests do not establish native Codex
acceptance on macOS, Linux or Windows through WSL 2. Dogfood confirmation per platform is owed on
the same issue.

## Smart observation selection (issue #687)

The Codex native hook path applies the shared deterministic observation selector before optional
content extraction and outbox admission. **Focused/standard (512)** is the default. Proven
successful routine reads, searches, and inventory calls may be represented by bounded summaries;
the summary preserves the native identities and source positions it represents. Detailed keeps
eligible routine calls as individual records while the effective pressure state permits it. The
detail mode and the capacity profile are independent choices: `standard` (512), `larger` (2,048),
and `largest` (8,192) are each valid with either mode. The larger profiles have finite provisional
budgets; a selected count is not a sustained-throughput or host-acceptance claim.

Failures, denials, cancellation, interrupted, partial, or unknown outcomes, edits and side effects,
declared checks or negative verification, and reads protected for an obligation, claim, or finding remain
individual. A `PreToolUse` identity is retained before its outcome is known; only a paired,
proven-success read can enter a summary. Ambiguous shell composition, nonzero or conflicting
outcomes, and caller-supplied `routine_read` labels stay protected. Codex session-stream records
remain a separate structural source and are outside this native selection/content path.

Codex states a tool result under `tool_response`, so the proof that a read succeeded is normally
nested rather than a top-level field. The selector and the summary builder share one definition of
that proof; where they disagreed, the buffered account refused every Codex-shaped post and
observation ingestion stopped for the rest of the session (issue #753). A refused summary now
admits its reads individually with a `routine_summary_invalid` coverage gap, names the lane once in
`finishup observe status`, and records the bounded `routine_summary_invalid` hook reason instead of
the opaque `observe` token. The behavior is shared by every host ingress, not Codex-specific.

Use the owner controls after an exact preview:

```text
finishup observe selection-preview --workspace /exact/project \
  --detail detailed --capacity larger --session-id <codex-session-id> --json
finishup observe selection-apply --workspace /exact/project \
  --detail detailed --capacity larger --session-id <codex-session-id> \
  --accept --preview-digest <preview-digest> --json
```

The default is a temporary session override. Use `--persist` on both preview and apply, and omit
`--session-id`, only when the owner wants a workspace default. `--expires-at` is an optional
RFC3339 UTC deadline; `selection-status` reports selected and effective mode/capacity separately.
Revoke with `selection-revoke` at the same scope. Expiry, revoke, lowering capacity, or pressure
affects future optional admission; accepted observations continue to drain and are not rewritten
to fit the new target. Selection does not change Codex hook deadlines, session-stream admission,
content consent, repository privacy, provider, or network authority.

**Configurable capacity (issue #828) — Codex decision.** Codex uses the same local capacity path as
every other host: `finishup observe selection-preview` with `--capacity standard|larger|largest`,
`--capacity custom --queue-count <64..8192>`, or `--capacity none`, then `selection-apply --accept
--preview-digest`, or the terminal interface's `/observe`. There is no Codex-specific capacity
control, and repository or plugin configuration cannot raise capacity. An agent may relay a change
only after the owner accepts the displayed preview's scope, values, local-hardware consequences,
remaining limits, and lower/pause/resume path; ordinary task permission never authorizes an
increase. `--capacity none` returns `capacity_no_cap_unsupported` because the local state document
has a 16 MiB safety ceiling, and changes nothing; the largest supported capacity is 8,192 rows. MCP
`status` stays read-only for capacity. Hook body caps and Codex hook deadlines are unchanged. Custom
counts need control schema `2.9.0` on both the client and the service; an older revision drops a
saved custom count to the default.

**Lowering above the fallback byte bound (issue #843) — Codex decision.** Codex uses the shared
store path with no Codex-specific behavior. Lowering, revoking, expiring, or ending a larger
selection can leave more accepted rows than the new target holds. Those rows still drain, and the
store keeps finite room, tied only to them, for refused-input loss, delivery attempts, and session
ends. A refused hook reports `hook_observe_degraded: outbox_overflow; loss accounted` only after
the loss is durable. The notice ends with `cause=<cause>`, the closed admission
dimension that refused, and the same cause is recorded as the `admission_loss_<cause>` reason in
`hook_diagnostics.reasons` (ADR-029, tb4n1 B3). Only later inputs of the lost host call, or calls it
spawned, carry `observation_input_loss`; the shared store path applies this to every host. If a `SessionEnd` hook cannot persist its local end, it stays fail-open
within its teardown budget. It prints `hook_observe_degraded: session_end_unrecorded` and
records that reason in `hook_diagnostics.reasons`.

To keep an upcoming read individually linked to a later claim, use the bounded narrowing control
with an active consent and the exact current Codex session:

```text
finishup observe protect-read --workspace /exact/project \
  --session-id <codex-session-id> --reference obl_<existing-id> --count 1 --json
```

Only `obl_`, `clm_`, and `fnd_` references are accepted. At most 32 logical reads can be outstanding
and the protection expires after ten minutes by default; an explicit expiry cannot exceed that
bound. It grants no content or disclosure authority. Promotion is limited to a native identity
still in the local buffer:

```text
finishup observe promote --workspace /exact/project \
  --source-identity <source-identity> --json
```

After the buffer has drained, promotion reports `promotion_window_closed` and
`content_availability: not_retained`. Rerun or reacquire current evidence when needed and label
the new observation with its new time and subject state; promotion cannot recover old bytes or
retroactively prove the earlier state.

Codex's profileless native capture arm follows active observation consent; it is separate from
selection. The workspace capture lane has independent limits of 512 staging/pending capture
tickets and 128 MiB of captured content. A larger observation capacity does not raise those
limits. The hook's bounded capture pass and service deadline still apply. If staging is partial,
cancelled, times out, or lacks a complete post/content group, the event remains incomplete and
does not become a successful routine summary; when the hook reaches the recording boundary FinishUP
records `content_capture_unavailable`. A host kill before authenticated staging can leave transient
content without a durable gap. Capture configuration or a successful structural receipt is not
proof that Codex bytes were captured, selected for a check, or used by a provider.

The self-observation exception covers explicit FinishUP MCP workflow names. A Codex shell event such
as `exec_command finishup observe status`, `finishup observe selection-status`, `finishup observe
selection-preview`, or `finishup closure-prepare` has no authenticated executed-launcher identity in
the hook payload; a path written in the command text is still host input. It therefore remains an
ordinary shell observation and may use the available structural, capture, or materialization
budget. Failures, mutations, and ambiguous shell are never suppressed. This is a current support
boundary for local CLI self-reads; use the explicit MCP status or receipt route where available or
account for the CLI read in coverage and capacity.

### Oversized hook payloads (issue #667, tb4n1 B5)

The Codex hook ingress cap is 1 MiB (`MAX_HOOK_STDIN_BYTES`, shared by every host); a body at or
under it is parsed in full and its captured content stays bounded by the content budget. It was
256 KiB until tb4n1, where 96 PostToolUse rows were lost to it: 42 were FinishUP's own
`closure_prepare` replies (300 KB-1 MB, including nested code-mode calls, which reach the hook as
`mcp__finishup__closure_prepare`), most of the rest `view_image` results carrying base64 data URLs
and large `cat` outputs. Each loss left its pre-event unpaired.

The observe ingress (`finishup hooks observe`) now skims a complete body up to 8 MiB
(`MAX_HOOK_SKIM_BYTES`) with the same safety rules as the full parse:

- Image, audio, and video bytes (an `input_image` data URL, an MCP `image` block) are replaced
  with a fixed placeholder. If the body then fits the 1 MiB cap it is admitted whole, with its
  text and outcome, and records no gap.
- A FinishUP MCP tool (`mcp__finishup__*`, `closure_prepare` included) keeps a closed identity row:
  session, turn, transcript, tool, call id, and outcome flags. Its content is never captured in
  any case, so the row is complete, pairs with its pre-event, and records no gap.
- Any other body still over the cap keeps the same identity row with the
  `payload_content_omitted` gap and the `codex_payload_content_omitted` hook diagnostic. Command
  text and output are not retained; the row pairs with its pre-event instead of vanishing.

A body over the skim cap, or a complete oversized body that fails the parse, is still refused
before any row exists. The hook stays fail-open and the host continues. FinishUP records the bounded
`codex_payload_too_large` reason against that event in `finishup observe status` hook diagnostics,
and notes the `payload_too_large` coverage gap on the consented workspace, where
`finishup observe status` shows it. That workspace gap does not yet reach task receipts: no row
exists, so a receipt simply has no evidence for the dropped event rather than naming the loss.
The native `post-tool-use` (start correlation), `user-prompt-submit`, and `session-start` entry
points parse the body themselves with the 1 MiB trusted cap and record the same reason above it.
The caps are fixed; raising them is not an operator control. A reader consumes at most
cap-plus-one bytes, so the true size of a refused body is never measured and never recorded. The
refusal costs exactly that one event; the next ordinary event still ingests.

Matcher decision (tb4n1 B5): the PostToolUse observe hook keeps matching every tool, FinishUP's own
included. Codex matchers are regular expressions without lookaround, so "every tool except
`mcp__finishup__*`" is not a clean matcher; excluding only the post-event would leave each FinishUP
pre-event unpaired, and excluding both would drop the delivered record of FinishUP mutations and of
any failed FinishUP call that self-observation deliberately keeps. The size problem is fixed in the
reader instead. `closure_prepare` reply size itself is owned by the closure work, not by this
ingress.

Observed images (P3-2, issue #1013): Codex `view_image` results and code-mode outputs carry images as `input_image` data URLs. Before the bytes are
dropped, the hook records up to 8 images per call as digest-only facts: SHA-256 and byte count of
the decoded image, a media type sniffed from its bytes (PNG, JPEG, GIF, WebP, else
`image/unknown`), and pixel width and height read from the header only. The service records one
`evidence_recorded` row per image (`artifact`, `content_digest`, `digest_only`), listed in the
call's result `evidence_refs`, with the description `Observed image tool result <type> <w>x<h>
(<n> bytes); pixels were not captured or sent`. No pixel is captured, stored, or sent; the agent
can cite the evidence id as its own inspection of the output. This holds at every body size up to
the 8 MiB skim cap.

## 8. Remove

Skill removal and activation/MCP removal are separate, consent-gated operations. Skill removal
never deletes marketplace, `config.toml`, cache, or MCP entries. Activation removal never deletes
the skill tree.

### Skill tree

```text
finishup integrate codex skill preview --json
finishup integrate codex skill remove --json
```

Confirm the exact preview digest. Removal deletes only a valid managed marker plus its byte-exact
file inventory. Modified, partial, or unmanaged content is refused and preserved — there is no
force-remove in v0.1. Removal never uninstalls the FinishUP package, deletes MCP configuration, deletes
ledger/key data, or touches other skills. Verify `status` shows `absent` afterward.

### Plugin, marketplace, and `config.toml`

```text
finishup integrate codex plugin preview --codex-home <home> --json
finishup integrate codex plugin remove --codex-home <home> --accept --preview-digest <digest> --json
```

`preview`, `status`, and `remove` are the whole Codex plugin command surface. The generic
`install`, `update`, `enable`, `disable`, and `export` commands that the shared
`integrate <host> plugin` group also lists belong to the Claude Code (and, for `install`, Cursor)
lifecycles; `--help` marks each command's hosts, and invoking one for Codex refuses with
`codex_plugin_command_unsupported:<command> supported=preview,status,remove` (exit 2) before any
binary discovery or mutation. Codex activation is the digest-bound setup/recommendation ceremony
(`finishup setup run`, ADR-012), not a standalone plugin command.

The Codex plugin command uses the same preview → explicit accept → apply shape as Codex
activation and MCP install: the mutation is bound to the exact preview digest. It does **not**
consume the Cursor `plugin_artifact_apply` OS-presence cell; that cell remains the standalone
portable-artifact authority and would fail closed on this host. Cache purge is default-off.
`--purge-cache` additionally deletes other version directories under
`<codex-home>/plugins/cache/finishup/finishup/<ver>` whose trees byte-match a finishup render or their own
valid `yoetz.codex-plugin-install/1` marker. Foreign or modified cache directories are refused
(`remove_refused`, conflict `cache`) and left untouched. Preview and apply use the same no-follow,
descriptor-relative 256-total-entry, 16-level, 4-KiB-relative-path, 64-file,
256-KiB-per-member, and 4-MiB-aggregate bounds, so directory-only, deep, sparse, and oversized
trees fail closed before unbounded allocation or recursion. Apply retains the validated version
descriptor through quarantine rename and rechecks the exact approved names and bytes immediately
before and during unlink; newly observed names are never swept into deletion. Observable drift
before the first unlink restores the retained inode to its exact version name; later drift
preserves the remaining quarantine. Both report `write_failed` because quarantine rename already
crossed the mutation boundary. Keep same-UID cache writers
quiescent during removal because ordinary POSIX files provide no atomic compare-and-unlink token
for the last content-write window.

Apply runs `codex plugin remove finishup@finishup --json`, then `codex plugin marketplace remove finishup
--json` when `[marketplaces.finishup]` byte-matches the finishup render, then deletes
`<repo>/.agents/plugins/marketplace.json` only when a retained no-follow descriptor still byte- and
inode-matches through a private quarantine rename, then
deletes the bound current-version cache. Whole-table TOML edits are verified by re-parse. A second
removal is a no-op (`already_absent`). Foreign, modified, dual, or otherwise conflicting entries
refuse with `remove_refused` and name the conflicting surface (`personal_marketplace`,
`repository_marketplace`, `config_marketplace`, `config_plugin`, `inventory`, `cache`, or
`membership_unverified`). Before
mutation, changed preview-bound bytes report `preview_stale`.
After a mutating host command starts (including a zero-exit command with malformed JSON), config
write, marketplace quarantine/unlink, cache quarantine rename, or member unlink has
started, any newly observed conflict reports `write_failed` (with the bounded conflict token when
available) because the outcome may be partial; it is never mislabeled as a safe stale-preview
retry.

After a successful removal, `codex plugin list --marketplace finishup --json` is empty and
`config.toml` has no finishup tables. `finishup observe status` reports the existing activation
classification: `installed_not_activated` when the managed plugin source at
`.agents/plugins/finishup` remains (issues #387 and #347), including a modified copy, or `not_installed` when that source is also absent.
The command reports whether the skill tree remains; it does not remove it. Consent records and the
observation store are intentionally left in place.

While another verified connected project that still serves the exact FinishUP manifest remains in
the home (see [Several projects in one Codex home](#several-projects-in-one-codex-home-issue-1058)),
the preview's outcome is `detach` instead: it lists those projects in `shared_with`, names the
project the binding moves to in `rebind_to` when it named this one or a project that no longer
serves its manifest, lists unverified `possible_users` (with `membership_unknown`), and plans
neither host command nor any deletion from the shared FinishUP cache (`--purge-cache` has no
effect). A Yoetz-era activation of this project is its own and is deactivated in the same plan
(`legacy_removed_block`, `legacy_cache_versions`, `legacy_marketplace_json_planned`; see [Legacy
Yoetz registrations](#legacy-yoetz-registrations)). Apply rewrites the exact
`[marketplaces.finishup]` table (and this project's exact legacy tables) in place, then removes
this project's canonical `marketplace.json` (or its exact Yoetz-era document) and its
marker-validated legacy cache, then updates the connected-projects record; the disconnected
project then reads `installed_not_activated` while the remaining projects stay `active`. With possible users but no verified project left, the
preview refuses as `codex_plugin_remove_refused:membership_unverified` before any change.

### External MCP registration

```text
finishup integrate codex mcp preview-remove --json
finishup integrate codex mcp remove --accept --preview-digest <digest> --json
```

The first command exposes the exact unregistration digest and current owned route without
mutation. Noninteractive removal requires that digest plus `--accept`; `--accept` alone fails
closed. The registration serves every project of the home: while other projects use it, the
preview names them (`shared_with`, `possible_users`, warning
`mcp_registration_shared_with_other_projects`) and its digest binds them; `setup disconnect`
keeps it for them instead (an owned entry under the earlier `yoetz` key is user-level too and
stays with it). Apply selects owned entries under `finishup` and `yoetz`, re-reads each
immediately before its name-based remove, and refuses a foreign replacement or changed FinishUP
route observed at that boundary. A foreign entry under the other name is retained. An
already-absent entry is a no-op only after the same successful `mcp list --json` absence check.
Interactive removal shows the exact command, route profile, warning tokens, and preview digest
before requesting confirmation.

Codex 0.149.x exposes a name-based remove command, not a compare-and-remove token. The owned-entry
preview therefore includes `host_remove_not_compare_and_swap`: the owner must keep concurrent
Codex MCP configuration writers quiescent during the accepted apply. The immediate pre-remove
recheck narrows the host limitation, but cannot atomically exclude a non-cooperating replacement
inside the final subprocess scheduling window. Post-apply verification still fails closed if the
removed key is not positively observed absent; a generic failed named lookup is not success.
Plugin-managed MCP is not this command: it goes away with the plugin artifact, not with `codex mcp
remove`.

After the removal command returns, FinishUP checks the selected home again even if Codex exited
nonzero. A successful structural list confirming absence completes removal with exit 0 and
`removal.warnings=["host_remove_returned_nonzero"]`; a zero-exit removal has an empty warning
list. Setup disconnect carries the same versioned outcome in `status.mcp_removal` and prints
the warning in its human report. No host stderr or subprocess payload is echoed.

If the entry is still present or the check is unreadable, removal remains unverified (CLI exit 20).
Its report carries the observed owned/foreign state or null, `next_action=inspect_registration`,
and an exact `next_command` for the selected runtime, binary and home. Run that read-only command
first. If absent, a newly accepted removal preview is a no-op and reconciles stale route metadata;
if still owned, obtain and accept a fresh preview before retrying. Preserve foreign entries.
Command exceptions also remain unverified. FinishUP never retries the mutation automatically.

This reconciliation applies to external Codex MCP removal on macOS, Linux and Windows through
WSL 2; it does not establish native Windows support. Deterministic adapter coverage is separate
from host-version acceptance: issue #860 records the bounded disposable native round trip.

## 9. Bounded `codex exec --json` import

The import support command is Codex-only and local. It accepts the exact request documented in
[`docs/usage/importing-codex-jsonl.md`](../usage/importing-codex-jsonl.md); it does not read rollout
files, add an MCP operation, hook event, or dedicated TUI screen, and it does not change
external-review policy. The CLI import and consent commands are the owning terminal surfaces.

The first `finishup import --input <request> --json` call must stop with
`PRIVACY_AUTHORITY_REQUIRED` after the source and plan are durable. Run
`finishup consent status --json` and review the `import_publication_preview`. The preview is
structural only: never copy source lines or excerpts into an agent chat. For agent-attested
authorization, show the exact danger text and digests, wait for an explicit current-chat approve
or deny instruction, then relay that exact pending item through `finishup consent authorize` with
`--warning-acknowledged`. Agent attestation is not independent proof. After approval, replay the
identical import request; do not add an approval argument or mint a new request ID.

The owner-only authorization survives a service restart only for the same stored plan. It is
consumed after terminal completion. A source, manifest, target task/session/writer, profile/version,
mapping, plan, or limit change must produce another preview. Denial, expiry, or a different pending
consent publishes nothing. Import intake never authorizes AI-powered review provider or reviewer
egress.

## 10. Troubleshooting and recovery

| Symptom | Action |
|---|---|
| Target untrusted/unsafe | Correct the explicit root/permissions; there is no force option. |
| MCP, service or hooks stop with `release_runtime_group_writable` / `release_runtime_world_writable` | A runtime another account can write (ADR-007, 2026-10-14) stops `finishup mcp serve` with `release_runtime_group_writable` or `release_runtime_world_writable` and the exact `chmod -R go-w` repair on stderr (Codex shows it as the MCP server's startup error). Its hooks exit 20 with no stdout, so they make no allow or block decision (exit 2 is the only blocking code); Codex continues the turn; their stderr names the token without local paths and points at `finishup service run`, which prints the repair. Group write through the user's own private group (the Ubuntu/Fedora umask 0002 default) is accepted. |
| Resource invalid | Reinstall from a verified package artifact. |
| Preview stale | Run `status`, then a fresh preview. |
| Modified/partial content | Preserve and review manually; use `replace_modified` deliberately if desired. |
| Compatibility is `unsupported` | Automatic activation is unprofiled; use a supported FinishUP/Codex version pair when capability evidence is required. Session-stream parsing is separate: a newer Codex release is still admitted structurally, and `observe reconcile` reports `admission: partially_understood` with the affected `admission_reasons` rather than `unsupported_format` (issue #656). |
| Write/swap interrupted | Run `status`; preserve any staged content; do not delete it yourself. |
| Skill not discovered, or duplicate `$finishup` names loaded | Check the exact scope, loaded skill roots, managed path, trust, version, and capability matrix; reload Codex. |
| Setup reports `installed_not_activated` | Run `finishup recommend list --codex-path <exact-executable> --codex-home <exact-home>`, then accept only the freshly shown target/preview digest. Historical acceptance cannot suppress an observed inactive target; a decline suppresses only its unchanged exact target. Review canonical inventory and the versioned cache; marketplace/config presence alone is insufficient. A marker-consistent stale cache is refreshed by an ordinary approved re-run. |
| Activation reports `destination_conflict` | The versioned cache (or a config/marketplace surface) holds foreign, marker-inconsistent, or modified content. Review it by hand; setup only replaces trees that match their own FinishUP install marker. Another FinishUP-connected project in the same home is not a conflict. |
| Setup reports `project_connected_via_other_path` | This directory is already connected under another path (symlink, letter case, or a move). Run the `setup disconnect` the message names for this project (it clears the other entry), then connect again. |
| Disconnect reports `membership_unverified` | No verified project is left to carry the shared pieces, but projects FinishUP connected earlier or trusted checkouts with FinishUP's plugin files (`possible_users`) might still use them. Reconnect the project that uses FinishUP (that records it) and rerun the disconnect, or preview `setup disconnect --remove-shared` if none does. |
| Setup reports `connection_lock_unavailable` | Nothing changed. FinishUP could not take its setup lock under its own state directory (the folder is named in the message). It must be a local, owner-only (0700) folder without symlinked parts on a filesystem that supports `flock`. |
| Setup reports `connection_projects_record_invalid` (adapter: `source_invalid` with `conflict: connected_projects`) | `.yoetz-connected-projects.json` in the Codex home is not an owner-only regular file with valid content. Make it owner-only again (`chmod 600`) or restore it. Remove it only if it is damaged, then connect every project that uses FinishUP with this home again before disconnecting any: until then a disconnect keeps the shared pieces for projects this installation connected and for trusted checkouts, and stops as `membership_unverified`. |
| Setup reports `target_untrusted` for a Codex home that does not exist | Codex setup needs the home first: `mkdir -p -m 700 <home>`, then rerun. |
| Activation failed with an explicit `--codex-home` | Read the actual `reason` in `registration.plugin_activation`/`readiness.plugin_activation`; the bound home and config path are echoed there. `codex_home_required` appears only when no home was passed. |
| Setup reports plugin source files but no FinishUP skill appears | Check `.agents/skills/finishup`; source installation and plugin activation do not prove project-skill discovery. |
| `list_mcp_resources` fails with `resources/list failed: Unexpected response type` | Codex's rmcp client is built with serde_json `arbitrary_precision`; before modelcontextprotocol/rust-sdk#1300 it cannot decode a fractional number in a buffered result, and the whole listing is dropped. FinishUP therefore lists guidance resources without the fractional `annotations.priority` on every host; an older FinishUP shows this symptom. Guidance never needs the listing: call `read_guidance` with a registered URI. |
| MCP name already present | Preserve it and review ownership rather than running `mcp add`. |
| `setup` skipped MCP registration | Codex not on PATH, or the entry is foreign-owned; run `finishup integrate codex mcp status --json` for the exact state. |
| MCP unavailable | Diagnose through separate MCP configuration/startup steps. |
| Trigger absent or failed | Use the manual re-grounding procedure; never edit hook configuration through this integration. |
| `observe status` shows no envelopes for a session | Read `hook_diagnostics.reasons`: `workspace_unresolvable` means the hook's `--workspace` locator could not be canonicalized; `workspace_unconsented` means the session's Git root carries no active consent (a session started in a subdirectory canonicalizes to the same root as the consent, so grant consent at the repository root); `paused` means consent is paused. A successful ingest records no diagnostic, so read `recent_count` together with the envelopes: no new envelopes and a zero `recent_count` means the hooks never reached the ingress or the runtime gate is disabled, not that a binding drop occurred. |
| `observe status` shows `mapping_present: false` after a consented `SessionStart` | The hook sends `start mode=create_or_attach` with the canonical `--workspace` root as `workspace_ref` and `codex-session:<session_id>` as `external_ref`. Before automatic new-pair admission, it scans private local lifecycle mappings for an eligible ended same-host session. A unique mapping from a received `SessionEnd`, with every other bound session ended and the candidate bound only to this consented workspace, is selected before the ordinary request: the hook holds the workspace and predecessor lifecycle locks, revalidates ownership and state, and sends one `mode=attach` request carrying that selector plus the new pair. The catalog requires the selected root task to be active and non-quarantined, its canonical workspace and repository-privacy binding to match, and no start already pending for that selected route. Unrelated tasks in the same workspace do not block this recovery (#814); a pair already bound to another task remains a conflict. Delegated child routes require an authenticated attach handle or target selector. Recovery takes a nonblocking workspace reservation before pruning or scanning, then holds it with ordered locks for every eligible ended same-host session through full candidate revalidation, the service RPC, authorized rewrites, and pruning. The revalidation includes unmapped sessions, cross-workspace ownership, mapping identities, and mapping recency; a busy workspace reservation or candidate-lock contention or a changed snapshot returns `auto_attach_recovery_busy` rather than creating work from an unstable selector. A successful recovery rewrites every ended same-host predecessor mapping for that task to the rotated session and writer so pending predecessor rows drain on the successor route rather than being quarantined. With no usable persisted selector, automatic `create_or_attach` admits the new pair as independent work, including beside a dormant task. `workspace_task_exists` identifies only explicit `mode=create` colliding with an identical pair; workspace membership never selects a task. The candidate set is bounded (#549): a recovery unbinds the ended predecessors it consumed, and each `SessionStart` pass keeps at most the 32 most recently mapped ended bindings per workspace, pruning unmapped ended sessions first; a binding is never pruned while its session is live or while a pending or quarantined row still names it, so protected rows may keep the total above 32, ended unmapped rows still terminalize, and a pruned session that resumes re-binds on its next hook event. The public error reveals no selector; a hard crash without `SessionEnd` remains fail-closed rather than being guessed from age. Otherwise read `hook_diagnostics.reasons` for the typed cause: `auto_attach_workspace_unbound` (no paired request was legal), `auto_attach_request_invalid` (an authoring defect — file it), `auto_attach_conflict` / `auto_attach_refused` (the service answered and declined), `auto_attach_result_invalid`, `auto_attach_mapping_write_failed`, `privacy_authority_required`, `vault_locked`, `timeout`, `storage_unsafe` / `storage_corrupt`, `service_incompatible`, or `service_unavailable` (the daemon was still starting; `UserPromptSubmit` and `Stop` retry under the bounded budget; teardown `SessionEnd` records its lifecycle intent and drains without an auto-attach retry). An explicit MCP `start` remains the recovery path; for `vault_locked` on a never-initialized install, that `start` returns the typed `vault_initialization_required` continuation below rather than a dead end. |
| `observe status` shows `mapping_stale` after every resume or compaction | Before issue #578 the `finishup hooks session-start` status read connected without a workspace locator, so the daemon's repository fence refused every probe as `SESSION_CONFLICT` and a live mapping was reported stale. The rendered command now passes `--workspace .`, and the probe selects its locator in a fixed order (issue #659): an explicit project path other than the bare `.`, then the host payload's session `cwd` (a subdirectory resolves to the repository root), then the hook's own working directory. The host cwd outranks the bare `.` because Codex hook working directories are not stable across surfaces; an explicit path that cannot be canonicalized never falls through to another repository. `finishup hooks observe --event SessionStart` and the shared mapped-session lane derive the probe locator the same way when no explicit workspace was consented. A fence refusal is `status_workspace_unbound` / `status_workspace_mismatch` with a keep-the-mapping advisory, and a companion diagnostic row names the locator source (`locator_source_explicit`, `locator_source_host_payload`, `locator_source_cwd`, `locator_absent`, or `locator_unresolvable`) so an absent context and a supplied one that failed to resolve are distinguishable; `mapping_stale` means the daemon actually reported the session replaced, and the advisory names the replacement ids. |
| A scoped `start` returns `SESSION_CONFLICT` with `repository_identity_required` or `repository_identity_mismatch` | `repository_identity_required` means the attach request omitted the trusted workspace/repository context; `repository_identity_mismatch` means the context resolved to a different repository than the bound route. Keep the selected `session_id`/`writer_id`, resolve the canonical repository root, and retry the same attach with that trusted context. The corrected request resumes the existing task (a rotated session/writer is allowed by the 0.3 recovery contract); it does not create a sibling. Never copy a commitment or infer a selector from a public workspace string. |
| The agent created a sibling task instead of continuing the auto-attached one | The `SessionStart` context names the mapped `session_id` and `writer_id` and says to continue with `start mode=attach` by that session id; guidance and the `start` tool description name the canonical absolute repository root as `workspace_ref`, the value the hook commits (issue #580). The agent's successful scoped `start` re-binds the mapping through `finishup hooks post-tool-use` from `structuredContent`; a scoped start that binds nothing records `start_bind_unparsed` / `start_bind_invalid_ids` / `start_bind_write_failed`. |
| `observe reconcile` of a child rollout reports `child_parent_unmapped` | The v2 child header names a spawning session that is not bound to the selected workspace alone with a lifecycle mapping. Reconcile or attach the parent session in its own workspace first, or select the workspace that owns it. Nothing was ingested (#841). |
| `observe reconcile` of a child rollout reports `child_route_missing` | The spawning session is mapped, but no validated attach published a child lane for this child thread: the child's attach callback carried neither a host child alias nor its own transcript, or no hook reached the child thread. Read `hook_diagnostics.reasons` for `start_bind_child_lane_unbound`. The provisional annotation stays unbound; nothing is inferred from stream status or annotation counts (#841). |
| `observe reconcile` of a child rollout reports `child_route_ambiguous` or `child_identity_invalid` | More than one route or workspace claims the child thread, or the header declares a delegated child without a usable distinct child and spawning thread. Nothing was ingested; the observation keeps its bounded gap (#841). |
| `hook_diagnostics.reasons` shows `child_transcript_identity_conflict` | A Codex callback's own transcript proved it came from a delegated child that it cannot name for the callback's session, or that contradicts the host child alias. The callback is an explicit attribution gap and is never delivered as parent work (#841). |
| `observe status` shows pending `mapping_missing` after a runtime route conflict | A non-retryable `SESSION_CONFLICT` while acquiring the task runtime keeps the envelope pending for a later drain after its lifecycle mapping is repaired. The route must still pass its ownership checks. Non-retryable conflicts after runtime acquisition remain `ledger_rejected` and enter quarantine. Retryable route conflicts report `service_unavailable` and stay pending. |
| `observe status` shows `ledger_rejected` and `outbox_quarantined` | The service was reachable but rejected one envelope non-retryably. A repeated envelope after a lost acknowledgement, a service restart, or a workflow reattach (a second `start` in the same Codex session) is not such a rejection: its committed operation is resolved task-wide and the row is acknowledged idempotently with no quarantine row. A pending row from an ended host session whose task a successor recovered is delivered on the successor route (`session_superseded` is followed) and is also not `ledger_rejected`. A successor binding that cannot be followed quarantines that row as `session_superseded`, not `mapping_missing`. A `ledger_rejected` row is a genuine conflicting reuse of an event or operation identity. The row is retained under `quarantine_causes`, aggregate `delivery_causes`, and gaps; `pending_delivery_causes` names only rows still in the outbox. Later rows can drain; reclaim only after the underlying defect is understood. A hook-driven attempt also appears in the bounded `hook_diagnostics`, while manual and supervisor drains are represented by status rather than hook activity. Do not restart a ready service. A row is also quarantined after 128 consecutive rejections with the same retryable reason so a catch-all failure cannot block the lane forever; pause, vault, disabled, and designed back-pressure reasons keep their existing recovery behavior. |
| `observe status` exits with `observation_status_failed:<reason>` | The reason names the layer: `workspace_unresolvable` (exit 2) is the locator; `storage_unsafe` (exit 20) is an unsafe state/lock path; `storage_unavailable` (exit 20) is a bounded open, permission, read-only, missing-parent, or lock-acquisition failure; `storage_corrupt` (exit 40) is invalid stored data. The fixed remediation never prints the absolute state path. A sandboxed Codex result proves only that sandbox cell; run and record an unrestricted-terminal comparison separately before making that claim. |

When more than one eligible ended same-host mapping names a different task, automatic admission
records the closed `auto_attach_binding_ambiguous` cause and does not guess or create around the
ambiguous selector. A busy recovery reservation, candidate lock, or changed recovery snapshot uses
`auto_attach_recovery_busy`; `workspace_task_exists` remains the explicit identical-pair conflict.

Busy host lifecycle changes are durable local work. State schema `/11` adds bounded pending
session-lifecycle intents, and a READY or hook drain reconciles them under the workspace and
session reservations before routing their rows; busy mapping writes use an atomic per-session
handoff. Upgrade this state quiescently: stop the older FinishUP service and Codex hooks, install
the new runtime, then restart the service and all Codex integrations before writing `/11` state.
Mixed old and new writers are unsupported because a `/10` writer ignores the new pairing fields and
can erase a deferred intent when it saves.

Setup binds every MCP lookup, registration, verification, and removal to the same explicit
Codex home used for plugin activation. Both `CODEX_HOME` and testing-wrapper
`CODEX_TESTING_HOME` are passed to those subprocesses; the parent environment is unchanged.
Registration and removal preview digests include the selected home, so approval for one home
cannot be replayed against another. An unresolvable explicit home fails before registration.
When activation first exposes the plugin-bundled MCP entry, the interactive wizard shows a fresh
MCP preview and asks for confirmation once before registering the selected launcher. Declining,
a foreign entry, or another intervening change stops the write. Noninteractive callers retain
`preview_stale` and must obtain a fresh preview; old approval is never silently reused.

## 11. Security, privacy, and prohibited actions

Codex is the v0.1 allowlisted first-party client for exact current-chat consent attestation.
It should guide FinishUP setup, installation, and settings changes in normal conversation: explain
each consequential choice, recommend one outcome with its trade-off, and preserve the user's
explicit selection. When the user explicitly wants AI-powered review, recommend Expanded first
for review depth and explain Assisted as the lower-disclosure AI-powered option. Do not silently
downgrade either choice.

For `repository_privacy_grant`, run the catalog-advertised prepare command only after the recipe is
chosen. Show the v6 `repository_privacy_preview` in full: repository commitment; authority,
current-policy, candidate-policy, and diff digests; and every before/after row including the exact
provider/model/endpoint. The user's final approve/deny applies only to that expiring one-use target.
Any repository, authority, configured-route, recipe, target, expiry, or replay drift is a
no-mutation failure; never prepare a replacement silently. Strict MCP routing, host admission,
provider readiness, physical dispatch, and receipts remain separate facts.

For `vault_initialize` and `vault_passphrase_rotate`, it relays only the prepared pending ID,
operation, danger digest, target digest, decision, and warning acknowledgement. FinishUP generates,
loads, stages, and submits vault secrets inside the local helper; Codex must never request or
receive them. An ambiguous rotation preserves its staged entry for service-restart reconciliation.

First-run start continuation (issue #512): on a never-initialized install, the agent's first MCP
`start` returns non-retryable `VAULT_LOCKED` carrying
`safe_details.continuation: vault_initialization_required` with exact-literal `prepare_command`,
`review_command`, `authorize_command`, the pending TTL, and `replay_request_id`. The Codex flow
is: run `finishup consent prepare vault_initialize`, show the returned danger text and digests in
chat, wait for the user's explicit current-chat approve or deny, relay exactly that decision via
`finishup consent authorize` with `--warning-acknowledged` (agent attestation is not independent
proof), then replay the exact original `start` request ID and body once. Denial, expiry, and
every ceremony failure remain their distinct bounded outcomes; a hard-locked initialized vault
never carries this continuation and keeps the unlock/recovery paths.

Never paste modified skill content, repository content, paths, Codex configuration, a transcript, a
prompt, a key, an environment variable, or a raw exception into public support. Share only versions,
state, source/installed/preview digests, the bounded reason token, and file-state names.

- Never claim a global or fuzzy install scope.
- Never force an overwrite or a removal.
- Never claim skill installation changed MCP configuration.
- Never claim support for a Codex version outside the current tested set.

For a disposable-worktree integration run, use the [Codex dogfood parity runbook](codex-dogfood.md).
The ordinary setup/AI-powered review checks above are necessary but do not prove exact-worktree
activation, consent, host delivery, observation, rollback, or normal-target isolation. In
particular, an isolated Codex home (`CODEX_TESTING_HOME`) does not isolate FinishUP: without
`FINISHUP_ISOLATED_ROOT` (ADR-026) exported to every tested process, the run's FinishUP clients and any
service they spawn resolve the normal singleton, state directory, and storage. Prove the mode with
`finishup service isolation --json` before launch; the parity gate's `service_isolation` facet fails
closed on shared, ambient, or unknown identity.

For the FinishUP-owned external registration, issue #561 makes this propagation a supported product
contract: an isolated preview displays and digest-binds the exact root, apply uses Codex's native
`--env FINISHUP_ISOLATED_ROOT=<exact-root>`, and status must report
`isolation_binding=isolated_exact`. Ambient registration stores no environment. A missing or
different known root on a bare registration requires re-registration; arbitrary environment keys, inherited-variable
declarations, and malformed roots classify the same-name entry as foreign and are never replaced.
Before a dogfood model task, use the app-server capture in the parity runbook to launch the real
registered child and satisfy `mcp_child_isolation`; registration status alone is not child-start
evidence.

A pinned test instance (ADR-028, issue #604) is the second guard for the registered child: when the
registration's `command` is the absolute launcher of a runtime created with
`finishup instance create --bind-runtime`, the child resolves that instance's root even if the `env`
block is lost, and a different root in the environment is refused as `isolation_root_conflict`
rather than obeyed. The `--env` binding, `isolation_binding=isolated_exact`, and the
`mcp_child_isolation` facet remain required and unchanged. The everyday Codex registration must
name the everyday launcher by absolute path: a bare `command = "finishup"` resolves through `PATH`,
and a test runtime earlier on `PATH` then reaches the everyday endpoint, answers
`service_incompatible`, and its `finishup service restart` advice supersedes the everyday service —
the failure recorded on issue #604. See [`test-instances.md`](test-instances.md).

The plugin activation cache is the other place Codex launches FinishUP (issue #1076). `plugin add`
copies the portable project source, whose `.mcp.json` stays a bare `finishup` with no environment,
so the project tree and the committed repository render carry no machine path. Apply then replaces
that cache copy. The replacement `.mcp.json` uses the same proven absolute launcher and, when this
process is isolated, the same `FINISHUP_ISOLATED_ROOT` and `YOETZ_ISOLATED_ROOT` pair as the
external registration. `PATH` is not consulted. A noninteractive connect (the terminal UI and
`finishup connect`, which applies the same approved plan) accepts the plugin MCP entry only when
`codex mcp get` reports that same absolute command and the isolation binding the cache wrote:
`isolated_exact` when this process is isolated, `ambient` when it is not. A report that keeps the
command and drops the environment is not accepted and does not register a user-level replacement;
the continuation is to rerun the connection. Reconnecting rewrites a marker-consistent cache
that still names a bare `finishup` or a legacy `yoetz` command; repeating that activation changes
nothing. Disconnect removes the cache, including the bound entry, and leaves the portable project
source in place. Plugin hook commands are not pinned. In the activation cache, the project
source, and the committed repository tree they stay the portable basename (`finishup hooks …`),
with no isolation environment. Codex records hook trust as a hash of that command. Rewriting a
cache hook command changes the hash, so an already-approved hook becomes modified and stays
inactive until `/hooks` reviews it again. The hook schema has no environment field, so isolation
cannot be attached beside the command without changing that hash. A legacy `yoetz` hook string
is replaced only when activation recopies the current portable source, which still names
`finishup` by basename. This repair covers the MCP entry the plugin starts. If the installed
CLI cannot prove its console script,
activation preview refuses rather than writing a command resolved through `PATH`.

Absolute external launchers are managed by the same preview/install/status/remove flow (#654).
Run that flow from the installation you intend Codex to use. Preview selects its console script
from that interpreter's scripts directory and verifies its bytes against the installed FinishUP
RECORD; status recognizes only that exact absolute script, with recognized serving arguments
and the reviewed root. A pinned instance must also have a matching pin and instance identity,
current runtime provenance, and an unexpired lifetime. A basename, an executable bit, a different
installation's matching version, or a path supplied by the host is insufficient.

Review the command and root printed by `integrate codex mcp preview` before applying. An unchanged
absolute registration is a no-op; explicit route changes preserve the launcher; removal previews
name the current absolute command. Drift in the command, launcher evidence, or root invalidates
the preview. Missing or modified launcher evidence, symlink/unsafe paths, conflicting transports,
unexpected environment/arguments, and an absolute command bound to another root remain protected.
If the installed CLI cannot prove its console script, repair that installation before registering.
Symlink aliases and wrapper/module commands are not owned absolute console-script registrations;
use the direct script printed by the installation's preview. Bare/legacy registrations remain
recognizable for removal and explicit migration, without granting ownership to unrelated absolute
binaries. Plugin/external dual ownership remains a blocker. Claude Code and Cursor keep their
existing native-carrier identity rules; this repair changes only Codex external registration.

## Subscription evaluator is a separate Codex role

Codex may be both the host carrying FinishUP and the selected external AI-powered evaluator, but those
are independent cells. Host skill/plugin/MCP activation grants no ChatGPT evaluator login or
privacy authority. Configure the evaluator only through
`finishup provider codex-subscription setup`; it binds a separate owner-private `CODEX_HOME` and the
newest installed Codex release (at least `0.157.1`) that passes the evaluator's capability check.
Never reuse the host's ambient home, environment, session, tools, instructions, or repository cwd
for the evaluator.

The evaluator binds FinishUP's own checked copy of that release (issue #855), never the host Codex
installation. Updating the host Codex therefore changes neither the evaluator nor its binding until
the owner runs `finishup provider codex-subscription repair`, which adopts the newer host release
when it passes the check and keeps the previous one otherwise. Repair also moves a binding written
under the pinned `0.157.1` cell and reuses the dedicated home's sign-in. The host's own Codex
capability cells (this runbook) stay exact; only the evaluator is admitted by capability. Decision
for this host: supported through the shared provider surfaces, with no Codex-specific step. Native
Codex acceptance of a post-repair check is pending; see the
[subscription evaluator runbook](codex-subscription-evaluator.md#evaluator-runtime-retention-and-repair).

The registered host route still decides whether this Codex process may request AI-powered review
work: `strict` proves zero evaluator launch, while `policy` only permits ADR-009 to decide. Read the
[subscription evaluator runbook](codex-subscription-evaluator.md) before claiming live model use,
runtime isolation, privacy receipt, or cleanup.

Fallback endpoint pairing (issue #582) is host-independent: whether the evaluator or a paired
API provider serves a given attempt is a service-side dispatch decision recorded in provenance
(`fallback_from`), with no Codex-host-specific behaviour, registration, or route input — the
strict/policy route ceiling applies to dispatch authority regardless of which endpoint serves.

Routine/final Codex review budgets (issue #571 item A1) are host-independent too. The service
selects the budget profile from the frozen case: `final` when the frontier carries a completion
claim, `routine` otherwise. It then dispatches with that profile's configured effort and output
limit and records them in provenance. Codex gets no host-specific behavior, registration, route
input, or per-request selector, so the decision for this host is "supported, unchanged".
Recording a completion claim is the only way a check requests the final profile.


### Structural review progress (#571 A2)

Decision: supported through the shared MCP `status` tool with no Codex-specific behavior,
registration, or route input. Call `status` with `view: "operation"` and the check request ID while a long review runs; Codex receives the privacy-minimized text summary, which names the operation state, phase, attempt, condition, elapsed and remaining milliseconds, and the structured page carries every field. The phase vocabulary, deadline, and terminal outcome are
service facts, identical for every host; progress never includes provider text, tokens, reasoning,
or account identity. A read from a different session or writer of the same task may return
retryable `BUNDLE_BUSY` while the check runs. This is shared service behavior, not evidence of a
fresh installed native Codex dogfood run.

### Large tasks and AI-powered review failure recovery (#674–#676)

Codex uses the shared service status snapshot cache and bounded AI-powered review reference
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

The current Codex MCP surface advertises the read-only `closure_prepare/1.0.0` support tool.
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

Codex sessions carry the standing `unpaired_event` gap from start to finish (hook actions outnumber
results; the cause is issue #917). Older builds recorded the advisory finding
`fnd_8a9389b5-…` in every Codex session and delivered it through `PostToolUse` `additionalContext`.
Decision for this host: supported, same rule as every host. The rule is service-side and
host-neutral: an observation-authored, non-actionable finding (the "Observation coverage is
incomplete or stale" advisory, including rows written by earlier builds) never counts in
`unanswered_finding_count` or `findings_unanswered`, and acknowledging it once is optional and never
supersedes a recorded check. It stays in `status view=findings` and on the receipt as a disclosed
limitation and does not become resolvable. `refresh_observation` is an operator continuation: it
remains in structured observation advice and `finishup observe status` for real recoverable causes
such as source lag, a stale cursor, a drain backlog, service unavailability, or a locked vault,
but is never copied into Codex hook context. Hook context is reserved for work advice. The shared
guidance and this host's skill give the closure order: answer unanswered findings before the final
check (the current status frontier is a valid `finding_frontier`), answer only the findings that
check returns that are still unanswered, then `receipt`, then `work_closed`; no recheck follows
those answers, `work_closed`, or an `insufficient_packet` review without a new repair, while a
recorded repair still gets its re-check. Which conditions raise the advisory, and how the sticky
`unpaired_event` gap surfaces, are owned by issue #917. Verification: shared-path regressions cover
the ledger rule on the memory and SQLite backends; a live Codex dogfood transcript on macOS, Linux
and WSL 2 is not yet recorded. That gap is owned by issue #911.

### What follows the last check on Codex (tb4n3 RC-6, #1029)

The records that follow a deterministic arm's final check are the `check` call's own hook
observation (its post lands after `check_recorded`; the nested hook names `mcp__finishup__check`)
and the rollout's stream bookkeeping (`Opaque observation kind=event_msg|response_item|
token_usage_record`, `Observed completion signal kind=...`), because #564 keeps a successful
`status`, `receipt` or `read_guidance` post local-only. `kernel/later_material.later_material_class`
reads them as `yoetz_own_call` and `no_tool_activity`, so `check_current_as_of_earlier_frontier`
no longer appears for a check followed only by FinishUP calls and a receipt. The rollout's
`McpToolCall` item keeps its `server` and is named as its hook names it (`mcp__finishup__status`,
#1038); an item without a server keeps its bare tool name (`status`), which is still read as
FinishUP's own tool. An item whose server cannot be spelled that way (the server is not a plain
token, for example it contains `__` or starts with `_` or `-`, or the scoped name is too long)
names no tool when its tool has a FinishUP name, so it is never read as FinishUP's; any other tool name
under it is kept. A nested `apply_patch`, an `exec_command` that is
not in the hook's `exploration` runner class and an unpaired stream output with no tool identity
stay `other` and keep the
disclosure; a `wait` poll (it only returns the output of a cell started earlier) and a
`clock.sleep` (hook spelling `clocksleep`; it only pauses the turn) are `no_tool_activity`; a
nested deliverable or workspace `apply_patch` supersedes the check. A patch
whose every path is `finishup_receipt.*`, a FinishUP tree or scratch is `non_counting_write`. Tests:
`tests/unit/application/test_tb4n3_later_material_host_shapes.py` drives real Codex hook payloads
through the ingress and the materializer.

Codex 0.159.3 names every response-item row itself (`custom_tool_call` `id: ctc_...`, its output
`id: ctco_...`; `fc_`/`fco_` for function calls) beside the `call_id` the call and its output share.
The reader paired on `id`, so no code-mode cell output ever joined its call: it reached the ledger
as an unpaired result with no tool identity (`unclassified_observed_evidence`, read as `other`),
the #917 hold never applied, and in tb4n4's deterministic arm the agent's own `mcp__finishup__*`
cells kept `check_current_as_of_earlier_frontier` on 35 of 60 final receipts (#1038). A call and
its output now pair on `call_id` (`id` only as a fallback), which also folds the stream copy of a
hooked direct `function_call` into the hook's one action again instead of a second action and an
unpaired result. A completed tool item
(`event_msg`/`item_completed`) keeps its own `id` (`exec-<uuid>`, or the call id on a direct call):
that is the id ADR-022 decision 15 compares with a hook call id, so the item-to-hook link is
unchanged. On the recorded 0.159.3 slice (`tests/fixtures/codex/rollout-compaction-0.159.3.jsonl`)
the 28 unpaired cell results are gone. The three cells that ran no nested tool at all recorded
their own `exec` action, as #917 decided, and stayed `other` until tb4n5 showed such a cell
bounding a final check (medical S); since the tb4n5 amendment a cell with no observable tool call
is no workspace activity (see [One action per tool call](#one-action-per-tool-call-and-the-standing-orphan-record-917)).

### Gaps FinishUP and the host made on every attempt (#1041)

tb4n4's deterministic arm carried, on all 60 attempts, gaps that came from FinishUP or the host rather
than the agent's work. Their dispositions:

- **Held rollout tail.** A final line Codex has not finished writing (no newline yet, whether or
  not it already parses) is held and re-read on the next reconcile; the stream reader no longer
  reports it as `truncated_payload`. Lines over the 1 MiB bound and unreadable chunks still are.
  Before this change the gap appeared only in the reconcile result (`finishup observe reconcile
  --json`), not in task coverage.
- **Shell `apply_patch <<EOF`.** A pre-only attempt closed by the observed `FileChange`; see
  [Reviewable native edits](#reviewable-native-edits).
- **Rejected FinishUP calls (tb4n5).** Codex fires no `PostToolUse` for a tool result that is not a
  success, and an MCP result with `isError: true` is not one, so every FinishUP call the service
  rejected left its `PreToolUse` pending until it expired as `pending_attempt_expired` (17 of 18
  tb4n5 attempts; the shell heredoc above did not occur once). The FinishUP MCP bridge now records each
  error answer it returns (a commitment to the tool, the request's FinishUP session and writer, and
  its `request_id`, or for a `publish_work` sent without one its canonical arguments; nothing
  else), and the pending attempt of that call closes as
  `rejected_by_yoetz` without the gap once the next hook runs at least 5 s later, or at once when
  the session ends or its generation advances. Each rejection closes at most one attempt in any
  workspace. Every other missing post still expires with the gap, and `finishup observe
  status --json` names each ending under `pending_attempt_endings` (reason `ttl`, `session_end`,
  `generation` or `rejected_by_yoetz`, the tool name and the source generation) so an export can
  tell the producer.
- **Local retention.** The 256-row local envelope ring, the state bound and the dedup fence keep
  local copies of accepted rows; every tb4n5 attempt crossed the ring, and its eviction was
  reported as `truncated_payload`. Eviction now reports only `local_retention` in `observe status`
  (not content loss, not a gap). Clipped hook content keeps `truncated_payload` on the row it cut,
  and an oversize or unreadable rollout line keeps it in the reconcile result.
- **`HookPrompt`.** A Stop hook that continues the turn (FinishUP's closure gate) makes Codex 0.159.3
  write an `event_msg.item_completed` item of type `HookPrompt`. The compatibility profile admits it
  as bookkeeping (it pairs with nothing and is read as `no_tool_activity` after a check), so it is
  no longer an `unsupported_event` gap. No exact profile admits it.
- **`semantic_review_not_requested`.** Not recorded for a `deterministic_only` check on a route
  that does not require AI-powered review; see
  [Closure readiness and standing limitations](#closure-readiness-and-standing-limitations-913).
- **Hook latency** (`drain_pass_delivered_nothing`, named `drain_budget_exhausted` before tb4n5;
  `hook_followup_deferred`; `drain_connect_timeout`): not lossy. Its material effect was rows
  landing after a check; with cells paired on `call_id` and FinishUP-only cells kept local whatever the
  hook timing (#1038), tb4n5 measured it again and found no regression. The owner kept the 0.2 s
  budget (ADR-022 amendment of 2026-10-13): `drain_pass_delivered_nothing` counts hook passes that
  delivered no row within it (the rows stay queued), and the measure of lateness is now the outbox
  delivery lag, enqueue to acceptance, which `finishup observe status --json` reports as
  `delivery_lag` (`count`, `p50_ms_at_most`, `p95_ms_at_most`, `max_ms`, `since`).

Per host: Claude Code and Cursor have no rollout stream, no code-mode cell and no intercepted
`apply_patch`, so the held tail, the shell patch and `HookPrompt` are Codex-only; the
`semantic_review_not_requested` rule is service-side and the same on every host. The rejected-call
record and local retention are host-agnostic: the bridge records an error answer whichever host
called it, and every host spelling of a FinishUP tool commits alike, so a paired ordinary profile on
Claude Code or Cursor closes the same way.

### Inspection check on Codex (#1048)

`check` with `"mode": "inspect"` is a read inside FinishUP: it records nothing, mints no finding, runs
no review and needs no FinishUP disclosure decision, so a lost answer is answered by asking again with
a fresh `request_id`. One call returns what is left to close (the `status` readiness split, then
every unresolved obligation and finding with what it lacks and whose move it is), the
hook-observed actions since the last check, and whether each obligation's resolution evidence links
to its declared deliverables or requested commands (`evidence_off_declared_items` when it does
not). Use it instead of a series of `status` reads where Codex admits `check`; no status read or
`dry_run` is required before `publish_work`. The startup read is the operating card
(`agent-instructions.md`); the larger pages are read on demand. ADR-047. The MCP `check` tool
(including code mode, where an inspection takes the 30,000 ms `status` deadline) and `finishup check`
carry the mode.
`apply_patch` edits are listed by write class, never by path.

Host approval is per tool, not per mode. An inspection is a call of the MCP `check` tool, whose
descriptor is the same for every `mode` (`readOnlyHint: false`; `openWorldHint: true` on the
policy route), so Codex gates it exactly as it gates any `check`
([Auto review and host admission](#auto-review-and-host-admission)). On the policy route it needs
approval under `approval_mode = auto`, the guardian decides it under
`approvals_reviewer = "auto_review"`, and under approval policy `never` Codex refuses it
(`MCP tool call requires approval, but approval policy is never`) before FinishUP runs, unless the
trusted project's admission (`approval_mode = "approve"` for `check`) applies. On the strict route
(`openWorldHint: false`) Codex does not ask. `status` (`readOnlyHint: true`) needs no approval
under that rule. Decision: supported behind the `check` gate. A held or refused inspection is a
host hold with nothing pending in FinishUP and no review to protect, so the agent reads `status`
(readiness, `view=obligations`) instead and continues; the review-hold rules do not apply to it
(guidance `review.md`). Capability gap, owner issue #1048: admission needs a policy route and a
repository grant that permits external review, so on a policy route without that grant an
inspection costs an approval (or, under policy `never`, a refusal) that the `status` reads it
replaces do not. Closing it needs a read-only advertisement for inspection: one descriptor per
tool cannot carry a hint per mode, and a separate tool is the alternative ADR-047 rejected.

### Guidance delivery on Codex (tb4n5)

- **Closure trigger in the skill description.** The skill description ends "Also use when a
  FinishUP finding, Stop message or receipt needs an answer", so a host that selects skills by
  description can load the skill again at closure. Decision: supported; whether this host
  re-selects the skill at closure is unmeasured until its dogfood lane runs.
- **Initialize body.** The compact body adds "Do not list resources; read the named topics": all
  18 tb4n5 attempts called `list_mcp_resources` in their first cell. The per-step cadence left the
  body; the operating card states it once (ADR-047 amendment). The Codex skill keeps one start
  sentence that names its antecedent, the card pointer, `references/startup.md` and the closure
  judgment rules; the capacity procedure is the catalogued topic
  `workflow.md#change-local-retention-capacity`. Decision: supported.
- **Page-zero sections.** Page zero of a paged `read_guidance` read carries
  `structuredContent.sections`, one `{uri, byte_count}` per catalogued section, and the bounded
  pointer in `content` names the anchors and sizes. A code-mode cell that prints the structured
  result (the `startup.md` snippet prints the whole page) shows the list. Decision: supported.
- **Check-cell deadline at closure.** A code-mode `check` cell without `yield_time_ms` yields, and
  the yielded `exec` cell lands after the check and makes it stale (5 of 9 S attempts, a stale
  final check in 6). The Stop gate repeats `// @exec: {"yield_time_ms": 300000}` only after a
  recorded code-mode `exec` cell for this session (`session_observed_code_mode`), or when
  `check_cause.tool` is `exec`. The host brand Codex does not select it: plain `exec_command` and
  `write_stdin` get the neutral close sentence. The status `check_cause` sentence repeats the
  pragma when the cause's tool is `exec`. Decision: supported for observed code mode; direct MCP
  stays on the neutral sentence. Evidence boundary: unit tests only; the Codex dogfood lane is
  pending.

### Closure readiness and standing limitations (#913)

Codex sessions carry standing limitations that no agent action removes, so `closure_readiness`
names them in `standing_limitations` instead of as work: `host_outcome_unavailable` (Codex hooks
state no command outcome; #910 removes it where an outcome exists), `unpaired_event` (pairing
loss, sticky by design; #917 owns how it surfaces), and commonly `content_unselected`,
`observation_qualified_partial` and `advice_semantic_pending`; `check_current_as_of_earlier_frontier`
is a standing disclosure and appears only while an unclassified record follows the check (tb4n3 RC-6). Observation status may also report
`pending_attempt_expired` and `unsupported_event`; both are standing. A finished Codex session whose
remaining conditions are only these reads `ready_with_limitations`.

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
unless the check asked for `semantic_required` (issue #1021, ADR-040, same on every host). A strict process whose applied Codex route record says `policy` (registration drift, #537) still
follows the verification policy.
At
`closure_readiness.state: ready_with_limitations` the agent requests the receipt without another
check; the receipt conclusion is unchanged (a local-only check stays `insufficient_coverage`).

X-HOST evidence: the derivation is covered by service-side contract tests over a Codex-shaped
ledger replay; a dogfood transcript on this host across macOS, Linux and WSL 2 has not been
recorded yet. That gap is owned by issue #913.

### Bounded workflow recovery examples (#613)

These examples use the existing MCP operations and selectors on the local Codex cell. Replace
placeholders with values returned by the current call or session-start context; do not reconstruct
them from memory or from the live store.

- **Read retry.** If a `status`, diagnostics, or `status view=operation` read times out, send the
  same read intent with a new read `request_id`. Keep its view, operation filter, cursor, and limit
  unchanged. An unreadable read does not establish that an operation or task is absent.
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
- **Exact-session attach.** When `SessionStart` or recovery context provides a held
  `session_id`, use that exact value as the `mode=attach` selector. Codex's canonical repository
  context supplies the workspace fence; if the request carries identity refs, include the
  canonical `workspace_ref` + `external_ref` pair together, never `workspace_ref` alone. Use the
  returned successor `session_id` and `writer_id`, then read `status` before continuing. A bare
  `task_id` is not an attach selector.
- **Same-pair fresh conversation.** With no held session, call `start mode=create_or_attach` using
  the same exact canonical `workspace_ref` and stable `external_ref` pair, with no `session_id`.
  The same pair resumes; a different complete pair is independent work, even in the same workspace.
  A remote URL is not the workspace identity.
- **Explicit sibling handoff.** Use `start mode=create` only after same-task pair/session recovery
  is exhausted, every earlier write has a known terminal outcome, the binding is healthy and
  authorized, and the user has declared one bounded remaining or repaired verification scope. Keep
  the same canonical `workspace_ref`, choose one different stable `external_ref` such as
  `<work-item>-recovery-v1`, and establish the Codex mapping from the returned task/session/writer.
  Publish a fresh plan, evidence, checks, and receipt for that scope. The handoff must say that the
  predecessor receipt, findings, obligations, evidence IDs, and unresolved status remain separate;
  the sibling cannot make the predecessor look resolved. If no new scope exists, keep the old
  receipt and stop instead of creating another sibling.


## Observation recovery diagnostics

Codex uses the shared selected-admission and outbox store. New native input obeys current hard
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

A known inventory can still hold a stranded capture handoff: a ticket whose `codex_hook` row was
already acknowledged or quarantined, so nothing will consume it. Its age alone used to hold
`oldest_age` at the hard limit with an empty queue (#836). The row's own delivery now retires a
ticket it leaves behind, and the same READY maintenance pass retires any handoff at least 30
seconds old that no queued row can deliver, through the catalog route of the task that owns it
rather than a session mapping. It reports `capture_handoff_retired` or, when an owning bundle cannot
be read, `capture_handoff_unavailable` and retries. A handoff whose row is still queued keeps its
pressure. `observe status --json` names each retirement under `capture_handoff_retirements`
(ticket identity, stage, reason, ticket state, quarantine reason, and age) and records
`content_capture_unavailable`,
because the staged bytes are not attached. In a workspace shared with Claude Code or Cursor, their
hooks deliver queued Codex rows without their own content profile, so a Codex row is no longer
refused as `content_capture_profile_mismatch`.

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
wait in one hook pass shares a single deadline measured from hook entry: 7 s for
every observe hook (10-second host timeout) and 2 s for SessionEnd (3 seconds); the legacy
synchronous spool writer takes no store lock; each wait
is still capped at two seconds. A pass whose capture cannot take the lock in time still exits
with the host's ordinary fail-open output, does not retain that input, and records a
`store_lock_timeout` diagnostic naming the holder's role, store phase and hold time (listed
under `store_lock_events` in `finishup observe status`); holds of one second or more are recorded
as `store_lock_long_hold`. Neither is reported as `observe` or `workspace_unconsented`.

An unexpected exception in a pass is recorded as `observe_<exception class>`
(`observe_exception_value_error`, `observe_exception_os_error`, or
`observe_exception_unavailable` for an unlisted class), never with its message. A drain whose
preflight fails names the stage: `drain_connect_timeout`, `drain_connect_failed`, or
`native_content_stage_failed`; `drain_preflight_failed` is left for a failed local outbox read
and for rows written before tb4n2 (see INTERFACES).

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

Codex consumes structured MCP results, so the `continuation` token arrives in `safe_details` and the
bounded text projection repeats the resolved directive for parity. No Codex-specific behavior is
configured.

The observed Codex failure this covers:

**Bounded text and committed operations (ADR-043, issue #1025).** Codex shows the model the
serialized `structuredContent` outside code mode and the bounded text summary inside it; that
summary is composed within 4,096 bytes (it was 512, and the closing `check` of 10 of 13
deterministic tb4n3 runs overflowed it). The verdict, the `overall next` instruction, the review
status/reason and the frontier with its head digest are reserved first, so a closing check always
reads. The receipt summary reserves the claim-verification pairing (its header and one line per
flagged obligation) ahead of droppable gap codes, inside the same 4,096-byte cap. When
AI-powered review failed inside FinishUP, the check and receipt summaries reserve that fault
sentence too, so a tight summary does not drop it. A text that cannot be built never fails a committed call: the clause is omitted and named
(`summary_render_failed:<builder>.<clause>`), a service diagnostic records it, and the structured
result is the call's result. Hook advice over FinishUP's own 2,000-character cap ends with a cut
marker (no Codex document states a hook limit; the cap is FinishUP's own). No Codex-specific behavior is
configured; it is the same on macOS, Linux and WSL 2.

The observed Codex failure this covers: a `start` with `actor_id` `codex:/root` was rejected as
`INVALID_REQUEST` with `fields: ["/actor/actor_id"]`, `reasons: ["invalid_type_or_value"]`, and
no continuation, and the text channel carried neither the field nor a way forward. The same
rejection now carries `input_correction_new_identity` and its text reads
`Rejected: invalid_type_or_value at /actor/actor_id.` followed by the directive to submit the
corrected body once under a new `request_id`. The regression case is
`tests/unit/mcp/test_recovery_directive_delivery.py`, which replays that exact body.

Provider-side failures reaching Codex through the app-server path keep their existing stage-typed
diagnostics (issue #529). Those failures also resolve through the shared recovery registry
(`continuation_for_semantic_outcome`, issue #742): the adapter's closed `failure_class` and the
recorded `semantic_reason` select a frozen directive, and raw provider text never reaches it.
Hook advisories never carry that token; SessionStart's vault-locked advisory appends its own
`vault_unlock_required` token after the host-specific prefix (issue #739). No Codex-specific
recovery wording is configured.

### Compatible newer transcript metadata (0.2.3)

The structural compatibility parser accepts fractional metadata introduced by Codex 0.153.4
without dropping the surrounding message or tool record: unrepresentable numeric leaves become
null, while the record commitment still identifies the original bytes. Its token-usage wrapper
is a known telemetry family from which no work evidence is inferred. Exact certified profiles
are unchanged. This repair does not add multi-agent lineage or promote a newer host capability
cell; unsupported shapes still report their coverage gaps.

For a returned start error with `start_busy_same_identity`, the reservation remains durable and
only its fenced lease was yielded. Replay the exact start body and request ID once, without
inventing session or writer IDs. `start_pending_same_identity` instead means a live lease remains:
wait up to 60 seconds before the one exact replay. If still busy or pending, retain the original
request and report the unresolved start. These continuations do not authorize a new task.

**CLI JSON (issue #741).** When an agent in this host runs `finishup` in a shell with `--json`, a
CLI-owned JSON error body carries a `recovery` object resolved from the same registry. A workflow
command (`start`, `publish-work`, `check`, `respond`, `status`, `receipt`) also prints JSON when
stdout is not a TTY; its failure keeps the exact wire body on stdout and writes the directive
lines to stderr. This is CLI behavior shared by every host; no Codex-specific behavior is
configured.

## Post-compaction recap (issue #1027, ADR-044)

Decision for Codex: **supported.** When Codex starts the session again after a context compaction
(`SessionStart`, `source: compact`), the `finishup hooks session-start` re-ground hook (registered by the
plugin for `resume|compact`, 15 s timeout) reads the mapped session's compact `status`, then up to three
bounded (1.5 s each, started within the hook's first four seconds) `obligations` pages for the declared
deliverables of the current plan, and appends a receipt-style recap
after the held-ids cue and the admission notice. The whole context is at most 4,000 characters
(the recap at most 2,400; every other hook context keeps 2,000). Each line names its source, withheld
text stays withheld, and any failure leaves the held-ids cue unchanged. A `resume` start is unchanged.

Facts about the host, from the tb4n3 sglang S rollout (Codex 0.159.3): compaction ran for about four
minutes with no tool call (`PreCompact` at 08:45:09, `PostCompact` at 08:49:06, `SessionStart` at
08:49:08); the hook output arrived as two `hooks.additional_context` developer messages (the admission
notice and the held-ids cue). Codex runs the re-ground hook and the plugin's `observe SessionStart`
hook concurrently; the one that wins the session lifecycle lock reads `status` and carries the
held-ids cue and the recap, and the other emits at most the admission notice (which is why the rollout
shows the notice and the cue as separate messages, once each). Either hook can therefore carry the
recap, and only the lock holder composes it. `PreCompact` and
`PostCompact` are registered async; their ordinary observe pass reconciles the rollout and drains the
outbox, so no extra drain is added (ADR-044 decision 5). A recap line states how many undelivered local
rows were pending when it was read.

Open question (not claimed): whether `PreCompact` accepts model-visible context, which would put the
recap into the summarization itself. No certified Codex profile documents it. Verify against the exact
host before using it.

## Cold service attachment and recovery (issue #670)

Codex SessionStart is synchronous even when tool hooks use the supported async profile. It
keeps its ten-second registration budget; async tool delivery does not authorize background
startup or service replacement.

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


### Review packet reserved room and named missing items (#907)

Codex `apply_patch` captures carry workspace-relative paths, so the newest applied edit of each path is
reserved as the current diff and older hunks for the same path are marked `superseded_by`. Shell
rewrites without visible bytes are still uncaptured (#883). Verification output is reserved per
command when the agent records the action, result and output; captured tool output has no command
identity until #910. An `insufficient_packet` check lists `missing_for_assessment` items with
their availability in the MCP and CLI check result; recheck only after supplying an
`agent_suppliable` item.

### One action per tool call and the standing orphan record (#917)

Each Codex tool call is one ledger action. An individually delivered `PreToolUse` becomes a
pending action keyed on the call's `tool_use_id`; its `PostToolUse` links the result and captured
output to that same action instead of recording a second one. A post whose pre never reached the
ledger (a FinishUP `start`/`publish_work`/`check`/`respond` call, whose pre stays local, or a lost pre)
still records its own action. In code mode the outer `exec` cell is decided per cell: its call is
always kept in the local store, and its output stays local only when one of this session's tool
hooks (`PreToolUse`/`PostToolUse`) was ingested after FinishUP read the call and its own triggered
reconcile completed before the output was read, so the hook fired while the cell ran and its nested
`exec_command`, `apply_patch` and MCP calls are the ledger record. A hook of the next cell never
counts for the previous one. This holds when `finishup observe reconcile` reads the call before its
nested hook, and for a long-idle session the bounded hook map forgot. A cell's output also stays
local when every nested tool item the rollout wrote between the cell's call and its output was one
of FinishUP's own MCP calls (`McpToolCall` with the FinishUP server, or with no server and a FinishUP tool
name, read as the later-material rule reads it; #1038): such a cell is FinishUP's own
call, recorded by those calls, whatever the hook timing (the hooks landing after the whole cell
was read, as tb4n4's hook latency showed, no longer leaves it a second `exec` action). A FinishUP
item counts only while its cell is the session's only open cell; any other nested item, a rollout
row the reader could not interpret, or a FinishUP item read while several cells are open removes the
mark from every open cell, so no cell borrows another's FinishUP calls. Limit: after parallel cells,
or in a session with a cell interrupted before its output (it stays open), later cells fall back to
the hook rule alone. A cell that made no observable tool call stays local too (tb4n5, ADR-029
amendment): in a session whose rollout has already written a completed tool item, a cell between
whose call and output the rollout wrote no tool item (`CommandExecution`, `FileChange`,
`McpToolCall`, or any other item family that is not a message, reasoning, compaction or hook
prompt), and while which no tool hook of the session was ingested, did no workspace activity; such
a cell (`text(load(...))`, `ALL_TOOLS.find(...)`, or only `tools.update_plan`) adds no `exec`
action after a check. In a session whose rollout never wrote a tool item (an older Codex, or a
session that has not called a tool yet) such a cell still delivers its output and is recorded.
Since #1038 the output pairs with its call on `call_id`, which Codex 0.159.3 needs (its rows also
carry their own `ctc_`/`ctco_` ids).

A cell that outlives its yield window keeps its identity until it ends (tb4n5, #1038 follow-up).
Codex writes `Script running with cell ID <id>` as the `exec` output, keeps the cell running, writes
its nested calls after that output, and returns its further output on later `wait` calls (each
naming the cell in its `cell_id` argument; the terminal one starts with `Script completed`,
`Script failed` or `Script terminated`). FinishUP reads only those host-written headers (the output's
first text item, which the cell's own output cannot forge) and the `wait` argument, never the cell's
JavaScript. The yield output is held with the still-open cell, nested items read while it is the
session's only open cell mark it as before, and the terminal `wait` output decides it by the same
rules; only a cell that is not FinishUP's own, not tool-less and not hook-recorded then delivers its
held yield output as its record. A yielded cell nobody waited on is decided at the turn's end
(`task_complete` or `turn_aborted` in the rollout). The `wait` polls stay `no_tool_activity`, so a
yielded check-only cell with any number of polls (or a `clock.sleep` while it runs, hook spelling
`clocksleep`, also `no_tool_activity`) no longer makes its own check stale. In tb4n5's semantic arm
20 such cells in 5 of 9 attempts did, and 3 final receipts kept `check_current_as_of_earlier_frontier`.
Overlapping cells keep the no-borrowing rule above. Tests:
`tests/integration/application/test_codex_yielded_cells.py`.
Limits: a cell mixing hooked and unhooked tools stays local, so its unhooked tool is not recorded;
a hooked cell whose call is read only after all its nested hooks, whose hooks' reconciles did not
complete before its output was read, whose hooks fired before an upgrade from the earlier cell
format, or whose entry the bounded maps forget before its output keeps its own action beside its
nested calls, and a hook landing while an unhooked cell runs can keep that cell local; an
interrupted cell whose output never reaches the rollout adds no record of its own; a retained
wrapper counts in `observed_count` without an accounting bucket. The rollout's completed command, MCP and patch
items follow the same session rule (#910, see [Tool outcomes](#tool-outcomes-issue-910)). A replay of the #917 code-mode example holds one action and one
result per nested call and at most four hook-observed events per shell command, down from about
7.9. Sessions that started before the upgrade keep their historical second action per call.

A post with no open pre (`unpaired_event`) stays disclosed on `status`, check coverage and the
receipt for the rest of the session, including after resume and restart. It no longer produces the
"Observation coverage is incomplete or stale" advisory. The advisory names its cause as
`cause:<gap>` and clears when source lag, a stale cursor, drain backlog, an unavailable service or
a locked vault recovers. Unsupported rollout records (`unsupported_event`, `unsupported_format`)
still raise it and do not clear in session; that classification is a follow-up. Instead the agent sees one "FinishUP notice (no response
needed)" in hook `PostToolUse` context the first time a new source/session/generation scope has an
orphan. It is not a finding: do not respond to it, recheck for it, or wait for it to clear. The
same applies on macOS, Linux and Windows through WSL 2; native-host dogfood evidence for this
change is tracked on #917.

### Reviewable native edits

Codex `apply_patch` calls (including code-mode nested calls) enter the shared encrypted capture lane
as workspace-diff content. Codex 0.157.x sends the patch as `tool_input.command` on both PreToolUse
and PostToolUse; the older `patch`/`input` carriers are still read. The post-tool `Exit code: N`
result prefix supplies the edit outcome and the structural `exit_status`. In code mode the outer
`exec` cell has no hook payload, but each nested `tools.apply_patch("...")` call is dispatched
through the tool registry and fires its own `apply_patch` hooks with the same shape, and each nested
`tools.exec_command` fires `Bash` hooks with `tool_input.command`. A shell `apply_patch <<EOF` is
intercepted by `exec_command` and fires only PreToolUse, so its patch is captured from that event
with outcome `unknown`. Its pending attempt is pre-only (#1041): it does not wait for a post Codex
never sends. A `FileChange` item the rollout writes in the same session closes it: the attempt
whose call id the item names; an item naming another call the session's hooks reported (in direct
mode a native `apply_patch` item carries its own call id) is that call's change and closes none;
only an item whose id names no reported call (code mode's `exec-<uuid>`) closes the session's oldest
pre-only attempt. One no file change closes before the ten-minute pending deadline or the session's
end still records `pending_attempt_expired`. Its pending action is the ledger's only record of the
edit (the `FileChange` item stays local), so the hook gives it the write scope of the files its
patch headers name (`*** Update File: ...`), classified as the native `apply_patch` tool's paths
are: it counts as an edit for the latest-edit fact, supersedes an earlier check as an edit, and is
the first material edit that re-arms a deferred review where the check-time capture is unavailable
(a non-git workspace; #1046 review). Before this, 44 of tb4n4's 60 deterministic attempts
carried that gap for this host behaviour alone. Limit: in code mode the item id (`exec-<uuid>`)
does not name the hook's call, so a nested `tools.apply_patch` change in the same session can close
a shell patch's attempt in its place; a reported call is known from its open pre or the local ring
of the last 256 observed rows, so a direct call both have dropped (an eviction the ring discloses)
can do the same. The count of closed attempts never exceeds the observed changes. Whole-file heredoc writes (`cat > path <<EOF`, `tee path <<EOF`) and `git
apply <<EOF` are captured from the post-tool `Bash` event; writes outside the workspace, such as
`/tmp` scratch files, are skipped. Edits made by `sed -i`, scripts or `git apply <file>` carry no
edit bytes in the command and are not captured (the check-time change below still shows their
result); other generic command input does not become code evidence. This capture uses the existing
profileless Codex observation consent; users who granted it earlier now also have `apply_patch` text
encrypted locally, while egress still follows the selected review recipe.

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

The directory is the one the check's own connection named: the Codex MCP bridge's working directory,
or the working directory of `finishup check`. The service reads that directory only when it resolves to
the task's own repository, and never runs a shell, hook, filter, external diff, credential helper or
network transport. The task-start commit is recorded when `start` creates the task. A task created
before this version, or from a connection that named no workspace, has none; its first check pins
HEAD as the task's base, later checks diff from that commit so work committed between checks stays
in the change, and each such check reports `check_time_change_base_unavailable` because work
committed before that first check is not in it. Codex code mode, nested `tools.apply_patch` calls
and `exec_command` rewrites need nothing extra: the change is read from the repository, not from any
hook. The capture honours the review recipe and privacy policy like any other excerpt, as
`repository_excerpt` items: a policy whose inference channel does not allow that category never
sends them, and the check reports `semantic_review_context_withheld`. Credential-like spans are
redacted first (`check_time_change_redacted`), every part still passes the never-send scan, files
named like credentials (`.env`, `.env.*`, `.netrc`, `*.pem`, `*.key` and similar, a name heuristic)
are listed by name only, and a change larger than the packet reports `check_time_change_truncated`.
The whole capture has 20 seconds. It is `check_time_change_unavailable` for a linked Git worktree or
a submodule checkout opened as the repository (its `.git` is a file), a repository root another
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
this host are Codex `apply_patch` workspace-diff captures (a whole patch or a hunk-sized byte range
of it), heredoc and `git apply <<EOF` captures, and captured tool output. The follow-up owner is
issue #912.

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

Codex project setup, hooks and MCP use the shared project-root rule (ADR-007, 2026-10-14): a
non-root user may use a root-owned project root that no other account can write, or a sticky one.
Files FinishUP writes inside the project must still be the user's own. Verified for Codex in a Boat
container as `nobody` and `agent`; Claude Code and Cursor are unit-tested on the same rule.

**Runtime another account installed.** Decision for Codex: same path as every host (shared entry
and setup code; no host-specific change). A runtime root installed and a non-root user runs stops
`finishup mcp serve`, `service run` and every hook with `release_runtime_not_owned` (exit 20) instead
of `release_runtime_unavailable: permission_denied` or "could not be verified". Codex shows the MCP server's startup error with that text; its hooks exit 20 with no stdout, so they make no allow or block decision and Codex continues the turn. Terminal
commands print the `.<prefix>-releases` directory the user must own; hook stderr carries the token
without local paths. Every connect path refuses to connect Codex to such a runtime (or one another
account can write) with that reason and leaves status and disconnect available. `finishup instance create --bind-runtime` on such a runtime
is `runtime_pin_unwritable` and keeps nothing, so a retry after the repair succeeds (ADR-028,
2026-10-14 amendment). Install FinishUP as the user, or see the Linux runbook for the one-user
`.<prefix>-releases` layout. Verified on Linux as `nobody` against a root-owned runtime (entry and
hook paths, not a Codex session); the Codex connect refusal is unit-tested.

**Review fixes (independent review of #1071).** Decisions for Codex: (1) a checkout root made
(`/app/.git` owned by root) is the project, used as a plain directory, through the shared
workspace binding (same path as every host); (2) Codex-specific: marketplace removal anchors its
descriptor walk on the project root and now judges that anchor by the project-root rule, as install
does, so `integrate codex plugin remove` and Codex disconnect remove `.agents/plugins/marketplace.json`
in a root-owned project instead of failing with `write_failed` (`conflict: repository_marketplace`)
after stripping the Codex config, on every retry; the Codex home keeps the owner rule; (3) host
admission never writes `.codex/config.toml` into a `.codex` another account created or others can
write (same path as every host; refined in round 2 below). Covered by tests through
the public install, activation and removal functions with simulated ownership.

**Review fixes, round 2.** Decisions for Codex (same path as every host unless named): (1) a
checkout root made (`/app` and `/app/.git` root-owned), or the user's own `git init` in a sticky
root-owned `/app`, now passes the service handshake: the service commits the plain directory
identity without running Git (Git refuses another owner's checkout), so hooks and MCP attach;
Git-based change capture reports `unsafe_root`. A root-owned `.git` file with more than one link
is not trusted. (2) A `.codex` root committed to the image is read normally: admission status is
`absent` (typically) and host admission's reverse sweeps (Codex disconnect, `integrate codex plugin remove` and strict MCP re-registration) report nothing to remove instead of `write_failed`; a
grant into it is refused `target_unsafe`. A `.codex` another account made, or one others can
write, is `unknown` (`folder_not_owned`) in status and refused by grant and revoke; writes to
`.codex/config.toml` go through the host folder pinned by descriptor, never a link swapped in after the
check. (3) Codex has two connect front ends: bare `setup run` (the Codex wizard, also with `--codex-path`) and the full-screen interface's Codex preview both refuse before previewing or writing any registration, as `setup run --host codex` does. Covered by tests through the public paths with simulated ownership, and the
repository identity with a real Git checkout owned by another uid.

**Review fixes, round 3.** Decisions for Codex: (1) the plain directory identity of a root-built
checkout is now its top's (the directory holding `.git`), the same from any subdirectory, so a
session started below the top meets its own hooks instead of `repository_identity_mismatch`
(same path as every host). (2) Check-time change capture reports `unsafe_root` for such a
checkout; the receipt reads "the repository failed a safety check (a link, another owner, ...)",
not "not a Git repository" (same path as every host). (3) `integrate codex mcp preview|install` (also the prompt-loop menu's "Install registration") now
refuses a runtime that cannot serve this account with exit 20 and the token, before any
registration; status, `preview-remove` and `remove` stay open. `finishup recommend accept
codex-plugin-activation` (setup's next command, which enables the Codex plugin and its hooks)
refuses the same way before refreshing or previewing; `recommend list` and `decline` stay open.
`integrate codex plugin` is removal only and is not refused.

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

Decision for Codex: supported, service-side, identical on every host. The reviewer instruction, the
packet ranking (since #1108 the change's reserved share first, then task inputs within an eighth of
the excerpt room, the verification oracle, FinishUP's summaries of binary inputs, redundant captured
edits yielding to the latest verification) and the digest-only alias are composed by the service
from the ledger and the check-time read; Codex needs no host step and nothing new is captured from
it. `admitted_input_roots` is a field of the current repository's privacy grant: `finishup privacy
input-roots add <dir>` is a widening that applies only after the trusted-terminal decision, `remove`
is an immediate tightening, and `status`, `finishup privacy show` and `/privacy` show it. Codex
sessions, MCP tools and hooks have no write path to it; an agent learns from the review guidance
that only the owner can admit a folder. No Codex capability gap. The consent-gated local copy of
each outbound packet is not part of this change (#1085).

## Reviewer instructions and packet order (n7, issue #1108)

Decision for Codex: supported, service-side, identical on every host. A tool output a Codex hook
captured reaches the reviewer behind `[FinishUP: observed output captured by a host hook (evidence
<evd_>)...]`, which the instruction treats as a witness; FinishUP's own records (an approved check's
result, an import report) carry their own labels; the agent's disclosures travel in one
`agent-disclosures` row marked as its assertion; and the packet lists the task, the change, task
inputs and observed output before the agent's account. Nothing is captured from Codex beyond what
its profile already captures, and no host step changes. The label's run clause (command action,
host-reported outcome, exit status) appears only when the hook recorded both the action and its
result with a keyed `omitted:hmac-sha256:` command identity equal to the capture's. A Codex
post-tool fixture proves it end to end
(`tests/unit/application/test_native_verification_follow_up.py`). Codex does not capture pre-tool
input bytes; the identity comes from the post-tool command context it keeps for test, build, lint
and typecheck runs. No Codex capability gap.

Issue #1102 (same decision for Codex, service-side, no host step and no new host payload): a
directory the task names inside the repository reaches the reviewer as FinishUP's listing of its
unchanged files plus the members most likely related to the change (sharing names with it, or beside
the changed files); a quoted or escaped path with spaces is one candidate, and when only the disk
can tell a spaced folder from prose the whole path is looked for before its words; an admitted
outside directory named without a trailing `/` is listed; an `other` follow-up request is answered
only from rows FinishUP recorded for the run or edit it names. When the task names a file or folder
outside the workspace that no admitted root covers, the check records
`task_input_outside_not_admitted`, whose fixed sentence names the owner's step
(`finishup privacy input-roots add <folder>` on a trusted terminal); it is a disclosure only, never
a Stop-gate item or a continuation on Codex. Codex still has no write path to admitted roots,
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

Decision for Codex: supported, service-side, identical on every host. `credential_heuristic` is a
field of the current repository's privacy grant that the service applies only to external
AI-reviewer egress; agent-context projection and the local model keep the filter. Codex needs no
host-specific step and gets no write path: `finishup privacy credential-heuristic disable` is a
widening that applies only after the trusted-terminal decision (walking the grant-creation
ceremony when the repository has no grant), `enable` is an immediate per-repository tightening,
and `--machine-default` moves only the default for new grants. MCP `status` carries
`credential_heuristic` (`repository`, `machine_default`) before any check; MCP tools and hooks can
only see the setting (status, the `semantic_review_credential_heuristic_disabled` check gap, the
external receipt's `secret_scan.credential_heuristic`). No Codex capability gap.

## Privacy receipts listing (issue #921)

`finishup privacy receipts list` and `get` are host-agnostic: every host's sessions write receipts
into the same local audit, and the operator reads them through the same CLI and control method.
Pages over 64 KiB now cross the local control socket in bounded chunks, an unreadable stored
receipt is skipped, counted and named (exit 40) instead of failing the page, and a store-side
failure is `privacy_audit_unreadable` rather than `invalid_request`. In-process tests drive the
real service, socket and client. Open evidence gap, owned by #921: a dogfood run on Codex
(macOS, Linux and WSL 2) that completes an AI-powered review session and then shows that
session's `network_egress` receipts in `finishup privacy receipts list`.

## Status page cost (issue #916)

`status` pages and `closure-prepare` no longer pay ~18 ms per returned row: the shared service,
control and bridge path decides schema validity without rebuilding diagnostics for valid results,
with byte-identical pages and receipts. This host uses that path unchanged. Its per-host dogfood
timing on macOS, Linux and WSL 2 is not yet measured; issue #916 owns it. See
[status render performance](status-render-performance.md).

## Hook schema loading (issue #1083)

A Codex hook process no longer builds the full schema catalog before its first control frame.
It parses only the control envelopes' schemas and their `$ref` closures, 92 of 232 documents,
with the same verdicts and errors ([interfaces](../INTERFACES.md)). Unchanged on this host:

- `hooks observe`, `hooks user-prompt-submit` and `hooks post-tool-use`;
- hook registration, payloads, outputs, recorded events, ordering and timeouts.

Host decision: supported, same code path.

Latency: the #1083 replay drove 48 PreToolUse and 48 PostToolUse callbacks rebuilt from two
recorded TB4 D-lane rollouts through the build before and after the change on macOS arm64 (single
idle machine, shipped launcher). The median PreToolUse fell from 1,891 to 1,259 ms and PostToolUse
from 1,921 to 1,261 ms (p90 2,173 to 1,527 ms and 2,141 to 1,564 ms). Linux and WSL 2 timings are
not yet measured; issue #1083 owns them.

Equivalence: the #1087 replay proof ([test instances](test-instances.md)) replayed 20 Codex
callbacks rebuilt from a synthetic rollout of 8 tool calls, and 9 malformed payloads, on Linux
x86_64 on 2026-10-17 through the merged predecessor (`0.3` at `c0198bb16`, with #1080 and #1086)
and this change's head (`ea1f6eda4`). Every exit code, stdout and stderr byte, drain, status read
and ledger event with its full payload compared identical after the normalization that runbook
describes, which matches run-generated values, such as task, session and result ids, one-to-one:
231 compared parts in the Codex workspace, including 26 ledger events. In the new build 15 of those
callbacks parsed only their schemas and none built the full catalog; the old build built it in the
same 15. A second replay of the new head compared identical with the first.
The MCP bridge (`mcp serve --host codex`) is not replayed: it builds the full catalog as it starts,
so its validation is unchanged by this change.

## Expanded excerpt count (issue #907 Phase 1b)

Decision for Codex: nothing is host-specific, and the behaviour is identical on every host and OS.
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

Decision for Codex: supported through the agent-supplied field, identical on every host and OS.
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

Codex renders a `UserPromptSubmit` hook, but whether `codex exec` fires it for the initial prompt is **unverified** in this repository (not exercised by the dogfood or capability suites). FinishUP does not read captured prompt text for review in any case; see below.

Host-captured prompts (`host_captured_user_prompt`) are not used on any host in this version:
captured prompt text never enters the packet, and the Expanded-only, explicit prompt-capture
choice that would allow it is still open on issue #908.

Automatic attach does not record a task statement. The shared observation hook opens the task
with a generic title and no `task_statement`, so until the agent calls `start` with the user's
request the reviewer sees at most that title (`task_title_only`), and the receipt says so.
Recording hook text there would label it `agent_transcribed`, which it is not, and would bypass
the prompt-capture consent still open on issue #908.
For Codex the first attach runs on `SessionStart`, before any prompt exists; a retry on
`UserPromptSubmit` is also unproven for the initial `codex exec` prompt (above).

### Limitation requests, `reopened` and one dialogue per concern on Codex (tb4n3 RC-1 and RC-7, #1024, #1030)

Host decision: supported, no host-specific code. The change lives in the shared kernel, `respond`
and review paths (ADR-034 and ADR-040 amendments of 2026-10-11), so Codex behaves exactly as the
other hosts. The Stop hook and the MCP `respond` tool take the shared path; a Codex session sees the same `respond` description (`reopened`, limitation requests) and the same `closure_after`. What a Codex agent can rely on:

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
check, respond, status and receipt operations with a compliant reviewer; a live Codex transcript on
macOS, Linux and WSL 2 is not recorded for this change.

### Call-schema traps on Codex (tb4n4, #1049)

Host decision: supported, no host-specific code. Every change lives in the shared protocol request
models, the MCP bridge's `read_guidance` dispatch and error hints, the status text and the kernel's
`command_attempts` rule, so Codex takes the same path as the other hosts. What a Codex agent can rely on:

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
the tb4n4 exports themselves were not replayed, and a live Codex transcript on macOS, Linux and
WSL 2 is not recorded for this change.

### Avoidable MCP rejections on Codex (n7 RC3, #1103)

Host decision: supported, no host-specific code. Every change lives in the shared publish and
respond request models, the `respond` and `receipt` applications and the `read_guidance`
resolver, so Codex takes the same path as the other hosts. What a Codex agent can rely on:

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
  reason maps its own), and its message states the rule. On Codex, `structuredContent` carries
  `safe_details` and the message, and Codex reads it in place of the text, so the agent sees the
  reason, the field, the continuation and the rule itself.
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
`tests/unit/mcp/test_tb4n4_call_traps.py`; the n7 exports were not replayed, and a live Codex
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

Owner-view presence decision for Codex (#1073): same path as every host, because the owner view is
a CLI and terminal-interface flow, never an MCP tool or hook. On macOS the service itself raises a
LocalAuthentication dialog (Touch ID or the login password) showing the confirmation code the
command prints, on either vault mode, including setup's system-keychain choice. A vault passphrase
the owner chose is asked for once when the service cannot show a dialog, or directly with
`--use-passphrase`; a passphrase kept in the system credential store is never prompted for on its
own. On Linux and WSL 2 there is no presence provider: only a vault passphrase the owner types
completes it, and a vault without one, or with one kept in the credential store, fails closed with
`owner_view_unavailable`. When Codex runs the command through `exec_command` with a pseudo-terminal,
the dialog appears on the owner's screen and the agent cannot answer it; a cancelled dialog is
`owner_view_refused` and shows nothing, and repeated dialogs back off. Without a terminal the command
ends with `owner_view_requires_terminal` before any dialog. If an agent's own ceremony is open, the
owner's command reports `owner_view_busy` with its own code, and any dialog on screen is not the
owner's. The dialog itself is covered only by stub-helper tests until
the manual check in [test-instances.md](test-instances.md#owner-view-with-touch-id-manual-check-on-a-real-mac-1073)
runs on a real Mac.
## Per-task review mode and agent opt-in (ADR-049)

**Decision for Codex: supported, the same MCP path as every host.** A task starts with local
checks under the owner's recommended setting (`conversation_review = local_agent_opt_in`); the agent
turns on AI-powered review for its own task with one `publish_work` draft, `decision_recorded`
version `1.1.0` with `review_mode: "ai_powered"` (`"local"` turns it back off), and then checks
without `mode`. `check` and `status` carry `review_mode`; the receipt names each switch. Guidance:
`finishup://guidance/review.md` (when to turn it on, when to stay local, the exact draft). Nothing
Codex-specific is involved: no hook, skill or registration field changes.

- **Owner setting.** `finishup privacy conversations agent-opt-in|owner-approval|local-only|ai-powered|status`
  for the current repository; first-run setup records it from its three answers. Owner approval
  makes each review the agent turns on wait for `finishup privacy decide-disclosure`, the same
  `awaiting_human` path as **Ask every time**.
- **Route.** Every interactive setup answer now registers the policy route. A registration made by
  an earlier local-only setup is on the strict route: an opted-in task there runs local with
  `route_local_only` (so does any task under "every task"), and the check prints the fix,
  `finishup setup run --route-profile policy` (or `finishup integrate codex mcp preview
  --route-profile policy`, then `finishup integrate codex mcp install --route-profile policy
  --accept --preview-digest <digest>` with the digest that preview printed). Then start a fresh
  Codex session.
  Non-interactive setup keeps the strict default for a fresh registration, and without
  `--route-profile` an existing registration keeps its route. The registration is shared by every
  project of the Codex home (#1058), so moving it to the policy route (an interactive answer, or
  the fix above) changes the route for the other connected projects too: the preview names them
  (`route_changes_for`, `route_changes_possible_for`) and an unattended `--accept` stops until
  that exact preview is approved.
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
  review as the default; with the ChatGPT subscription reviewer nothing is marked recommended, so
  the owner picks Assisted or Expanded explicitly. Private stays selectable and says that tasks
  stay local under it. The terminal interface's `/connect` for Codex keeps its own
  inspect/repair path and asks no review question (same as before).
- **Other repositories (review round 2).** A fresh install's first repository grant gives the
  installation row the hybrid (or the narrower answer), so another project or an independent clone
  starts local; a repository without its own privacy grant reports "AI-powered review is not set
  up for this repository" (`ai_review_available` false) and an opt-in there records
  `ai_review_not_set_up` until the owner approves that repository's grant (terminal or chat; a chat
  grant starts on the same first-grant default). Installations whose row already sent work keep
  the released repository-grant handoff.
- **Agent-driven setup.** Preview with `finishup setup run --host codex --route-profile policy
  --non-interactive --json` for every answer; without `--route-profile policy` a fresh
  non-interactive registration is strict and every task stays local (`route_local_only`).
- **Round 3.** In a repository without its own grant, `finishup privacy conversations
  agent-opt-in` (or `owner-approval`) walks that repository's privacy grant with the setting
  included (a local terminal is required; otherwise `local_terminal_required` and the command
  names `finishup --privacy`). With a reviewer bound, `finishup --privacy` lists the AI-powered
  review options (Assisted review by default) on a first grant and under agent opt-in or owner
  approval. Switching back to local after the closing review costs one more closing review
  (`review.md` says so). The MCP receipt summary's review-mode pointer is JSON-receipt only.
  Same path on Codex; with the ChatGPT subscription reviewer nothing is marked recommended,
  so Assisted review is the default and Assisted or Expanded must be chosen.
- **Round 3 verification.** A first Private grant in a repository reads as local only (an explicit
  `local_only` where it inherits an earlier repository's hybrid). `finishup --privacy`'s
  AI-powered review listing words Assisted review for the route: on a route without reviewed
  data-use terms it is the default, not recommended, and its draft records no evidence
  requirement. Where the released carry-forward is pending, status says the installation's earlier
  permission is carried forward when a task first starts in the repository.
  Same on Codex.

## Setup refresh and suggested reviewer model (FinishUP 0.3, #1067)

Decision for Codex: supported. The shared setup path changed, and every item below
applies on macOS, Linux and Windows through WSL 2.

- **Agent list and Codex list.** The guided agent list (shown in a terminal whenever Claude Code or
  Cursor is installed; on a machine with only Codex the Codex wizard runs instead) shows each
  installation's executable path, says one agent is connected per run, and defaults to the Codex a
  plain `codex` command resolves to on `PATH` rather than the first path in sort order. On a machine
  with only Codex, the Codex wizard's list of installations uses the same default. Codex plan
  summaries were already plain sentences; unchanged.
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
sandbox walk had no macOS keychain), and no native Codex session was recorded for it.

Verification-output follow-ups retain complete post-tool verifier input locally beside its
output, under the existing scoped content-capture consent and byte limits. The shared resolver
uses the authenticated same-phase input only for eligibility; it never sends that input as an
excerpt. Older captures without this context remain withheld. Private and repository-excerpt
denial withhold the auto-supplied output. This shared path applies on macOS, Linux and WSL 2;
native Windows is not claimed.

### Closing currency and observation replay (PR #1080)

Closing-review currency follows what a command did to the workspace, never its text (owner
decision, PR #1080 round 5; ADR-033). The Codex `PreToolUse` and `PostToolUse` hooks (`finishup
hooks observe`) fingerprint the workspace around every shell, `exec_command`, `write_stdin` and
third-party MCP call, and the post envelope carries `workspace_effect`. Host decision (n7 RC1,
#1105): Codex fires the unified-exec `Bash` `PostToolUse` only after the process has exited (no post
while it runs; the `write_stdin` poll that sees the exit sends the original call's post under its
id), so that post is the call's completion fact for the comparison, while its outcome stays
`unknown` until the rollout item supplies the exit. Before this, every Codex shell call read
`unavailable` and every later read re-armed the closing review. A Codex post is not a success fact
either: a read-shaped call is recorded on its own, never folded into a routine-read summary on the
post alone, so a failed `rg` keeps its exit 1 once a joined rollout item states it (a
`CommandExecution` item; a `function_call_output` row needs the stream reader's header change, n7
W2), and stays `unknown`, never a success, until then. FinishUP cannot establish the effect of a
response that reads as Codex's own `Process running with session ID N` header (an older or future
build), of a call whose pre-call pass did not run, and of every call observed only through the
synchronous legacy `finishup hooks spool` ingress (Codex builds without async command hooks) or only
through the session stream; those stay material. The session stream never folds a shell call into a
routine-read summary. When the stream copy of a call is recorded before its hook post, the post's
fact still reaches the call as one annotation row under its action, so a harmless read is not left
material by arrival order; a later `changed` or `unavailable` for the same call always outweighs an
earlier `unchanged` (round 6). An unchanged command (`date -u`, `rg`, `sed -n`, `git status`, a
FinishUP CLI call such as `finishup check` or `finishup status`: no lexical own-call exemption, the
comparison decides) does not re-arm the closing review; a command that changed the workspace does,
and so does one whose effect FinishUP could not establish, which the Stop text says. A command that
backgrounds or detaches a process (`cmd &`, `nohup`, `setsid`, `disown`, an `&` handed to `bash -c`,
`eval` or `ssh`) is never established, because it may write after the call ends; a quoted `&` in an
argument of a program FinishUP knows does not run its arguments or stdin as code in the form given
(`curl 'h?a=1&b=2'`, `sed 's/x/&/'`, `rg 'a&b'` without `--pre`) is not a background launch, while
`sudo`/`doas`, `wget`, shells, interpreters, other code-running programs, a wrapper or assignment in
front of the program (`env -S`, `LD_PRELOAD=`, `PATH=`), ANSI-C quoting (`$'...'`) and any `#` or
`<<` in the text (a quote in a comment or here-document body is one bash ignores) keep the
cautious reading (#1089). Round 6: neither is a call whose exit leaves a process it started still
running in the project (a launcher whose new-session child keeps working, with no background word in
its text): before comparing, the post-call hook reads the process table (`libproc` on macOS, `/proc`
on Linux and WSL 2) for a process of the same user that started during the call, is no longer
parented by the host, and has its working directory or a file open for writing in the project; one
found, or a process table that cannot be read, makes the call unverified. A directory that gains or
loses an entry while it is being compared does too. A pre-call snapshot that could not finish before
the host stops waiting is never stored, and the 0.75 s bound covers the whole pass, hashing
included. Verification runs (test, build, lint and typecheck runners, and the task's requested
commands) and package installs stay material whatever the workspace shows. The workspace is
everything under the project root, ignored files included; inside VCS metadata only the internal
churn (objects, refs, reflogs, the index and lock files) is skipped, so `git status`, a commit or a
branch stays unchanged while a `.git/config` or hook edit counts; `node_modules`, `.venv`/`venv`,
`.tox`/`.nox` and tool caches are compared at their first level (files by content, subdirectories by
identity); `__pycache__` bytecode is skipped but any other file there counts; FinishUP's saved
receipts and state are skipped. A task that declares a delivery inside the project where the
comparison does not reach it (a VCS store such as `.git/objects` or a skipped bookkeeping file such
as `.git/HEAD`, below the first level of a dependency environment or tool cache, `__pycache__`
bytecode, a saved receipt) gets no unchanged command; a declared `.git/config`, `.git/hooks/*` or
`node_modules/x.js` is compared and does not. Effects outside the root (databases, `/tmp`, the
network, a deliverable path outside the root, judged against the task's absolute `workspace_ref`)
are out of scope, as before. `finishup observe status` names a degraded comparison once as a
`workspace_fingerprint_<reason>` diagnostic (`too_large`, `timeout`, `unreadable`, `root_unusable`,
`store_unusable`, `process_table_unreadable`), and names `workspace_fingerprint_consent_unreadable` when the pass could not re-read consent and so recorded nothing; a call without its pre-call snapshot or still running
is recorded on its result as `(workspace unverified)` instead. `finishup observe status` also counts
every reading by its closed reason (`workspace_effect:` line; JSON `workspace_effect_readings`, with
the last 64 readings and their call ids): `call_incomplete` (no completion stated),
`background_launch`, `process_lingering`, `workspace_unsettled`, `no_pre_snapshot` and the degraded
reasons, so a call that stayed material can be attributed locally. A closing review that ended
without a judgment (`outcome_unknown`, `timeout`, ...) is not asked for again: readiness names
`semantic_review_no_judgment` and the Stop text points to that check's own continuation (at most one
new check) or a disclosed finish that reports a required review as unmet (ADR-033 n7 amendment).
Real edits and review-mode switches still re-arm; receipt, work-close and lifecycle records do not.
The behavior is the same on macOS, Linux and WSL 2; native Windows is not claimed.

Call-keyed hook/stream overlap requires an agreeing committed action core and checks reused
evidence against its original causal action/result association. An evidence-only collision cannot
create a different call or lend evidence to its pre-action. Missing captured evidence is appended;
conflicts still reject. Generic `finalize` and `*_regression` names grant no verification credit;
task-specific verifiers can use explicitly requested command matching under ADR-045. Capture consent,
authenticated command/output binding, privacy policy and provider limits remain required for verification-output auto-supply.
Native runner classification unwraps one ordinary host shell and retains nested executable paths;
keyed identity normalization is separate. The original completed
verification remains authoritative when its output is later retrieved through `write_stdin`.

### Server-filled publish boilerplate and brief status (#1084)

Host decision: supported, no host-specific code. The change lives in the shared protocol request
models, the publish application, the MCP bridge, `finishup publish-work` and the startup gate hook,
so Codex takes the same path as every other host. What a Codex agent can rely on:

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
- Codex reads the structured result, so the minted ids arrive in `accepted_events` and
  `server_filled`. In code mode a sandbox without `crypto` no longer needs a UUIDv4 helper for
  `publish_work` (it still does for `start`, `check`, `respond` and `receipt`). Codex has no
  startup gate hook; its observation hooks are unchanged.
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
MCP unit suites exercise the shared path. A live Codex session on macOS, Linux or WSL 2 is not
recorded for this change; native Windows is not claimed.

## Review results Codex actually shows, and supply that counts (W6, #1107)

**Upstream facts (pinned to `rust-v0.159.0`).** Outside code mode Codex hands the model
`serde_json::to_string(structuredContent)` and ignores `content` whenever structured content is
present (`codex-rs/protocol/src/models.rs:2302-2331`). `McpToolOutput::response_payload`
(`codex-rs/core/src/tools/context.rs:185-212`) prefixes `Wall time: N seconds\nOutput:\n` and cuts
the middle of a long body with a 50/50 head and tail split
(`codex-rs/utils/string/src/truncate.rs:38-69, 126-129`). A model slug missing from the bundled
`models.json` (for example `gpt-6.1-sol` at this tag) falls back to `bytes(10_000)`
(`codex-rs/models-manager/src/model_info.rs:127`), ×1.2 serialization allowance
(`codex-rs/utils/output-truncation/src/lib.rs:16-18`): the model sees the first and last 6,000
bytes. A bundled slug uses `tokens: 10000` (24,000 + 24,000 bytes). `serde_json` is built with
`indexmap`, so the model sees FinishUP's field order. The event copy at
`codex-rs/core/src/mcp_tool_call.rs:982-1025` is truncated separately for the UI and rollout only.

**Host decision: supported.** Every check result leads with `agent_next` right after `verdict`
(ADR-043 amendment): the next action and, for missing review input, each item, its targets, how to
supply it and what counts, within 2,048 bytes, so it always lands inside the 6,000-byte head.
`overall_next` and `missing_for_assessment` follow it, ahead of findings and every bulky field. A
lost or cut result is recovered with `status view=operation` for the check's `request_id`: the page
now carries `check_outcome` with the same verdict, `agent_next`, `overall_next` and missing items a
same-id resend from the same session returns, so an agent never replays the check through the CLI
to read them. Gap: both need the closure basis at the check's result frontier, which the service
holds in a process-local memo per reading session (eight frontiers) and otherwise re-reads from the
ledger, which refuses once a later material record exists (ADR-046). So a successor writer after a
same-task attach (its `session_resumed`), or any reader after a service restart once later work is
recorded, cannot rebuild it. The page then rebuilds a `supply_missing_input` lead from the stored missing items
when one is `agent_suppliable` (each item, how to supply it and what counts, without the predicted
receipt conclusion) and omits any other continuation; the verdict and missing items always come
back. Persisting the continuation with the stored check is a storage follow-up owned by #1100.

**Supply on Codex.** The captured output of a shell re-run of the target's exact command that
FinishUP observed after the request counts as supplying a targeted `verification_output` (or
`other`) item (ADR-006 amendment). The hook and the session-stream copy commit the run in different
shapes: hook first, the observed result cites the captured output but reads `unknown`, and the
stream item then appends the corrected result to the same action; stream first (the usual order on
0.159), the stream copy commits the action and result and the hook's captured output arrives late,
linked to the run's action event, and no result cites it. Every result of one action is one run, so
supply matching reads both shapes as the same run's output and never takes the corrected result for
a newer run without output. Only captured `tool_output` counts; the captured command input does not. Codex
shell calls are observed on the default hook registration, but output bytes are captured only under
the workspace's content-capture consent, so without it a re-run records no output and supplies
nothing. The output must also reach the reviewer whole before a repeat is dropped as already
supplied, which Private or a selection without repository excerpts never allows; long output the
packet clipped keeps the item, and the in-check follow-up adds the rest. An observed run never
answers `command_identity`: it records only `omitted:<keyed identity>`. `agent_next` therefore
always says to publish one `result_recorded` of the target's action with the output in `summary`,
even after a re-run, and says a re-run counts only once its output reaches the reviewer. A respond
counts only for a finding target; a description never counts.

**Verification:** `tests/unit/mcp/test_codex_structured_head.py` emulates the cut on the real bridge
projection. `tests/integration/application/test_observed_rerun_host_copies.py` feeds the recorded
Codex `PostToolUse` payload through the real hook mapping and the recorded rollout through the
session-stream reader and the service coordinator, in both commit orders (hook first leaves two
results on the one action, stream first one), then shows the re-run's output in the real packet and the repeat dropped as already supplied, and kept when the selection
sends no excerpt. `tests/integration/application/test_observed_rerun_supply.py` runs two real checks
around an already-normalized observed re-run whose output the packet does not carry.
`tests/integration/application/test_status_operation_view.py` covers the recovery page.
