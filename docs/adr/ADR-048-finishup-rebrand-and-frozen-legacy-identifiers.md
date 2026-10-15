# ADR-048 — FinishUP rebrand and frozen legacy identifiers

**Status:** Accepted for [issue #1055](https://github.com/TheGaySupreme123/finishup/issues/1055);
the steps code cannot take (domains, mail, registries, repository rename, live verification) are
tracked in [issue #1056](https://github.com/TheGaySupreme123/finishup/issues/1056). Design gates:
protocol, storage/durability, release/packaging. Maintainer acknowledgement: the owner's final
decisions recorded on #1055 — full backward compatibility for existing installs (PyPI `yoetz`
0.1-0.2.5, the maintainer's live vault, 0.3 development builds); recorded data is never rewritten;
the legacy state folder is adopted in place; a transitional `yoetz` distribution carries the
deprecated `yoetz` command for one release, and on such an install only `yoetz` is on `PATH`; new
output uses the FinishUP spelling except where a released contract or the deprecated-alias install
forces otherwise, and each such exception is labeled `(ADR-048)` in code (§1). This ADR changes
no released schema, migration, canonical fixture or backward-read fixture. It widens unreleased
schema versions in place (consent `7.0.0`, `check-result` `1.3.0`/`1.4.0`, `status-result`
`1.4.0`, `receipt-document` and `receipt-result` `1.3.0`, `read-guidance-request`/`-result`
`1.1.0`). It grants no runtime, credential, disclosure, egress or destructive-action authority.
**Implemented by:** `src/finishup/legacy_names.py` (the shared spellings),
`src/finishup/config/paths.py` (folder selection, both isolation-root names),
`src/finishup/config/env.py` and `src/finishup/config/load.py` (both variable prefixes),
`src/finishup/application/observation_check_policy.py` (both policy directories),
`src/finishup/domain/finishup_tools.py` (tool and skill spellings),
`src/finishup/protocol/guidance_uris.py` and `src/finishup/mcp/resources.py` (guidance schemes),
`src/finishup/kernel/task_facts.py`, `src/finishup/domain/task_statement.py`,
`src/finishup/kernel/test_edit_visibility.py` (agent text markers),
`src/finishup/application/semantic_case.py` (the forged-label fence),
`src/finishup/protocol/consent.py`, `src/finishup/protocol/errors.py`,
`src/finishup/cli/elevated.py` and `src/finishup/service/elevated_bootstrap.py` (consent heads and
pre-rename pending records), `src/finishup/domain/observation_capacity_policy.py` (command heads),
`src/finishup/domain/receipts.py` (`package_name`), `src/finishup/observability/privacy.py`
(diagnostic origins), `src/finishup/adapters/integrations/` (`codex_mcp.py`,
`codex_marketplace.py`, `codex_plugin.py`, `codex_skill.py`, `claude_code_integration.py`,
`cursor_integration.py`, `cursor_project_mcp.py`, `portable_plugin.py`, `host_admission.py`,
`legacy_launchers.py`, `launcher.py`, `codex_launcher.py`), `src/finishup/domain/write_scope.py`,
`src/finishup/cli/entry.py` (the alias notice), `src/finishup/cli/service_installation.py`,
`src/finishup/service/client.py`, `src/finishup/cli/bootstrap.py`, `src/finishup/mcp/server.py` and
`src/finishup/tui/runtime.py` (folder refusals and naming), `src/finishup/cli/host_admission.py`,
`src/finishup/cli/recommend.py`, `src/finishup/cli/codex_connection.py`,
`src/finishup/cli/upgrade.py` and `src/finishup/application/upgrade.py`,
`src/finishup/adapters/package_upgrade.py`, `src/finishup/application/package_update.py`,
`src/finishup/adapters/privacy/update_checks.py`, `scripts/generate_schemas.py`,
`release/transitional-yoetz/`, `scripts/check_transitional_yoetz.py`,
`.github/workflows/release.yml`, `scripts/provision_test_instance.py`,
`scripts/sync_committed_agent_trees.py`.
**Relates to:** ADR-002 (canonical protocol), ADR-003 (storage), ADR-004 (crypto and keys),
ADR-007 (packaging and release), ADR-009 (update-check allowlist), ADR-010 (harness port), ADR-015
(elevated consent), ADR-023 (plugin carriers), ADR-026 and ADR-028 (isolated roots and test
instances).

## Context

The product shipped as **Yoetz** through 0.2.5 and is renamed **FinishUP** from 0.3.0. The name is
not only prose. It is the PyPI and npm distribution, the console script, the platform folder that
holds the vault and the catalog, the `YOETZ_*` environment namespace, the MCP server key in every
host configuration, the plugin and marketplace names, the guidance URI scheme, the agent text
markers in recorded decisions, and a long list of byte strings inside stored and released data.

Three facts bound what a rename may touch:

1. **Released installs keep running their own code.** The released 0.2.1-0.2.5 upgrade command
   runs `uv tool upgrade yoetz`, which retains an exact version pin and does not verify the
   resulting version. It cannot move a `yoetz==0.2.5` tool (including one installed by the npm
   launcher) to FinishUP without an explicit replacement of that requirement. The 0.1.0 release
   has no `upgrade` command. Pre-rename 0.3 development builds instead run
   `uv tool install --upgrade yoetz>=V` and verify `<tool>/bin/yoetz --version`. Released update
   checks poll `https://pypi.org/pypi/yoetz/json`. Hosts connected by those releases run a bare
   `yoetz`, an absolute `.../bin/yoetz`, or `<python> -m yoetz`. None of that shipped code can
   change.
2. **Recorded bytes are evidence.** The ledger hash chain, object envelopes, crypto domain
   separators, keyring entries, SQL schema and recorded events contain the old spelling. Rewriting
   them would break digests, replay and decryption, and would falsify recorded evidence.
3. **The release gate makes released schemas immutable.** `release.yml` refuses any modified,
   deleted or renamed released schema file or manifest member, and each schema's `$id` is part of
   those bytes. ADR-007 names every `$id` an immutable hosted route under
   `https://schemas.yoetz.dev/0.1/`.

## Decision

### 1. Brand spelling

Prose says **FinishUP**. Lowercase identifiers say `finishup` (package, command, MCP server key,
plugin names, `finishup://` guidance scheme, `.finishup/` repository directory), environment
variables say `FINISHUP_*`, and Python classes say `FinishUp` (never `FinishUP` or `Finishup` in
an identifier). Every surface that writes new output writes these spellings: CLI and MCP text,
receipts, host artifacts, continuations, guidance and docs. The shared spellings, current and
legacy, live in `finishup.legacy_names`.

**Deprecated-alias exception.** An install upgraded through the transitional `yoetz` distribution
(§4) links only the `yoetz` script onto `PATH`; its `finishup` script stays inside the tool
environment. Where FinishUP prints a command the user or agent is expected to run, and that command
would not exist on such an install, it names `yoetz` instead, for this release only:

- the consent `review_command`, `authorize_command` and catalog prepare hints of `consent
  prepare|status|catalog` run through the alias (consent `/7` admits either head; §3 *Command
  heads*);
- the package-update advisory and its tips (`yoetz upgrade`), `recommend accept package-update`,
  the terminal interface's doctor remediation (`# then re-run yoetz`), and the commands of the
  upgrade plan run through the alias, which ends with the move to `finishup` (§4).

Everything else, including the danger text a new consent records, names `finishup`. Until the user
moves, any `finishup ...` command FinishUP shows can be run as `yoetz ...` with the same subcommand;
the update tips, the upgrade plan, `guidance/workflow.md`, `guidance/consent.md` and the
transitional READMEs say so.

### 2. Frozen legacy identifiers

These stay spelled `yoetz` for as long as protocol `0.1` is the wire namespace. Each kept literal
in code is labeled `# Frozen legacy identifier (ADR-048): <why>`.

| Family | Examples | Why it cannot change |
|---|---|---|
| Ledger protocol tags | `"protocol": "yoetz"`, `yoetz.event`, projection `yoetz/0.1.0` | In the entry-digest preimage of the hash chain, in request and materialize identities that retries replay, and in a SQL `CHECK`. |
| Object and vault formats | `yoetz-object/1`, `application/vnd.yoetz.*+json`, `yoetz-vault-root/1` and the other `yoetz-<format>/1` tags, `vault-root-state.yzr`, frame magics `YZO1`/`YZV1`/`YZH1`/`YZS1`, SQLite `application_id` `0x594F4554` | Stored in object headers, AEAD-bound headers, vault and recovery files (including exported `.yir` sets kept offline), and compared on every open. |
| Crypto domain separators | `yoetz/<name>/v<n>` (HKDF, HMAC, AAD and digest domains), `hmac-sha256/yoetz-privacy-egress-request-v1`, `yoetz-semantic-case-1.0.0` | Changing a separator changes every derived key and digest. |
| Keyring service names | `yoetz.vault-root.v1`, `yoetz.auto-unlock.v1` | Name existing OS keyring entries. The auto-unlock account is a digest of the absolute bundle path, which is why the legacy folder is adopted in place (§3). |
| SQL schema | `migrations/` (every byte), `yoetz_session_id`, `yoetz_task_id`, `yoetz_writer_id` | Applied migrations are skipped by `user_version`; an edit makes fresh and upgraded installs diverge. |
| Wire enum values | `yoetz_engine`, `yoetz_cli`, `yoetz_owned`, `yoetz_runtime`, `yoetz_own_call`, `yoetz_process_state`, `yoetz_limit_*`, the `owner` value `yoetz` in check inspection | Values in released and recorded schemas and in events the kernel re-parses. Only Python member names change (for example `McpRegistrationState.FINISHUP_OWNED = "yoetz_owned"`). |
| Schema and record tags | the whole `yoetz.<name>/<n>` namespace (`yoetz.semantic-case/2`, `yoetz.consent.pending-agent/7`, `yoetz.isolation-report/1`, every `*-install/N` marker schema, ...) | Persisted, digested or wire-pinned; protocol 0.1 keeps one tag namespace. Repository- and CI-only tags may move in lockstep. |
| Actor ids | `yoetz:observation-coordinator`, `yoetz:approved-check-service`, `yoetz:tui`, `yoetz:codex-hooks`, `yoetz:<harness>-observe` | Enter recorded event authors and request bodies; a rename would mix ids within one ledger and could turn an in-flight retry into an idempotency conflict. |
| Released schemas | the 154 schema files released at v0.2.5, including their `Yoetz ...` titles and `$id`s under `https://schemas.yoetz.dev/0.1/`; the `yoetz.schema-manifest/1.0.0` tag; the `yoetz-config` family and its `YoetzConfig` owning model | Byte-immutable under the release gate. `yoetz.dev` must stay registered and keep serving `/0.1/`. |
| Marker and residue file names | `.yoetz-plugin-install.json`, `.yoetz-install.json`, `.yoetz-claude-marketplace-install.json`, `.yoetz-cursor-plugin-install.json`, `.yoetz-marketplace-activation.lock`, marker keys `yoetz_version`/`yoetz_launcher`, crash-residue prefixes `.yoetz.stage-` and friends, `yoetz-instance-pin.json`, `yoetz-release-runtime.json` | Status, removal and recovery find ownership through these exact names, in legacy and renamed directories alike; older runtimes and retained release snapshots read the same files. |
| Other stored strings | `[withheld-by-yoetz:possible-credential]`, the spool key `_yoetz_spool_id`, the capture headers `# yoetz edit outcome:`/`# yoetz edit source:`, the nested-cell mark `yoetz`, the `format = "yoetz.approved-check-policy/1"` line in `checks.toml` | Written into stored content or user files and recognized again later. |
| Released consts | consent `pending-agent`/`status` 2.0.0-6.0.0 command head `yoetz`, `check-result` 1.0.0-1.2.0 continuation head `yoetz`, `receipt-document` 1.0.0-1.2.0 and `version-manifest` up to 2.2.4 `package_name` `yoetz`, `read-guidance-*` 1.0.0 `yoetz://` | Released at v0.2.5. The unreleased successors are widened in place (§3). |

Recorded fixtures and evidence (`fixtures/canonical/`, `fixtures/backward-read/`, digested replay,
adversarial, receipt and privacy envelopes, recorded live-host evidence, `tests/fixtures/tb4_replay/`)
keep their bytes; FinishUP-spelled variants are added beside them, never in place.

### 3. Names recognized under both spellings

Readers accept the legacy spelling alongside the new one; writers emit only the new one. Where
both are present and disagree, FinishUP fails closed rather than choosing.

MCP deadline variables are checked in the bridge before service discovery or invocation, including
closure preparation's status reads and the recovery read for an invalid real publication. A
conflict between the two spellings raises `ConfigError("config_env_conflict")` locally and returns
`INVALID_REQUEST` with `config_correction_required`; it never falls back to a default or an
all-tools override. A per-tool override cannot hide conflicting all-tools spellings, including
for a writing `check`, whose numeric deadline still ignores the all-tools value. Unparsable
numeric values retain their existing default behavior.

| Surface | New | Legacy still read | Precedence and conflicts | Lifetime |
|---|---|---|---|---|
| Platform folders | `finishup` | `yoetz` | One name is chosen for all ambient roots (data, config, state, cache, logs, runtime). A legacy installation anchor (`data/catalog.sqlite3`, `data/vault`, `config/config.toml` or `state/service.lock`) with no FinishUP anchor selects the legacy folders **in place**: nothing is moved, copied or linked. A FinishUP anchor, or none, selects `finishup`. Anchors under both names fail closed with `PathSafetyError("installation_root_ambiguous")` (exit 20, `local_state_repair`), and a lone settings file counts: the remedy keeps the folders that hold the vault and catalog where they are and moves a lone `config.toml` under the other name into those folders; when both names hold a vault or catalog, it says to keep the installation in use and move the other name's folders aside without deleting them, and a leftover `service.lock` from a stopped older service is moved aside the same way. An anchor that cannot be examined counts as present. The CLI's control-error path (including `service status|restart|stop`), `setup status --next`, MCP (public code `STORAGE_UNSAFE`) and the terminal interface name the token and its remedy rather than an absent service. Plain `setup status` keeps its released 2.0.0 report on stdout (`service.reachable` false), names the refusal on stderr and exits 20; `provider status` exits 20 with the same stderr lines (with `--json`, the `STORAGE_UNSAFE` failure payload on stdout) instead of `internal_error`. Isolated roots never use this choice. `installation_naming()` reports the closed token `finishup` or `legacy_yoetz`; human `service status` prints a keep-these-folders note on stderr for `legacy_yoetz`, and `/doctor` shows an *Installation folders* entry. A Yoetz install that has none of the four anchors (for example only a diagnostic file) is treated as no installation. | Permanent: the vault and keyring binding live there. |
| Environment variables | `FINISHUP_*` | `YOETZ_*` (same suffixes) | The legacy name is read only when the new one is unset. Both set and equal is accepted; both set and different raises `ConfigError("config_env_conflict")` (`safe_name` = the `FINISHUP_` name), or `PathSafetyError("isolation_root_env_conflict")` for the isolated root (`config_correction_required`; no instance needs disposal). `isolation_root_conflict` keeps its ADR-028 meaning: a variable that disagrees with the runtime pin. Unknown and secret-shaped names are refused under both prefixes. Rendered host registrations, hook commands, the detached service and child processes carry **both** isolation-root names with one value, so an older launcher found through `PATH` still isolates (#604). | Permanent reader; dual export while the alias ships. |
| Approved workspace checks | `.finishup/checks.toml` | `.yoetz/checks.toml` | The legacy file is read only when it is the only one. Both present fails every `observe checks` operation with `policy_ambiguous` (exit 20). `observe checks status` reports `policy_file`. Trust binds to the file's raw bytes, so a byte-identical move keeps it trusted. | Permanent. |
| Host registrations | MCP key `finishup`, `finishup-local`, `finishup@finishup`, `.agents/plugins/finishup`, `.agents/skills/finishup`, `plugins/local/finishup` | the same under `yoetz` | Status reports `legacy_registration` (MCP key) and `legacy_installation` (plugin, marketplace or skill tree) as `none`, `legacy_only` (owned but outdated), `duplicate` (owned under both names) or `foreign` (not provably FinishUP's; never touched). Ownership of a legacy entry needs proof: a bare `finishup`/`yoetz` launcher, this runtime's launcher, its `yoetz` alias (proven by the transitional distribution's RECORD; the exact sibling path counts by location only when no `yoetz` distribution is installed or nothing is there), or a launcher recorded in a self-consistent frozen marker. Integrate and the guided connection migrate an owned legacy registration within one reviewed, digest-bound preview; disconnect and remove take owned entries under both names. A migration retires only what belongs to the project being connected: shared legacy state other projects may still load (Claude Code's `yoetz-local` marketplace tree and user-level registration) is kept and reported, and a legacy tree is deleted only when nothing activated still reads it (Codex `.agents/plugins/yoetz`). Every approval surface lists the legacy items its digest removes. Admission grants are written only for `finishup`; exact legacy grant forms are reported, removed by revoke and sweep, and retired by a grant once nothing FinishUP owns uses the old name (an unread fact keeps them; `legacy_grant` reads `unverified`); a grant is refused (`legacy_registration_active`) while the host serves FinishUP only under `yoetz`. With several projects per configuration root (ADR-012, #1058 amendment) a project's own legacy activation (Codex tables, document and cache; Claude Code's project install and declaration) still goes with its disconnect, also a detach, while user-level legacy state other projects may share (the Codex `yoetz` MCP entry, Cursor's `plugins/local/yoetz`) stays with the shared FinishUP pieces until the last disconnect or `--remove-shared`; a disconnect's admission sweep takes exact legacy entries too. Yoetz kept no record of the projects it connected, so Yoetz-era shared pieces found without one (Cursor's owned `plugins/local/yoetz`; a byte-identical Codex `[marketplaces.yoetz]` or `[plugins."yoetz@yoetz"]` table, or a FinishUP-shaped `[mcp_servers.yoetz]` entry) are treated as an earlier release's pieces are (ADR-012): on Cursor, which has no binding naming a project, membership is unknown and the tree stays until `--remove-shared`, even for one project; on Codex they make trusted checkouts serving FinishUP's manifest possible users, and the Codex project an exact `[marketplaces.yoetz]` table names, while it still serves its Yoetz-era marketplace document, is a member of the shared registration, never the FinishUP binding's anchor (with neither, an ordinary disconnect removes the registration). A Codex connect keeps an owned `yoetz` entry beside `finishup`, instead of migrating it, while a project's `.codex/config.toml` still names `mcp_servers.yoetz` without a transport (the table a Yoetz 0.2 admission grant wrote) or cannot be read, or while the home's own config or record cannot be read (every known project is read; no count window). It binds that decision in the registration preview digest (`/6`), names per project what releases it (the revoke only where exact earlier-name approval tables are all that hold it), and always names the explicit way out: the low-level removal under both names, then a connect, with its cost stated. One that would also change the review mode stops first and keeps both modes reachable (#1073). `setup status --host codex` explains a transport-less project table under either key, including the `[mcp_servers.yoetz.tools.check]` a Yoetz 0.2.x disconnect left behind. Per-host detail is in each host runbook's *Legacy Yoetz registrations* section. | Until no legacy registration remains; readers stay. |
| Tool and skill spellings | `mcp__finishup__*`, `mcp__plugin_finishup_finishup__*`, `finishup:*`, `plugin-finishup-finishup:*`, skill `finishup`/`finishup:finishup` | the same with `yoetz` | A legacy spelling counts only beside its own server key; mixed spellings are rejected. Hook matchers cover both, for example `^mcp__(?:finishup\|yoetz)__start$`. | Permanent: recorded observations keep legacy tool names and replay reclassifies them. |
| Guidance URIs | `finishup://guidance/...` | `yoetz://guidance/...`, including four pre-rename title anchors | `read_guidance` and `resources/read` accept the exact catalogued legacy spelling and answer in the caller's scheme; `resources/list` advertises `finishup://` only. | No expiry decided; dropping it needs its own decision. |
| Agent text markers | `finishup-blocker:`, `finishup-assumption:`, `finishup-verification-limit:`, `finishup-no-material-work:`, `finishup:test-change:`, and the Stop-time acceptance attestation (tb4n5). The legacy unflagged re-read still reads `finishup-acceptance:<obligation id>:met`. The flagged rule (#1079) reads `finishup-acceptance:<obligation id>:met:<evd_ or res_ id>` only when that id is an observed verification linked for the obligation (`admissible_verification`: hook-captured or observation-captured evidence, or a result of an observed command; an agent-asserted id does not answer), or `finishup-verification-limit:<obligation id>` | `yoetz-` / `yoetz:` spellings | Both spellings are one marker to every rule; matching stays exact, whole-line and case-sensitive (the acceptance attestation keeps its own anywhere-in-the-final-message rule). Teaching text emits only the new spelling. A `yoetz_availability` delegation block is honored like `finishup_availability`. | **Permanent**: recorded decision statements are re-parsed on every projection rebuild. |
| Review packet labels | `[FinishUP ...` | `[Yoetz ...` | The forged-label fence prefixes an agent line beginning with either name, in any ASCII case, with `(agent text) `. | Permanent. |
| Command heads | `finishup ...` in consent review/authorize commands, continuations, error details and capacity disclosures | `yoetz ...` | Released versions keep `yoetz` (consent `pending-agent/6` is tied to it). `consent prepare` and `status` emit `/7` for every operation with the head of the invoking launcher: `finishup`, or `yoetz` through the deprecated alias (§1). `/7` and the widened unreleased schemas admit `yoetz` from a pre-rename service; one projection never mixes heads (`consent_command_head_mixed`). Continuations, error details and capacity disclosures are always rendered with `finishup`. | Readers permanent. |
| `package_name` | `finishup` in new receipts and version manifests | `yoetz` | Receipts issued before the rename keep `yoetz`, bound by their digest; the unreleased `receipt-document`/`receipt-result` 1.3.0 admit both. | Permanent. |
| Diagnostic origins | `finishup.<module>:<line>` | `yoetz.<module>:<line>` | The durable diagnostics ring re-validates records written before the upgrade. | Permanent. |
| Launchers | `finishup`, `python -m finishup` | `yoetz`, `python -m yoetz` (from the transitional distribution) | See §4. Started through the alias, integrate and setup bind new host artifacts to the `finishup` script installed beside it; `python -m yoetz` binds `python -m finishup`. Every subcommand works under either name. | One release. |
| Test instances | `bin/finishup` | `bin/yoetz` in runtimes built from pre-rename revisions | `scripts/provision_test_instance.py` probes `bin/finishup`, then `bin/yoetz`, and drives that runtime's own package. | While such instances exist. |

### 4. The transitional `yoetz` distribution and the alias window

The `finishup` wheel and npm package declare only the `finishup` command. A separate, deprecated
`yoetz` distribution (`release/transitional-yoetz/`) is published to PyPI and npm at the same
version for **one release**:

- The Python package depends on exactly `finishup==<same version>`, re-exports the same extras,
  declares only the `yoetz` console script, and ships a small `yoetz` import shim for
  `python -m yoetz` and the legacy release-runtime bootstrap. It adds no product code.
- An eligible unpinned 0.2.x `yoetz` uv tool reaches it through its released upgrade command.
  An exact-pinned tool needs the owner's explicit `uv tool install --upgrade 'yoetz>=0.3.0'`,
  preserving its extras, Python request and resolution options; a 0.1.0 install likewise uses
  its package manager. Follow 0.2's stop-first procedure before replacement. The existing
  `yoetz` tool then gains `finishup`, `<tool>/bin/yoetz --version` prints the bare version, and
  hosts registered against that tool keep working. An older command's successful exit alone
  is not evidence that the package changed; the upgrade guide requires a direct version check.
- The npm package installs `yoetz==<version>` as a uv tool, never with `--force`, and runs it.
- An install that came from the transitional distribution polls `https://pypi.org/pypi/yoetz/json`
  (added to the ADR-009 allowlist) and its advisory names `yoetz upgrade` (§1); every other install
  polls `finishup`. Each identity keeps its own cache file in the shared state directory
  (`package-update-cache.json` for `yoetz`, which released Yoetz readers also read, and
  `package-update-cache-finishup.json`), so each keeps its own 24-hour TTL and neither answers for
  the other.
- Started as `yoetz` in an interactive terminal, FinishUP prints one stderr notice: `yoetz` is now
  `finishup`, any `finishup` command also works as `yoetz` with the same subcommand for this
  release, `yoetz upgrade` shows how to move, and the alias goes in a later release; it links the
  upgrade guide. It never prints for `--version`, `--json`, `hooks`, `mcp serve` or `service run`,
  or when stderr is not a terminal. `finishup upgrade` run through the alias plans with `yoetz`
  commands (the tool's `finishup` script is not on `PATH`) and ends with a **Move from the yoetz
  name** step: install `finishup` with the same managed Python as a fresh install
  (`uv tool install --compile-bytecode --managed-python --python 3.14.6 finishup`), carrying over the
  `semantic-openai` and `portable-recovery` extras when the `yoetz` tool's plain uv receipt proves
  them and otherwise asking the user to re-add extras and package options. A uv tool receipt
  (`uv-receipt.toml`) is *plain* when its `[tool]` table records only `requirements`, `python` and
  `entrypoints` (`options`, `constraints`, `overrides` and `build-constraint-dependencies` only when
  empty, except that `options` may record `compile-bytecode`, which the documented install sets;
  any other key disqualifies it), with exactly one requirement for the package carrying only
  a specifier and extras from that set; it is read only as a bounded regular file, never through a
  symlink. `finishup upgrade --accept` applies the same test and refuses a non-plain receipt as
  `refused_custom_uv_installation` rather than dropping the recorded choices; refresh each host; then
  `uv tool uninstall yoetz`. The step also says that every `finishup` command shown works as
  `yoetz` with the same subcommand until then.
- `release.yml` builds the transitional distributions twice, checks them in lockstep
  (`scripts/check_transitional_yoetz.py`), smoke-tests them against the exact `finishup`
  candidate, binds their digests into the same publication approval, publishes them only after
  `finishup` (PyPI, then npm) through Trusted Publishing, and verifies the published bytes. See the
  [transitional distribution runbook](../runbooks/transitional-yoetz-release.md).

**Removal gate.** The alias, the transitional distributions, their release jobs and the launcher
recognition are removed in a later release, and only after status reports no host still bound to a
legacy launcher. After removal, a `yoetz` tool's own `yoetz upgrade` would report itself current
forever, so the release that removes the alias must have status point such installs at the move to
`finishup`. Removing the launcher alias does not remove the permanent readers in §3.

## Consequences

- Existing installs keep their data, keys, settings, host registrations and recorded history
  without a migration step. New installs and new output are FinishUP throughout.
- Under protocol `0.1`, the identifiers in §2 stay spelled `yoetz` forever, including the hosted
  `$id` namespace `https://schemas.yoetz.dev/0.1/`. A future protocol namespace bump is the only
  place they could move; until then `finishup.dev` can at most mirror the `yoetz.dev` schema tree.
- A pending consent prepared before the upgrade stays a valid record: the operations whose danger
  text the rename changed accept exactly their own pre-rename text, still bound by the danger
  digest, and review shows the text the owner was shown (ADR-015 amendment). It expires within the
  15-minute pending TTL as usual. Any other mismatch still reads as `pending_tampered`.
- Deterministic finding wording now names FinishUP. Checkpoints written before the upgrade replay
  as superseded through the existing text-contract digest, not as corrupt; finding ids carry over.
- An adopted Yoetz install keeps living in folders named `yoetz`. Uninstall and data-retention
  guidance names both folder sets; the terminal interface's `/doctor` names which one is in use, and
  `finishup service status` prints a keep-these-folders note on stderr for an adopted install.
- Data under both folder names has no automated resolution: the owner moves one installation aside
  by hand, as the [upgrade guide](../usage/upgrading.md#upgrading-from-yoetz) describes.

## Alternatives rejected

- **A clean break.** Shipped `yoetz upgrade` code would never reach FinishUP, hosts would lose
  their server, and the vault would be orphaned under the old folder.
- **Rewriting or migrating stored data to the new spelling.** It would break hash chains, digests,
  decryption and replay, and would falsify recorded evidence; it also races an older running
  service that still holds the legacy lock.
- **Moving the legacy folder to the new name.** The keyring auto-unlock binding is a digest of the
  absolute path, an older service holds the lock and sockets there, and a move is not atomic
  across six roots.
- **Shipping the `yoetz` alias inside the `finishup` wheel.** A `yoetz` tool environment that also
  exposes `finishup` makes `uv tool install finishup` fail ("Executables already exist"), and a
  `finishup` wheel exposing `yoetz` collides with the existing `yoetz` tool the same way.
- **New schema versions for every widened contract.** The affected versions were not released at
  v0.2.5 (verified against the v0.2.5 manifest), so widening them in place is honest and avoids
  version churn.
- **A second `format` value in `checks.toml`.** It would fork the policy grammar and an older
  service would reject it; only the directory is dual.

## Host and platform decisions

The same on Codex, Claude Code and Cursor on macOS, Linux and WSL 2: each host's legacy
registration is recognized, migrated by integrate or the guided connection under its existing
preview-and-approve shape, reported by status and removed by disconnect. Per-host differences
(Claude Code's MCP configuration is owner-written and only reported; Codex legacy activation is
removed by exact table and cache, not by `codex plugin remove`; Cursor project MCP entries) and the
manual steps for legacy state FinishUP cannot prove are recorded in the host runbooks. Live
verification on a real 0.2.5 install is open on #1056.

## Verification

`tests/unit/config/test_installation_naming.py` and `tests/unit/config/test_legacy_env.py` cover
folder selection, ambiguity and every legacy-only, new-only, equal and conflicting variable case.
`tests/unit/kernel/test_legacy_markers.py` replays legacy markers to identical projections.
`tests/unit/mcp/test_legacy_guidance_uris.py` covers both schemes. The host suites
(`tests/unit/adapters/test_*_legacy.py`, `tests/unit/cli/test_codex_legacy_surfaces.py`,
`tests/unit/application/test_host_connection_legacy.py`, `tests/unit/tui/test_runtime_legacy.py`)
cover legacy states, migration and removal. `tests/unit/cli/test_entry_legacy_alias.py`,
`tests/unit/adapters/test_launcher_legacy_alias.py` and `tests/unit/test_transitional_yoetz.py`
cover the alias and the transitional distributions. `tests/unit/cli/test_folder_refusal_surfaces.py`
and `tests/unit/mcp/test_folder_refusal.py` cover folder refusals on every connect path;
`tests/unit/service/test_elevated_bootstrap.py` and `tests/unit/cli/test_elevated.py` cover
pre-rename pending records and the consent command head;
`tests/conformance/surfaces/test_transitional_launcher_guidance.py` covers the transitional-launcher
guidance. The release-workflow jobs are verified by
inspection and static contract tests only until a dry run (#1056).
