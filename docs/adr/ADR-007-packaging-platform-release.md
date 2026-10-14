# ADR-007 — Packaging, platforms, and release policy

**Status:** Implementation lock (2026-07-17). Release ratification still requires clean-VM
install/upgrade/uninstall evidence from built artifacts and the E-001 release refresh.
**Implemented by:** repository build metadata, `src/yoetz/version.py`, packaged resource
manifests, the packaging/capability suites, and the release workflows under `.github/workflows/`.

## Decisions

1. **Interpreter:** one exact CPython line, `>=3.14,<3.15` in metadata, tested/advertised patch
   `3.14.6` (refreshed at release lock). Writes gate on the exact tested
   patch/distribution/OS/ABI allowlist; import/`version`/read-only inspection work on any 3.14.
2. **Project & build tooling:** `uv==0.11.29` for env/lock/run/tool-install/build; build backend
   requirement `uv_build>=0.11.29,<0.12`; prereleases are disallowed; committed `uv.lock`;
   conventional `src/` layout.
3. **CLI framework:** Typer `0.27.0`, `pretty_exceptions_enable=False`; no Click-internal
   coupling. Async bridge: exactly one top-level `anyio.run(...)` per process entry (CLI command,
   MCP bridge, or foreground service); no nested event-loop helpers. Amended by ADR-012: bare
   invocation prints help in every case except the bounded first-run TTY exception on the root
   command only (interactive terminal, setup marker absent), which launches `yoetz setup run`.
4. **Console script:** distribution and executable both `yoetz`
   (`yoetz.cli.app:main`). `python -m yoetz` delegates to the same entry.
5. **Wheel strategy:** yoetz itself is a pure-Python wheel; platform specificity comes from
   the pinned APSW dependency wheels. Advertised platform matrix remains macOS 11.0+ arm64
   (`macosx_11_0_arm64`) and glibc 2.28+ x86-64 (`manylinux_2_28_x86_64`) until exact release
   evidence expands it. ADR-024 adds Windows 11+ x86-64 (`win_amd64`) as a candidate that may be
   advertised only after the complete Windows service transport, peer identity, storage, keyring,
   secret-memory, native-prompt, recovery, clean-install, and cross-platform drill gates pass. A
   portable console unit test is not that proof. No musl, Windows arm64, or macOS x86-64 claims.
   Amendment (2026-09-13, issue #724): the pinned APSW lock also resolves
   `manylinux_2_28_aarch64` wheels, so the package installs on Linux aarch64 (WSL 2 on
   Windows-on-ARM, Graviton, Raspberry Pi, Asahi) without any gate. Such a host is an
   **untested platform cell**, not a supported one: `version --json` adds
   `platform_cell_untested` to `limitations`, `setup status` reports `platform.cell`, and the
   interface's `/doctor` shows the platform line as not proven. The install is neither refused
   nor claimed. Certifying that cell requires a real `ubuntu-24.04-arm` release runner and
   release evidence, at which point the certified-cell table in `yoetz.version` and this list
   change together.
   Primary install:
   `uv tool install --managed-python --python 3.14.6 "yoetz==0.1.0"`.
6. **Keys, AI-powered review readiness, and compatibility extras:** the certified standard install
   includes direct pinned `cryptography` (AES-GCM, RFC 3394 AES Key Wrap, HKDF/HMAC) and `keyring`
   plus the approved secure-backend dependencies for each advertised cell because object/vault
   crypto, the Cryptography Argon2id passphrase KDF, and OS-keyring-first service startup are v0.1
   core behavior. Founder-authorized amendment (2026-07-29): `argon2-cffi`, `httpx`, and `openai`
   are also standard direct dependencies because first run offers both passphrase storage and
   AI-powered review and must not offer a path the installed artifact cannot execute.
   `semantic-openai` and `portable-recovery` remain compatibility extras for existing install
   commands, with the same exact pins; they add no dependency absent from the standard install. A
   malformed or incomplete environment still fails closed rather than downgrading.
7. **Type/lint stack and npm boundary:** Ruff `0.15.22` (format+lint, line length 100), official
   npm Pyright `1.1.411` via a development-only private `package.json`, strict mode. The locked
   contributor/CI toolchain is Node `26.5.0` with npm `12.0.1`; `npm ci --ignore-scripts` followed
   by `npm run typecheck` is the reproducible invocation. Node/npm are not end-user runtime
   requirements. Amended by ADR-012: the npm launcher now exists at `support/npm-launcher/` with
   its own provenance/delegation/upgrade contract — a dependency-free delegator to
   `uvx yoetz==<version>`. Maintainer release decision (2026-08-20, issue #366): v0.1.0 publishes
   that launcher as the public `yoetz` npm package through the protected tagged workflow, after
   PyPI publication and with trusted-publisher provenance plus byte-for-byte download verification.
8. **Release artifacts:** sdist + wheel, SHA-256 checksums, CycloneDX SBOM via `uv export`,
   dependency lock, support matrix, conformance summary, known limitations, changelog, security
   policy. The source publication-boundary scanner admits the reviewed repository-root
   `CLAUDE.md` alias only when its complete bytes are exactly `@AGENTS.md\n`; nested paths,
   different bytes, and every artifact occurrence remain blocked (issue #455). Sigstore signing
   is deferred until a documented verification command exists (a signature without a verifier is
   not a gate).
9. **Install/upgrade/uninstall:** documented and tested: `uv tool install/upgrade/uninstall`, the
   foreground `yoetz service run` entrypoint suitable for a user-selected external
   supervisor, `codex mcp add/remove yoetz`, and data-retention behavior on uninstall. Native
   launchd/systemd-user installer commands are deferred; uninstall never deletes bundles/vault/
   keyring entries. Amended by ADR-012: the `codex mcp get`/`codex mcp add` sequence is also
   available as the preview-gated `yoetz integrate <harness> mcp` commands and the `yoetz setup`
   wizard; the manual commands remain valid and the runbook's preservation rules are unchanged.
   Amended by issue #419: `yoetz integrate <harness> mcp remove` and
   `yoetz integrate codex plugin remove` are the digest-bound inverses for the MCP entry and the
   marketplace/`config.toml`/cache surfaces setup writes; uninstall still never deletes
   bundles/vault/keyring entries, consent records, or the observation store.
10. **Diagnostics:** `yoetz version --json` emits the full `VersionManifest`; startup safety
    validation is mandatory but the public `doctor` command stays v0.2.
11. **Public schema hosting without runtime coupling:** the checked-in `schemas/` tree is mounted
    byte-for-byte at `https://schemas.yoetz.dev/0.1/`; each `$id` is the direct URL formed by
    appending its exact relative file path. Released versioned schema paths are immutable. The
    manifest advances atomically with digest/ETag binding. The release comparison permits new
    manifest members while requiring every previous member to remain identical; released schema,
    migration, and canonical-vector files remain byte-immutable (release #702). PR/release gates resolve all refs from
    the local manifest with network denied, and installed Yoetz always uses packaged mirrors;
    hosted availability is independently verified release evidence, never an operational
    dependency.

## Amendment — package update and compatible data upgrade (2026-09-12)

Package replacement and data migration are separate lifecycle stages. The supported `uv tool`
carrier uses the guarded package action from `yoetz upgrade --accept` (the 2026-09-24
amendment below removed the `--writers-stopped` attestation); the command refuses source checkouts,
pinned test instances, and isolated runtimes. Other carriers follow their own package procedure. A
successful carrier command is therefore not a host, service, or data-upgrade result.

When the new package's service starts (after quiescence here; on reopen under the 2026-09-24
amendment), the fresh service generation runs the storage-owned
`BundleUpgradeCoordinator.run_before_ready` phase after catalog migration and before publishing
READY. It uses the existing catalog `maintenance_operations` row (`kind = 'migration'`,
`requested_target_version = '13'`) to resume one `package_upgrade_migration` operation, creates a
verified machine-bound backup before applying bundle migration `0013` from schema 12 to 13, and
reopens the bundle through the normal writer before projection replay verification. Existing task
bundles, settings, permissions, host routes/integrations, consent, event history, objects, and
frontiers are carried forward. A response loss or service restart reuses the recorded operation and
backup identity; an unsupported or ambiguous path fails closed and keeps the installation out of
READY until the documented recovery procedure succeeds.

Host refresh, plugin activation, reload, and fresh-session checks remain separate proof facets. An
upgrade does not select new hosts, roots, ownership, observation profiles, privacy recipes,
providers, or Expanded review. Release acceptance still requires artifact-bound package evidence,
the controlled startup migration result where applicable, and independent per-host activation and
runtime evidence.

## Amendment — retained release runtimes, switch on reopen (2026-09-24, #820)

The maintainer explicitly expanded #820/#822 to isolate running releases after review reproduced
that eager imports still read replacement resources from disk. This supersedes the original
no-side-by-side-runtime non-goal and the quiescence requirement for upgrades starting at 0.3.0.

1. **Running processes retain their release.** Before an installed MCP bridge, service, stateful
   hook or upgrade command loads its command graph, the console/module entrypoint copies its virtual
   environment's code, dependencies, resources and instance pin into an
   owner-private sibling generation. Files are independent copies, never hardlinks into uv's
   cache. Completed payloads are read-only. Installed RECORD contents, `pyvenv.cfg` and any pin
   select the generation; package version alone never aliases different artifacts. A fixed
   `-I` bootstrap re-execs its interpreter and retains the original invocation for host binding.
   Python links point directly to the existing base interpreter, preserving its dynamic-library
   loading rules; its standard library remains at the `pyvenv.cfg` location. The supported package
   action does not replace that base interpreter installation. Removing/upgrading the base Python
   itself while processes run is outside this package-update contract.
2. **Partial copies never serve.** The manager's owner-only lock serializes generation creation,
   supported package replacement and pruning. A marked copy abandoned by a crashed constructor
   is reclaimed under that lock; unrecognized directories are preserved. A copy is renamed into
   place only after comparing
   source file identity/size/mtime and installed RECORDs before and after copying. External
   package symlinks and editable/path-linked dependencies are refused. No environment variable
   selects a runtime or bypasses validation. Source checkouts remain development runtimes and
   cannot execute the installed upgrade. The stateless startup-context cue retains its independent
   fast path and bounded missing-resource fallback; it makes no readiness or access decision.
   Failed serving startup is explicit, including on stateful hooks; it does not manufacture an
   allow decision or a successful observation.
3. **State and host identity stay put.** Only runtime files are copied, never settings, consent,
   catalog, ledgers, objects or vault contents. An instance pin is preserved byte-for-byte, so
   dropping an environment variable cannot reach the ambient installation. Host registrations
   keep their existing absolute launcher. The retained service spawns through its retained
   interpreter, and a process lease travels across the initial exec without a pruning gap.
4. **The next session switches.** A fresh MCP bridge retires a stamped older package's service,
   including a protocol-compatible one, through the existing bounded shutdown and restart path.
   A bridge from an older release never signals a newer holder. Explicit `yoetz service restart`
   retains rollback authority. An absent/unparseable version retains the prior bounded identity
   rules. Hooks and ordinary CLI connections never supersede an existing service. Reopening a
   host can interrupt an older session if the new service is incompatible; the old bridge then
   asks to reopen, never to replace its newer successor.
5. **Package success is observed.** `yoetz upgrade --accept` uses `uv tool install --upgrade`
   with a Yoetz requirement bounded below by the invoking version. This replaces an old exact
   version pin without permitting a downgrade and retains supported compatibility extras and
   the recorded Python selection.
   Custom uv resolution options, additional requirements, non-registry sources, source checkouts
   and isolated/pinned instances are refused instead of silently losing their configuration.
   The fresh original launcher must report its version after the carrier exits. An unchanged
   version is reported as unchanged; timeout or unreadable output is not upgrade success.
   `--writers-stopped` remains accepted and ignored for compatibility.
6. **Cleanup cannot stop work.** Every serving generation holds a shared process lease. New
   starts reclaim unused older copies under the manager lock; `yoetz upgrade --prune-runtimes`
   explicitly removes unused completed copies and reports how many remain in use. It never
   signals a process, follows a linked generation, or removes an unrecognized directory.
7. **Coexistence remains a release obligation.** Later releases must keep shared local state
   readable and degrade-safe for still-running earlier writers, or ship a specific guarded
   transition. Retaining runtime bytes is not storage-format compatibility. Upgrading from
   0.2.x still follows its shipped quiesced procedure once because `/10` writers cannot share
   `/11` observation-local state. Compatible task migrations remain backup-first before READY.

Verification includes real installed MCP processes across a local wheel replacement, resource
identity, preserved instance binding, active-generation cleanup refusal, and real-daemon switching
and downgrade prevention. It does not certify native Codex/Claude/Cursor sessions or every future
release's storage coexistence. Package, service, migration and host activation remain separate
reported facts.

## Amendment — "writable by another account", not a mode bit (2026-10-14, owner decision)

The owner explicitly requested this fix after a Linux compatibility run (release/packaging design
gate acknowledged). Since the 2026-09-24 amendment, every installed service, MCP bridge and hook
refused a runtime with any group-write bit (`release_runtime_unsafe`, shown only as "could not be
verified"). Ubuntu, Debian, Fedora and RHEL give normal accounts umask 0002 with a user-private
group (`USERGROUPS_ENAB yes`), so `uv tool install` there makes every runtime file and uv's
managed interpreter group-writable by a group of one, and Yoetz never started. The same mode-only
rule refused such users' repositories (`unsafe_root`), workspace locators, Codex launchers and
host configuration roots (`target_unsafe`).

1. **One rule.** An object is unsafe when an account other than its owner can write it. World
   write always qualifies. Group write qualifies unless the group is the owner's user-private
   group: the owner's primary group, named like the owner, with no supplementary member other
   than the owner and no other account using it as its primary group. Completeness must be
   provable, so the answer is read from `/etc/passwd` and `/etc/group` themselves (and
   `/etc/gshadow` when readable), and only when `/etc/nsswitch.conf` serves `passwd`, `group`
   (and `initgroups` when named) exclusively from `files` and `systemd`, with no userdb service
   beyond dynamic users and no userdb drop-in record. `nsswitch.conf` is read with glibc's
   syntax (lines end at LF only, so vertical tab and form feed are whitespace; the name ends at
   a colon or whitespace and the whole run of both is the separator; `[STATUS=ACTION]` clauses
   must use glibc's words), and every entry for those databases must be local, because glibc
   before 2.33 honours the first duplicate and later releases the last; a malformed entry for
   them makes the answer unprovable. A directory service (SSSD, LDAP, NIS, winbind) may not enumerate accounts and may report a populated group as empty, so on such a
   machine, on macOS (no `nsswitch.conf`) and with any NIS compat line, duplicate gid, name
   mismatch or unreadable file, group write counts as shared: those users install with
   `umask 022` or run the printed `chmod`. `/etc/gshadow` is unreadable to ordinary accounts; the
   account tools keep its member list in step with `/etc/group`, and a group password set with
   `gpasswd` is outside the rule. Answers are cached for five seconds so a long-lived service
   notices membership changes. `yoetz.config.foreign_write`
   owns the rule; every former `mode & 0o022` owner-write check uses it (release runtime, runtime
   pin, workspace binding, structural and check-time Git capture, Codex launcher, and the Codex,
   Claude Code, Cursor and portable plugin targets). Owner-only `0o077` checks on material Yoetz
   creates itself are unchanged.
2. **The runtime check covers what it follows.** The retained-runtime walk also checks the
   environment prefix itself and, for a `bin/python` link, the resolved interpreter, its
   directory and that directory's parent. Because a generation links that interpreter rather than
   copying it, the interpreter check is repeated every time an existing generation is reused and
   when a process inside a generation starts (a later group change or modification is refused
   then, not only at creation). A refusal is `release_runtime_group_writable` or
   `release_runtime_world_writable`, never the generic message. Terminal commands (`service
   run`, `mcp serve`, `upgrade`) print the exact repair, `chmod -R go-w <environment>
   <interpreter tree when owned by this account>`, and suggest `umask 022` before reinstalling.
   Hooks keep the existing non-blocking exit 20 with no stdout decision and print the token
   without local paths. A spawned `service run` records the token as its startup failure, so
   the command that started it names it; every CLI `service_unavailable` and `setup` probe the
   installed runtime read-only and print the same refusal instead of a supervisor hint. `setup run` refuses to connect any host to such a runtime (reason = the token, next step = the repair);
   its status view and disconnect stay available.
3. **Our own installs are owner-only.** `yoetz upgrade --accept` runs `uv tool install` under
   umask 022, the npm launcher installs under umask 022, and the test-instance provisioner runs
   uv under umask 022 and clears group/other write on the runtime it created (uv can hard-link
   files from a cache written under a looser umask). A runtime already shared through a group is
   refused rather than silently tightened: tightening cannot undo a write another account made.

Verification: unit tests with synthetic account databases (private group accepted; supplementary
member, foreign primary, differently named group, unknown or unenumerable databases refused) and
per-site umask 0002 tests; a real Ubuntu 24.04 normal account with umask 0002 ran `uv tool
install`, `service run`, `mcp serve`, Codex/Claude Code/Cursor hooks, `state capture` and the
three host setup previews; adding a second account to the runtime's group produced
`release_runtime_group_writable` on each surface until the printed `chmod` was run.

## Amendment — retained generations carry their bytecode (2026-10-14, owner request)

A Linux/WSL compatibility run found every sealed generation without bytecode (0 of 384 `yoetz`
modules), so every serving start compiled the whole package and, the tree being read-only, could
never cache it: importing `yoetz.cli.app` took 11.7-12.0 s on a nested WSL 2 guest against
6.1-6.6 s from the ordinary environment (macOS 0.85-0.96 s against 0.50 s). Clients then missed
the five-second handshake and services the restart budget.

1. **Sealed with bytecode.** Before sealing, every copied module gets an unchecked-hash pyc in
   `__pycache__` at optimization level 0 (what the `-I` bootstrap loads; never
   `sys.pycache_prefix`). Unchecked hashes never consult the source mtimes the copy does not
   keep, and an immutable generation cannot make them stale. Hash-based bytecode the
   installation already holds (checked or unchecked) is reused when its embedded source hash
   matches the copied source and no other account can write it or its directory; only the flags
   are rewritten. Timestamp bytecode is never reused: its header proves only a whole-second mtime
   and a size, which an edit within the same second at equal length keeps, so reusing it could
   seal stale code. Anything else is compiled with the generation's own file names. A module this interpreter cannot compile still
   compiles at import. Pycs are sealed `0400` in `0500` directories like every other member.
2. **Older generations are not reused.** The generation key includes a layout version, so a
   generation sealed before this change never satisfies a newer start; the next start builds a
   complete one and the ordinary lease-aware pruning removes the old one once unused.
3. **Installs compile.** The documented install, `npx yoetz`, `yoetz upgrade --accept` and the
   test-instance provisioner pass `--compile-bytecode`. uv writes timestamp bytecode by default
   (hash-based only under `SOURCE_DATE_EPOCH`), which item 1 does not reuse, so creating a
   generation compiles the package once per release (macOS: about 7.8 s; 3.1 s when hash-based
   bytecode is reused); serving starts then load the sealed bytecode. uv records that flag as the receipt option `compile-bytecode`; the upgrade accepts
   exactly that option and still refuses any other recorded option.
4. **A slow start is named.** When on-demand start ends its budget while the service it spawned
   (or a live singleton holder) is still starting, the error carries phase `handshake_timeout`
   and is rendered as `service_handshake_timeout` (retry; no lifecycle command) on the CLI and
   in MCP (`safe_details.phase`). A CLI command that finds nothing accepting while a live process
   has stamped the singleton says the same instead of the supervisor hint. Budgets are
   unchanged: hook auto-attach keeps its one-second fail-open budget and on-demand start its 30
   seconds; with bytecode, a generation starts as fast as the ordinary environment.

## Implementation-lock identities

The 2026-07-17 implementation lock freezes the direct dependency declarations below. All are
exact pins except the intentionally bounded build-backend requirement. The generated locks also
freeze every transitive distribution, source, artifact hash, marker, and license.

- Runtime: `anyio==4.14.2`, `apsw==3.53.3.1`, `argon2-cffi==25.1.0`,
  `cryptography==50.0.0`, `httpx==0.28.1`, `jsonschema==4.26.0`, `keyring==25.7.0`,
  `mcp==1.28.1`, `openai==2.46.0`, `platformdirs==4.10.0`, `pydantic==2.13.4`,
  `textual==8.2.8`, and `typer==0.27.0`.
- Compatibility extras: `semantic-openai` repeats `httpx==0.28.1` and `openai==2.46.0`;
  `portable-recovery` repeats `argon2-cffi==25.1.0`.
- Development/test: `hypothesis==6.156.6`, `pytest==9.1.1`,
  `pytest-timeout==2.4.0`, and `ruff==0.15.22`; Pyright remains npm-owned as above.
- Runtime candidate: CPython `3.14.6`, APSW `3.53.3.1`, and SQLite `3.53.3` with exact source ID
  `2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62`.

These identities select what implementation and capability testing exercise; they do not create
a supported runtime cell. Only passing, artifact-bound release evidence may populate
`runtime-support.json`.

## Consequences

Every dependency update is a reviewed PR + package patch release rerunning contract/storage/
packaging/capability matrices. E-001 refreshes these implementation pins at release lock and must
record whether each selected identity stayed fixed or changed; a newer version alone never widens
the support allowlist.

**Amendment (ADR-023, 2026-08-21, issue #149): generated Agent Plugins artifacts and vendored
upstream schema bytes.** Portable plugin artifacts are generated projections of the neutral
`PortablePluginPlan` and follow the same parity rules as every packaged resource: rendered only
from packaged bytes, committed mirrors regenerated exclusively by their owning scripts
(`scripts/sync_resource_ripple.py` and the committed-tree regeneration it drives), never
hand-edited, and covered by the packaging suites before any install-parity claim. The Agent
Plugins 1.0.0 schemas must be vendored byte-pinned by #150 with the SHA-256 digests recorded in
ADR-023 decision 3 and then treated exactly like decision 11 mirrors: the packaged copy is the
runtime authority and upstream hosting is never an operational dependency. Marketplace
publication of the portable artifact is deferred and requires its own separate, dated release
decision like the 2026-08-20 npm decision above; rendering an artifact locally creates no
publication claim.

**Issue #150 implementation detail.** The first portable projection's exact members are
`plugin.json`, `skills/yoetz/SKILL.md`, and the five canonical guidance references; `mcp.json` and
the Codex-specific skill manifest are absent. The Agent Plugins `plugin.schema.json` and
`mcp.schema.json` bytes are vendored under `support/agent-plugins/1.0.0/` at the ADR-023 digests,
and the neutral skill wrapper is owned at `skills/portable/yoetz/SKILL.md`. All three enter the
reviewed resource inventory and wheel/sdist through `sync_resource_ripple.py`. Runtime rendering
uses only those packaged bytes, so clean-install rendering and installed guidance parity are
covered by the packaging gates without an upstream fetch.

**Claude Code native amendment (2026-08-27, issue #154).** Claude Code is a native dual target,
not an Agent Plugins consumer. The generated project-marketplace source contains exactly a strict
`.claude-plugin/marketplace.json`, `plugins/yoetz/.claude-plugin/plugin.json`, the shared skill and
five byte-identical references, the exact tested hook file, and optional plugin-owned `.mcp.json`.
Claude Code `2.1.241` copies the plugin into
`<CLAUDE_CONFIG_DIR>/plugins/cache/yoetz-local/yoetz/<manifest-version>`; Yoetz records the source,
render, marketplace, installed-cache, and executable digests separately. An unchanged manifest
version cannot be used to claim updated active bytes. Update success proves new cache bytes only;
reload/new-session activation is a separate proof facet.

The initial cell is local Claude Code CLI, project scope, and an explicit private directory
marketplace only. It admits only exactly proven Claude versions (currently `2.1.241`; the
`2.1.233` floor marks where default-disabled install, qualified uninstall, and complete-directory
validation behavior first exist, but a version above it is still refused until its native contract
is proven), uses Claude's project
install/update/enable/disable/uninstall commands, and verifies each outcome by list/settings/cache
read-back. Uninstall is qualified as `yoetz@yoetz-local`, uses `--scope project --keep-data`, and
removes the private marketplace source only after exact managed-marker validation. Claude plugin
data, Yoetz ledgers, vault/keyring/provider configuration, privacy receipts, credentials, foreign
marketplaces, other scopes, modified sources, and orphaned caches are never inferred to be safe to
delete. Public marketplace publication remains a separate release decision.
