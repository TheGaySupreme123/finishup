# ADR-007 — Packaging, platforms, and release policy

**Status:** Implementation lock (2026-07-17). Release ratification still requires clean-VM
install/upgrade/uninstall evidence from built artifacts and the E-001 release refresh.
**Implemented by:** repository build metadata, `src/finishup/version.py`, packaged resource
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
   command only (interactive terminal, setup marker absent), which launches `finishup setup run`.
4. **Console script:** distribution and executable both `finishup`
   (`finishup.cli.app:main`). `python -m finishup` delegates to the same entry.
5. **Wheel strategy:** finishup itself is a pure-Python wheel; platform specificity comes from
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
   release evidence, at which point the certified-cell table in `finishup.version` and this list
   change together.
   Primary install:
   `uv tool install --managed-python --python 3.14.6 "finishup==0.1.0"`.
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
   `uvx finishup==<version>`. Maintainer release decision (2026-08-20, issue #366): v0.1.0 publishes
   that launcher as the public `finishup` npm package through the protected tagged workflow, after
   PyPI publication and with trusted-publisher provenance plus byte-for-byte download verification.
8. **Release artifacts:** sdist + wheel, SHA-256 checksums, CycloneDX SBOM via `uv export`,
   dependency lock, support matrix, conformance summary, known limitations, changelog, security
   policy. The source publication-boundary scanner admits the reviewed repository-root
   `CLAUDE.md` alias only when its complete bytes are exactly `@AGENTS.md\n`; nested paths,
   different bytes, and every artifact occurrence remain blocked (issue #455). Sigstore signing
   is deferred until a documented verification command exists (a signature without a verifier is
   not a gate).
9. **Install/upgrade/uninstall:** documented and tested: `uv tool install/upgrade/uninstall`, the
   foreground `finishup service run` entrypoint suitable for a user-selected external
   supervisor, `codex mcp add/remove finishup`, and data-retention behavior on uninstall. Native
   launchd/systemd-user installer commands are deferred; uninstall never deletes bundles/vault/
   keyring entries. Amended by ADR-012: the `codex mcp get`/`codex mcp add` sequence is also
   available as the preview-gated `finishup integrate <harness> mcp` commands and the `finishup setup`
   wizard; the manual commands remain valid and the runbook's preservation rules are unchanged.
   Amended by issue #419: `finishup integrate <harness> mcp remove` and
   `finishup integrate codex plugin remove` are the digest-bound inverses for the MCP entry and the
   marketplace/`config.toml`/cache surfaces setup writes; uninstall still never deletes
   bundles/vault/keyring entries, consent records, or the observation store.
10. **Diagnostics:** `finishup version --json` emits the full `VersionManifest`; startup safety
    validation is mandatory but the public `doctor` command stays v0.2.
11. **Public schema hosting without runtime coupling:** the checked-in `schemas/` tree is mounted
    byte-for-byte at `https://schemas.yoetz.dev/0.1/`; each `$id` is the direct URL formed by
    appending its exact relative file path. Released versioned schema paths are immutable. The
    manifest advances atomically with digest/ETag binding. The release comparison permits new
    manifest members while requiring every previous member to remain identical; released schema,
    migration, and canonical-vector files remain byte-immutable (release #702). PR/release gates resolve all refs from
    the local manifest with network denied, and installed FinishUP always uses packaged mirrors;
    hosted availability is independently verified release evidence, never an operational
    dependency.

## Amendment — package update and compatible data upgrade (2026-09-12)

Package replacement and data migration are separate lifecycle stages. The supported `uv tool`
carrier uses the guarded package action from `finishup upgrade --accept` (the 2026-09-24
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
   A bridge from an older release never signals a newer holder. Explicit `finishup service restart`
   retains rollback authority. An absent/unparseable version retains the prior bounded identity
   rules. Hooks and ordinary CLI connections never supersede an existing service. Reopening a
   host can interrupt an older session if the new service is incompatible; the old bridge then
   asks to reopen, never to replace its newer successor.
5. **Package success is observed.** `finishup upgrade --accept` uses `uv tool install --upgrade`
   with a FinishUP requirement bounded below by the invoking version. This replaces an old exact
   version pin without permitting a downgrade and retains supported compatibility extras and
   the recorded Python selection.
   Custom uv resolution options, additional requirements, non-registry sources, source checkouts
   and isolated/pinned instances are refused instead of silently losing their configuration.
   The fresh original launcher must report its version after the carrier exits. An unchanged
   version is reported as unchanged; timeout or unreadable output is not upgrade success.
   `--writers-stopped` remains accepted and ignored for compatibility.
6. **Cleanup cannot stop work.** Every serving generation holds a shared process lease. New
   starts reclaim unused older copies under the manager lock; `finishup upgrade --prune-runtimes`
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
`plugin.json`, `skills/finishup/SKILL.md`, and the five canonical guidance references; `mcp.json` and
the Codex-specific skill manifest are absent. The Agent Plugins `plugin.schema.json` and
`mcp.schema.json` bytes are vendored under `support/agent-plugins/1.0.0/` at the ADR-023 digests,
and the neutral skill wrapper is owned at `skills/portable/finishup/SKILL.md`. All three enter the
reviewed resource inventory and wheel/sdist through `sync_resource_ripple.py`. Runtime rendering
uses only those packaged bytes, so clean-install rendering and installed guidance parity are
covered by the packaging gates without an upstream fetch.

**Claude Code native amendment (2026-08-27, issue #154).** Claude Code is a native dual target,
not an Agent Plugins consumer. The generated project-marketplace source contains exactly a strict
`.claude-plugin/marketplace.json`, `plugins/finishup/.claude-plugin/plugin.json`, the shared skill and
five byte-identical references, the exact tested hook file, and optional plugin-owned `.mcp.json`.
Claude Code `2.1.241` copies the plugin into
`<CLAUDE_CONFIG_DIR>/plugins/cache/finishup-local/finishup/<manifest-version>`; FinishUP records the source,
render, marketplace, installed-cache, and executable digests separately. An unchanged manifest
version cannot be used to claim updated active bytes. Update success proves new cache bytes only;
reload/new-session activation is a separate proof facet.

The initial cell is local Claude Code CLI, project scope, and an explicit private directory
marketplace only. It admits only exactly proven Claude versions (currently `2.1.241`; the
`2.1.233` floor marks where default-disabled install, qualified uninstall, and complete-directory
validation behavior first exist, but a version above it is still refused until its native contract
is proven), uses Claude's project
install/update/enable/disable/uninstall commands, and verifies each outcome by list/settings/cache
read-back. Uninstall is qualified as `finishup@finishup-local`, uses `--scope project --keep-data`, and
removes the private marketplace source only after exact managed-marker validation. Claude plugin
data, FinishUP ledgers, vault/keyring/provider configuration, privacy receipts, credentials, foreign
marketplaces, other scopes, modified sources, and orphaned caches are never inferred to be safe to
delete. Public marketplace publication remains a separate release decision.
