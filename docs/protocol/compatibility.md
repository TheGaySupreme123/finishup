# FinishUP compatibility

"Compatible" is not one number. FinishUP tracks many independent version axes, and a claim on one axis
never implies a claim on another. This page names each axis, its authoritative discovery source,
and the exact rules that govern reading and writing across versions. Successfully importing one
transcript, or one successful `check`, is never grounds for a blanket compatibility claim.

## Independent axes

| Axis | Discovery source |
|---|---|
| Package / commit / release provenance | `version --json` |
| Public protocol version (`PROTOCOL_VERSION = "0.1"`) and per-operation request/result schema version (`1.0.0`) | `version --json`, `schemas/operations/` |
| Local-control hello/setup/proposal versions, including repository-locator and authority-digest support | `version --json`, `schemas/service/`, `schemas/privacy/` |
| Each durable event schema name and registered version | `schemas/events/`, `version --json` |
| Canonical encoding / digest domain version | `docs/adr/ADR-002-canonical-protocol.md`, `fixtures/canonical/` |
| Storage schema and its ordered migration set | `version --json` (catalog 5, bundle 13), `migrations/` |
| Object envelope / encryption / key / recovery artifact formats | `version --json` (object format `yoetz-object/1`) |
| Projection engine/generation and local policy/config digest | `version --json` (projection `yoetz/0.1.0`) |
| Receipt schema and render version | `schemas/receipts/receipt-document-*.schema.json` |
| Installed resource set / skill / reference compatibility | `version --json --resources`, `skills/codex/finishup/manifest.json` |
| CLI contract / MCP SDK / MCP protocol | `version --json` (MCP SDK `mcp==1.28.1`, protocol negotiated against the latest published revision) |
| Codex exact tested executable set and JSONL importer format profiles | `version --json`, `fixtures/imports/codex/` |
| Optional provider adapter / profile / model / SDK | `version --json`, provider capability fixtures |
| Python / OS / CPU / ABI / APSW / SQLite source and build options / filesystem / key backend | `version --json` (Python `>=3.12,<3.15`, certified cell 3.14, APSW `3.53.3.1`, SQLite source ID pinned in ADR-003) |

`version --json`, the installed resource manifest, bundle metadata, and the release
capability/support matrices are the sole authorities. No prose table in this document is itself
normative if it drifts from those sources for an installed release.

## Version rule vocabulary

Every compatibility statement uses exactly one of four states:

- **`supported`** — complete required evidence exists for this exact cell.
- **`readable`** — safe to read or inspect, but no write claim is made.
- **`unsupported`** — known denied or failing for this exact cell.
- **`untested`** — no claim either way. `untested` is never collapsed into `unsupported`, and
  "available" or "installed" is never treated as a compatibility state by itself.

For package/protocol SemVer: a major version change may break readers or writers; a minor version
may add a backward-compatible optional capability, but only when an old reader can safely ignore or
preserve it; a patch version never changes canonical bytes or schema semantics. Actual release
behavior is governed by the exact schema/version manifests shipped with a release, not by SemVer
optimism about a range.

## Reader/writer matrix

- A client sends only operation schema versions the server currently advertises, and strictly
  parses the exact selected result schema — an unknown required field or variant is never silently
  ignored.
- The server may read a retained older event version only when a registered decoder/migration
  fixture exists for it. An unknown event schema is preserved as canonical accepted data and
  surfaced as an explicit coverage gap; it is never mapped to a guessed meaning.
- Writers never append under an unsupported protocol, storage, object, or canonical version.
- A newer, unknown storage schema allows at most tested structural read-only inspection and version
  guidance; every write and migration fails closed (`MIGRATION_REQUIRED` / `STORAGE_UNSAFE`).
- Older local-control hello/setup/proposal decoders remain available only for their frozen shapes.
  An omitted repository locator yields an unbound session, and a policy-digest-only proposal cannot
  create a repository row, consume migration entitlement, or authorize external LLM work under
  repository-grant mode. Compatibility is fail-closed, not an authority downgrade.
- An old package reading a bundle changed by a newer package is supported only when the release
  support matrix says so for that exact pair — installing an old wheel is never rollback.

| Scenario | Outcome |
|---|---|
| Older client / current server | Server rejects an unsupported request schema version (`PROTOCOL_VERSION_UNSUPPORTED`); a supported older request version is served normally. |
| Current client / older server | Client must not send a schema version the server has not advertised as supported. |
| Current package / older bundle | Readable/writable only when the current package's registered migrations cover the bundle's schema version; otherwise migration is required first. |
| Older package / current bundle | Fails closed — an old package is not guaranteed to understand a newer bundle's schema, object format, or canonical rules. |
| Unknown event | Preserved verbatim as canonical data; reported as an explicit projection/coverage gap. |
| Unknown object format/version | Payload access and writes fail closed; no plaintext or empty fallback is substituted. |

## Event/schema evolution

An event family/version pair is immutable after release. Fixing semantics requires a new version;
canonical bytes and digests for the old version remain readable forever. A new optional field is
permitted on an existing version only with an explicit default that does not alter old canonical
bytes; otherwise it requires a new schema version. A new event family requires a coordinated
registry, schema, reducer, unknown-gap handling, fixture, skill, and documentation update — it never
ships as a silent addition.

Consent publishes `catalog`, `pending-agent`, `prepare-result`, `review-result`, and `status` as one
versioned family. Frozen v2-v6 files remain byte-identical and packaged; current runtime projections
emit v7. V6 added the exact repository privacy before/after preview and admitted
`expanded_review`, so older readers never reinterpret that wider enum or silently omit the decision
surface. The durable owner-only pending record similarly moves from v3 to v4 and invalidates a
short-lived older pending action rather than upgrading its authority target. The
`chat-user-attestation` family remains version `1.0.0`; its exact one-use envelope did not change.
A pre-upgrade private review marker is not an unclaimed pending action: it may still have a live
owner, so the new runtime preserves it and blocks replacement instead of deleting it during
upgrade. This is the existing interrupted-review fail-closed boundary, not successful recovery.
V7 adds the exact project coordination grant binding. Its project and membership generation are
part of the reviewed authorization target; decoding an older consent result does not grant that
new capability or change an existing workspace's observation or disclosure permissions.

The declared-completion-scope change is an explicit pre-release 0.1 correction under that optional
field rule. `plan_published` and `plan_revised` remain event schema `1.0.0`, and status remains
request/result schema `1.0.0`. Existing plan events omit `no_obligations_reason` and retain their
byte-identical canonical encoding. Omission means no typed empty-scope declaration; on a revision it
also clears any earlier declaration. A present value is one of the three closed reasons and is
admitted only when the effective current plan has zero obligation refs. Older readers that preserve
the exact event bytes remain safe; no storage migration or reinterpretation of old bytes is needed.
Because `start` reuses the compact projection on attach, its existing `open_obligation_count` also
admits `null` when current plan scope is unreadable; this prevents a redacted plan from being
reported as zero or making the task unattachable. The start result schema remains `1.0.0` under the
same pre-release correction.

The finding-readiness correction is likewise an explicit pre-release 0.1 contract correction.
Start and status result schemas remain `1.0.0`: their former
`unresolved_finding_count` field becomes `unanswered_finding_count`, compact status renames its
preview to `unanswered_findings`, and both compact surfaces add
`receipt_blocking_finding_count`. Status readiness replaces `findings_unresolved` with the distinct
`findings_unanswered` and `receipt_findings_unresolved` conditions. No canonical event byte or
stored response disposition changes, and the internal SQLite projection column retains its
generation-1 name; replay derives both public counts from the existing findings and responses. A
durable pre-correction create result normalizes its receipt-blocking count to zero. A pre-correction
attach result cannot reconstruct responded actionable findings from its old unanswered-only count,
so replay returns `receipt_blocking_finding_count: null` with the explicit
`legacy_receipt_blocking_count_unknown` gap instead of declaring storage corruption or inventing a
value.

Golden vectors are retained for every released version under `fixtures/`. Reducers, checks, and
receipts always name the engine/policy version that produced them and never reinterpret old bytes
under a newer policy silently. Unknown or redacted data always weakens coverage and receipt
wording; it is never treated as equivalent to current, fully observed data.

The evidence read-back change (issue #914) is an in-place edit of the unreleased 0.3 status
request 1.2.0 and status result 1.4.0, which no released tag carries. The evidence filter gains an
optional `author` whose only value is `mine`, and each evidence row gains an optional
`publication_channel`. Both are optional on the wire, so a request or result produced by an earlier
0.3 build still validates; the current service always fills the channel. Control 2.9.0 references
the same two documents and needs no new version. No event bytes, storage, or released schema
change.

## Storage, object and recovery

Storage migrates forward only, through a contiguous, immutable, numbered migration set, under an
exclusive generation and a verified backup taken first. Migration never rewrites canonical event
bytes. There is no automatic downgrade or reverse SQL. For the supported package transition, a
fresh service runs `BundleUpgradeCoordinator.run_before_ready` before publishing READY. It uses
the existing catalog `maintenance_operations` row (`kind = 'migration'`,
`requested_target_version = '13'`) to resume the same `package_upgrade_migration` operation,
creates the machine-bound backup, and applies bundle migration `0013` from schema 12 to 13. A
target that is already current is verified as a no-op; an unsupported, ambiguous, or post-commit
uncertain result keeps READY blocked and requires the explicit recovery procedure. Package
replacement alone is not data-upgrade completion. "Rollback" means restoring a verified
pre-migration backup into a new quarantined target, replaying it, and then performing an atomic
catalog switch — see [`../runbooks/migration-rollback.md`](../runbooks/migration-rollback.md).

Catalog repository-authority migration is narrower than an ordinary policy decision: it preserves
accepted machine-policy bytes and records bounded pre-upgrade route/first-repository entitlements.
Consumption requires a trusted repository locator and atomically inserts the exact child row. It is
idempotent and grants no later repository. An old client or missing locator cannot consume the
entitlement and leaves external LLM work blocked.

An unknown object, recovery, or key format, or a key-slot mismatch, fails payload access or write
outright; there is no plaintext or empty fallback. Machine-bound and portable-recovery backup
compatibility are explicit and separate claims — see
[`../runbooks/backup-restore.md`](../runbooks/backup-restore.md) and
[`../runbooks/key-recovery.md`](../runbooks/key-recovery.md). A portable backup's format version
being current is not by itself proof that its recovery secret or artifact is available.

Projection caches may be discarded and rebuilt whenever a registered projection version supports all
events currently in the ledger; projection compatibility never substitutes for ledger compatibility.
Policy and receipt wording changes are themselves versioned, and an old receipt's JSON remains
addressable by its own schema version.

## N5 intra-version audit (2026-10-14)

The owner's request to keep older versions working acknowledges the storage and packaging audit
gate. This is a bounded commit-pair probe, not a new supported-old-release cell. The old wheel was
built from `0291f441d355ac9b740da3b37efc239337e3011a` in an external scratch clone; the candidate
was `3e37fce639a70d6deb1e883757356a8271ad7b03` on integration base `0a4d4e8b7`, measured as its
installed wheel (SHA-256
`dc742ff57ea138a14c70de1d2fcfe384e3f1de70a8473389869ff0d66792413f`). Both are package version
`0.3.0`, with separate ADR-028 disposable instances.

- The old application wrote a synthetic 13-event SQLite ledger containing a plan, obligation,
  evidence, completion claim, hook observations, check and receipts in all three formats. A
  SQLite backup and synthetic test objects were copied into the candidate's private instance,
  without vault material. The candidate reopened and replayed it, decoded all three historical
  receipt documents and rendered them as markdown and text. Nine status views and new JSON,
  markdown and text receipts preserved `insufficient_coverage`; closure retained the recorded
  `host_outcome_unavailable` and `unpaired_event` limits instead of becoming clean.
- To exercise one endpoint without retargeting either runtime's pin, the old daemon was imported
  from the old installed wheel using the candidate instance's pinned interpreter. Its old schema
  digest was `sha256:2322a2455459c3ca7687efe1c009b5a27c6e3a1e8c619d41adb5195c27073244`. The
  candidate's status refused it as `service_incompatible`; the candidate's absolute launcher
  then ran `service restart`. The old daemon exited 0, the successor stamped the candidate's
  schema digest, and replacement completed in 15.041 seconds. The successor was stopped through
  that same launcher.
- The backward-read/resource-manifest conformance, withdrawn-field decoder and closure-shape
  slices passed 27 tests locally. No additional product incompatibility was found in these
  probes. The earlier decoder repair for the interim
  `undeclared_references_created_in_task: true` shape remains in the candidate.

The synthetic object store does not certify encrypted-vault migration or recovery, host
reactivation, pending consent, provider credentials, or older clients reading new writes. The
service probe used actual old wheel code inside an independent pin, not an in-place package
upgrade or two runtimes pointing at one another's instance. Release support matrices remain the
authority for broader claims.

## External integrations

MCP compatibility names the exact SDK and protocol-revision pair tested against an installed
artifact (`mcp==1.28.1`, protocol negotiated). Codex support is an explicit tested executable set
per platform (target/maximum-tested `0.144.5`) — a version newer than maximum-tested is
`untested`, never inferred `supported`. Skill compatibility combines the skill schema version, the
FinishUP protocol range it declares, and exact-tested Codex evidence; installing the skill files alone
is not itself a support claim. The Codex JSONL importer records exact format observations per
tested profile; unknown lines are quarantined as an explicit import gap, never silently dropped.

Provider compatibility (for example the OpenAI Responses adapter) names an exact
adapter/SDK/endpoint/model profile and is optional and advisory; the strict-local base support
FinishUP ships with is independent of any provider profile. New `codex-chatgpt-subscription@1`
setups suggest `gpt-6.1-sol` with final and routine reasoning `medium` when the adopted Codex
lists it (Codex `0.162.1` does, checked 2026-10-14), and otherwise bind `gpt-6-luna` at `medium`
with a printed reason (released 0.2.x setups suggested `gpt-5.6-luna` at `high`; unreleased 0.3
builds briefly `gpt-6-luna` at `high`); the `0.157.1` floor lists
`gpt-6-luna` but not `gpt-6.1-sol`. Neither suggestion is a live packaged cell: no authenticated
`gpt-6.1-sol` review has run, and the suggestion rewrites neither historical Sol exact-cell
evidence nor existing bindings. The subscription evaluator is not an exact-cell claim: it admits any stable
Codex release at or above `0.157.1` whose retained bytes pass the capability check (reviewed
app-server subset, zero-inference isolation probe, model listed for the dedicated home), newest
first, and records the release, executable digest and capability-record digest as provenance
(ADR-006, 2026-10-13). This does not change the exact-cell rule for the Codex *host* integration
above. Platform support is stated as an exact
artifact/runtime/SQLite/filesystem/key-backend cell (for example "macOS 11.0+ arm64, APSW
`3.53.3.1`, SQLite source ID `2026-06-26 ...`"), never a generic "Python" or "macOS/Linux" claim.

Cursor local compatibility has two current implementation rows and two deferred SDK metadata rows,
never one inferred support claim. Here `deferred` is a release-planning label, not a fifth
compatibility state. No row becomes `supported` merely by appearing in this table; the exact proof
boundary must be satisfied independently.

| Cell | Exact profile | Required proof boundary |
|---|---|---|
| IDE | Cursor `3.17.8` build `3.17.8`, macOS arm64 | explicit isolated user root, portable/native source, discovery, activation, skill delivery, MCP owner/runtime, exact-JSON text compatibility, model call |
| CLI | Cursor Agent `2026.07.09-a3815c0`, macOS arm64 | exact binary digest, explicit `--plugin-dir`, skill delivery, MCP owner/runtime, model call |
| SDK TypeScript (deferred) | `@cursor/sdk==1.0.23`, bridge `sdk.v1` metadata fixture | no operational SDK claim; future design-gated proof must cover explicit local `settingSources`, precedence negative controls, and a correlated model call |
| SDK Python (deferred) | `cursor-sdk==1.0.24`, bridge `sdk.v1` metadata fixture | no operational SDK claim; future design-gated proof must cover explicit local `setting_sources`, precedence negative controls, and a correlated model call |

The IDE and CLI rows are initial implementation/fixture pins, not a promise that those or nearby
builds have complete release support evidence. The SDK rows retain metadata-only fixture pins for
future work and carry no current compatibility claim. A new design-gated issue and independently
reviewed operational proof are required before either SDK row can become a support claim. Cursor
Cloud and Cloud Agents are unsupported by issue #153.

Claude Code compatibility starts with one independent native cell:

| Cell | Exact profile | Required proof boundary |
|---|---|---|
| CLI/local/project | Claude Code `2.1.241`, exact executable digest, macOS arm64, private marketplace `finishup-local`, native format | strict validation, source/render/cache byte identity, project registration, disabled install, discovery, explicit enablement, new-session/reload activation, `/finishup:finishup` delivery, exclusive MCP owner/runtime, scoped model call, consented hook evidence |

The committed fixture proves strict validation, project installation into an exact cache, disabled
default, discovery/component inventory, hook declaration, fresh-session plugin/skill/tool
registration, and connected plugin-owned strict MCP. A correlated model call was blocked by absent
authentication in the isolated Claude config; only SessionStart/SessionEnd hook delivery was seen,
and the separately installed older FinishUP lacked the new hook command. Model use, accepted
observation, AI-powered review dispatch, privacy receipt, and workflow receipt therefore remain
unobserved
for that `2.1.241` cell. A later live capture (2026-09-04) on Claude Code `2.1.251` observed
`PostToolUse` delivery for a scoped MCP tool with `tool_response` as one bare JSON string of the
structured result; the binder admits that shape and a fixture pins it
(`docs/runbooks/claude-code-integration.md`). That capture is an observed payload shape only: it
populates no capability-profile entry, does not move the cell above, and `2.1.251` is not a tested
version.
Claude Desktop local/SSH, Desktop remote, web/cloud, synced plugins, managed/user/local scopes,
Agent SDK, and noninteractive/headless behavior are separate unpopulated cells. Claude Code is not
claimed to consume Agent Plugins 1.0.0.

Local-control schema `2.7.0` is the current append-only service-control wire. It retains the
`2.6.0` method bodies and adds the project support method. Retained schema bytes establish
historical decoding support, not interoperability between running package generations. Peers must
match the schema-manifest digest; no source is inferred across versions. Because every schema
change moves that digest, an upgraded installation cannot talk to the previous installation's
still-running service, and an older CLI cannot talk to a newer still-running service: a
decodable hello with a foreign digest is answered with this installation's hello-result and then
refused as `service_incompatible`, and on-demand startup
(the MCP bridge) or the explicit `finishup service restart` replaces an older stale holder with a
service of the current installation through its ordinary bounded shutdown. On-demand startup never
replaces a holder stamped with a newer package; only an explicit restart may. Stale bridges are
then refused in turn until their host session is reopened. A package-version change that leaves the
digest unchanged is still decodable, and a new session's bridge retires that older service too
(ADR-007, 2026-09-24 amendment). The 2026-08-27 Claude dogfood hit the newer-client /
older-service direction and saw an opaque `INTERNAL_ERROR`; that is now a bounded
`SERVICE_UNAVAILABLE` naming the repair. The 2026-08-28 dogfood hit the older-CLI / newer-service
direction as an opaque `invalid_request` with no correlation id; the service now answers the
hello-result so current CLIs name `service_incompatible` with holder identity and a diagnostic id.
An older CLI whose closed method enum cannot decode the new project method can instead report
`frame_invalid`. Use the updated launcher; existing host bridges switch when their sessions are
reopened. A frozen older wire is not widened to authorize newer methods.

## Change and deprecation process

Every change class (protocol, event, storage, object, projection, provider, platform) names its
required schema, ADR, fixture, conformance, migration, capability, and documentation updates before
it can ship. A breaking change requires a new version axis value, a stated upgrade/read strategy, a
retained fixture for the old shape, and an explicit known-limitation entry. A deprecation states the
version it was first deprecated in, the last version it remains supported in, and its removal
target; alpha status does not by itself promise any particular support duration absent a published
policy.

To diagnose a mismatch: capture `version --json`, the exact error reason code, the bundle/manifest
version identities, and the public digests involved — never upload the bundle, database, object
file, key material, configuration, path, or a transcript. Compare the captured identities against
the release support matrix and choose one of: upgrade, run a supported migration, use a compatible
client/skill version, or restore from a verified backup. Never force-edit version metadata to make
an identity mismatch go away.

## Current support manifest

The live, exact per-release support/capability cells (tested Codex versions, provider profiles,
platform matrix, and the trigger-hook capability cell) are published with each release as part of
`version --json --resources` and the release evidence bundle, not hard-coded in this page.
