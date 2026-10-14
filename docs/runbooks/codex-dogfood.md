# Codex exact-worktree dogfood parity

This runbook governs Codex dogfood launched from a disposable Git worktree. It prevents a
cooperative-MCP success from being reported as full Codex integration when the exact tested root
did not have the installed plugin, observation consent, mapping, hook delivery, or stream drain.

The retained gate is `scripts/check_codex_dogfood_parity.py` (issue #464). Run its `preflight`
phase before the first model task action and its `full` phase after rollback. A nonzero preflight
means **do not launch Codex**. The gate validates bounded structural evidence; it does not observe
the machine on its own, authenticate the report author, or upgrade a digest into content review.

## 1. Isolation and authority

- Use a disposable worktree, an isolated Codex executable/home, an isolated FinishUP installation and
  state directory, and a candidate wheel built from the recorded source ref.
- FinishUP isolation uses exactly one supported contract (ADR-026, issue #518): provision one
  owner-only (0700), symlink-free private directory outside shared temp and any repository, and
  export `FINISHUP_ISOLATED_ROOT` to it for **every** tested process — the launcher, the MCP server
  entry, hook commands, and every `finishup` control command the run executes. Config, storage
  bundle, state (service lock/generation), control endpoints, cache, and logs all derive from
  that root, so the isolated runtime structurally cannot reach the normal singleton. Do not treat
  `FINISHUP_STORAGE_DATA_DIR` alone as isolation (it relocates only storage), and do not rely on a
  bare `finishup` child command resolving ambient identity. A set but unusable root fails closed
  (`isolation_root_invalid` or the precise path-safety reason) instead of falling back to the
  normal install.
- Prove, never assume, the isolation mode with two connection-free snapshots. First run the normal
  target's exact `finishup service isolation --json` without the isolation variable; then run the
  candidate executable with the exact launch environment. Compare the two exact reports. Platform
  defaults are not a substitute because the normal target may relocate its config or storage.
- The isolation report's `path_identity` digests (`*_path_digest`) bind which path a root or
  file resolves to, not the file's bytes. An in-place or atomic edit of a config leaves its path
  digest unchanged, so never read equal path digests as "the config did not change". Byte
  evidence comes only from content observations: `finishup service isolation --json
  --content-digests` for the selected FinishUP config, and `--observe` (section 6) for normal-target
  files. Each carries SHA-256, size, existence, and observation time — never content.
- Rollback of FinishUP state is deleting the isolation root: every artifact of the isolated runtime
  lives beneath it. Stop only processes the runner started, then remove the root. An instance
  provisioned by `scripts/provision_test_instance.py` (ADR-028) is pinned to its root and disposed
  with that script's `dispose`, which stops only the holder of that root's singleton; see
  [`test-instances.md`](test-instances.md).
- Two Codex homes have different lifetimes. The **host** Codex home (the one carrying the plugin,
  MCP activation, and hooks under test) is per run and lives beneath the run directory. The
  **evaluator** home bound by `finishup provider codex-subscription setup --codex-home <dir>` holds
  Codex-owned ChatGPT OAuth state and no FinishUP identity, so it may be a stable owner-private
  directory outside the isolation root that later runs pass again; `setup` then reuses the
  existing sign-in (`login_reused: true`) instead of opening a new challenge. Record it through
  its `codex_home_digest`; never use the ambient user Codex home or the host home for it, and log
  it out with `finishup provider codex-subscription disconnect`, not by deleting the root. Without an
  explicit `--codex-home`, the default evaluator home resolves beneath the isolation root and is
  therefore fresh — and asks for sign-in — on every run.
- The exact worktree passed to Codex is also passed to plugin status, observation status, consent,
  mapping, drain, and session-stream reconciliation. Never substitute the primary checkout.
- Observation consent is independent trusted-local authority. Do not copy its database row, reuse
  primary-checkout consent, symlink state, or grant it through MCP/chat. When missing, stop and show
  the local `finishup observe grant --workspace <exact-worktree>` continuation.
- Activation decisions are exact-target and digest bound. Do not reuse an acceptance/decline from
  another executable/home or earlier cache state. `installed_not_activated` fails preflight.
- Snapshot the normal Codex target before the run (section 3). Test-owned mutations must be
  reversible, and the normal target must compare unchanged after rollback.

Do not place the report in the worktree or commit it. It is a run artifact. The report contains no
absolute paths, usernames, credentials, prompts, transcripts, provider payloads, command output, or
raw model content.

## 2. Identity record

Resolve and verify, rather than merely accept, these inputs:

| Report field | Required proof |
|---|---|
| `source_ref` | Exact 40- or 64-hex commit checked out by the tested worktree. |
| `package_digest` | SHA-256 of the candidate wheel/package installed in the isolated runtime. |
| `codex_executable_digest` / `codex_version` | Exact selected executable bytes and full reported version. |
| `codex_home_digest` | SHA-256 over the canonical selected Codex-home identity; do not publish the path. |
| `launcher_digest` | Exact launcher bytes that start the tested Codex process. |
| `route_profile` | Registered `strict` or `policy` route actually observed for that isolated target. |
| `worktree_digest` | SHA-256 over the canonical tested Git-root identity; do not publish the path. |
| `finishup_isolation` | `mode` and the five candidate `path_identity` digests from the exact launch report, plus `normal_mode` and the five `normal_*_path_digest` fields copied from the exact normal-target report: state, endpoint, storage, config, and FinishUP executable. They are path identities only. |

The source ref, wheel digest, executable digest/version, and launcher digest must agree with the
actual launch inputs. A clean working tree is not a substitute for the exact source ref, and an
installed package version is not a substitute for the wheel digest.

## 3. Preflight before launch

Run each status command from the isolated runtime, with the exact selectors filled in:

```text
<normal-finishup> service isolation --json --content-digests
FINISHUP_ISOLATED_ROOT=<exact-root> <candidate-finishup> service isolation --json
uv run python scripts/check_codex_dogfood_parity.py --observe <normal-codex-home>/config.toml [--observe <other-normal-target-file> ...]
finishup recommend list --codex-path <exact-executable> --codex-home <exact-home> --json
finishup integrate codex plugin status --project-root <exact-worktree> --codex-path <exact-executable> --codex-home <exact-home> --json
CODEX_HOME=<exact-home> CODEX_TESTING_HOME=<exact-home> finishup integrate codex mcp status --codex-path <exact-executable> --json
python scripts/capture_codex_mcp_surface.py --codex-binary <exact-executable> --codex-testing-home <exact-home> --output <capture-outside-worktree.json>
finishup observe status --workspace <exact-worktree> --codex-path <exact-executable> --codex-home <exact-home> --json
```

The report has one row for every preflight facet. A `pass` row has an evidence digest and no reason
or next action. A non-pass row uses exactly one of `fail | unsupported | blocked | not_run`, a
bounded reason token, an optional evidence digest, and a closed next action.

| Facet | Pass condition |
|---|---|
| `source_identity` | Worktree HEAD equals `source_ref`. |
| `package_identity` | Installed candidate is the recorded package digest. |
| `service_isolation` | The exact normal report has mode `ambient`, the exact launch report has mode `isolated`, and every state/endpoint/storage/config/executable digest differs. Shared, relocated, ambient, or unknown identity cannot pass. |
| `mcp_child_isolation` | MCP status is `yoetz_owned` with `isolation_binding=isolated_exact`, and the pre-model app-server capture starts the registered server successfully. This combines the exact reviewed binding, ADR-026 root derivation, and the installed Codex propagation regression; a bare, missing, different, foreign, failed, or unverifiable child cannot pass. |
| `workspace_binding` | Codex and every FinishUP control use the same exact worktree. |
| `observation_consent` | Consent is `active` for that worktree commitment. |
| `plugin_source` | Exact managed source is present in that worktree. |
| `plugin_installation` | The selected target reports the intended installed plugin. |
| `plugin_discovery` | The selected host discovers the exact plugin source. |
| `plugin_inventory` | Canonical inventory is positively verified. |
| `plugin_enablement` | Inventory/config report enabled for the selected home. |
| `plugin_rendered_bytes` | Host-rendered bytes match the selected Codex version. |
| `plugin_cache` | The versioned cache matches the intended rendered digest. |
| `plugin_activation` | Exact target state is `active`; presence or enablement alone is insufficient. |
| `normal_target_snapshot` | A digest-only before-run snapshot exists. When the report carries the `normal_target` lane, every `before` observation must be `present` or `absent`. |

The `--observe` rows are the `before` observations of the report's optional `normal_target`
lane. Give each observed file one stable `slot` token (for example `codex_config`); copy the
normal FinishUP report's `config_content` into a slot too when the normal FinishUP config is part of the
unchanged proof. The lane is optional (`normal_target: null`), but without it
`normal_target_unchanged` rests on the operator's own comparison, and the gate cannot tell a
path-stable byte change from an unchanged target.

If isolation is not proven — the command fails, reports `ambient`, or any identity digest equals
its normal-target counterpart — record the non-pass `service_isolation` row with the
`provision_isolated_finishup_root` continuation, provision a fresh isolation root, re-export
`FINISHUP_ISOLATED_ROOT`, and rebuild the report from fresh status. Never launch over shared,
ambient, or unknown FinishUP identity.

If the MCP registration is not `yoetz_owned` or its binding is not `isolated_exact`, record the
non-pass `mcp_child_isolation` row with the `reregister_isolated_mcp` continuation. Re-run the
isolated registration preview, review the exact `isolated_root`, apply that same preview digest,
confirm status reports `isolation_binding=isolated_exact`, and recapture the app-server inventory
before rebuilding the report.

If the registration is already owned and exact but the child state is `failed` or `unknown`,
re-registering changes nothing; record the row with the `recapture_isolated_mcp_child`
continuation instead. Inspect the capture output for the child launch error, repair the candidate
executable or its environment outside the registration, and re-run the capture until the child
starts. The capture starts the registered child without a model task; inventory is child-start
evidence, not proof that a model received or used a tool.

If consent is missing, record `blocked / observation_consent_missing /
finishup_observe_grant_exact_worktree`, show the trusted local command, and stop. If activation is
`installed_not_activated`, record `fail / installed_not_activated /
finishup_recommend_list_exact_target`, run the exact-target recommendation flow locally, and rebuild
the report from fresh status. Foreign, modified, or ambiguous activation uses
`manual_activation_review`; there is no force path.

Validate before launch:

```text
uv run python scripts/check_codex_dogfood_parity.py <report-outside-worktree.json> --phase preflight
```

Only `preflight_outcome: pass` and `launch_allowed: true` permit a fresh Codex process.

## 4. Fresh-host proof

The launched process must be new enough to load the exact activated plugin. Registration, file
presence, marketplace inventory, `tools/list`, or a successful non-model probe cannot replace any
of the following cells:

| Facet | Required evidence |
|---|---|
| `skill_delivery` | Fresh process receives the installed FinishUP skill/instructions. |
| `mcp_runtime` | The exact isolated launcher starts the intended FinishUP MCP runtime. |
| `model_mcp_call` | A correlated model-issued FinishUP MCP operation succeeds or returns its typed product result. |
| `semantic_dispatch` | Every in-scope `semantic_required` check reaches a terminal typed status. |
| `semantic_provenance` | Provenance matches the AI-powered review result under the AI-powered review dogfood gate. |
| `receipt` | Receipt conclusion and coverage match the recorded frontier and limitations. |
| `corrective_influence` | Scored only when the influence runbook put it in scope; otherwise `not_run`. |

Host authorization permits the in-scope tool call only. FinishUP still independently enforces
repository, privacy, provider, disclosure, credential, and exact-request gates.

## 5. Observation and session stream

For a profile advertising hooks, exercise its advertised lifecycle events in the fresh session and
then run status and drain for the exact worktree:

```text
finishup observe status --workspace <exact-worktree> --codex-path <exact-executable> --codex-home <exact-home> --json
finishup observe drain --workspace <exact-worktree> --json
finishup observe status --workspace <exact-worktree> --codex-path <exact-executable> --codex-home <exact-home> --json
```

`hook_lifecycle`, `mapping`, `accepted_envelopes`, `diagnostics`, and `drain` pass separately.
Passing requires `mapping_present: true`, at least one accepted consented envelope, bounded
diagnostics with no unexplained failure, a successful drain, and zero unexplained undelivered rows.
The drain must report `terminal: drained` and `pending_after: 0`; it repeats passes while rows
resolve and never sleeps, so `retry_pending` is a real cause (read `reasons`), not a timing
artifact. Expect no outbox rows for the workflow's own `status`/`receipt`/`read_guidance` calls or
for any FinishUP pre-event (issue #564); a row per `start`/`check`/`respond`/`publish_work` post-event
is the proportional volume.
Primary-checkout consent cannot satisfy this cell; the permanent regression fixture is
`tests/fixtures/codex-dogfood/worktree-without-exact-consent.json`.

For a profile advertising session-stream reconciliation, reconcile the real rollout through the
supported local command, then require accepted mapped records, cursor advancement, and no
unsupported/unmapped gap. The facet may be advertised only when the report's exact
`codex_version` has a fixture-proven rollout profile (`0.148.0` or `0.150.1`; the gate refuses
`session_stream_scope_unproven_codex_version` otherwise), and it still records `pass` only on that
run's own reconciliation evidence. A profile that does not advertise the capability records
`unsupported / capability_not_advertised`; it never records pass.

## 6. Rollback and full gate

Stop only processes the runner started. Reverse every test-owned activation/configuration change
through its reviewed command, verify the isolated target's intended final state, and compare the
normal-target snapshot. Record `rollback` and `normal_target_unchanged` independently.

With the `normal_target` lane, re-run the same `--observe` commands after rollback and record
each row as that slot's `after` observation (leave `after: null` only when it was not captured;
the unchanged facet then cannot pass). The gate compares path identity and bytes separately and
requires the unchanged facet to agree:

| Derived change (strongest first) | Required `normal_target_unchanged` row |
|---|---|
| Any `after` missing | not `pass` |
| A before/after observation is `not_regular`, `oversized`, `unreadable`, or `unstable` | `fail / normal_target_content_unobservable` |
| Path digest and bytes both differ | `fail / normal_target_path_and_content_changed` |
| Same path digest, different presence, size, or SHA-256 | `fail / normal_target_content_changed` |
| Different path digest (moved file or retargeted symlink), identical bytes | `fail / normal_target_path_moved` |
| Nothing differs (including absent before and after, or an atomic replacement with identical bytes) | may `pass`; a content reason is refused |

Anything else is rejected as `normal_target_unchanged_content_mismatch`. A change made
concurrently by another normal-target writer (for example desktop plugin materialization) fails
the facet exactly like a test-owned change; the reason names the kind of change, and the
timestamps bound when it happened, but attributing it remains an operator forensic step.

Then run:

```text
uv run python scripts/check_codex_dogfood_parity.py <report-outside-worktree.json> --phase full
```

The full outcome cannot pass if preflight did not pass. Required postflight rows vary only by the
four explicit scope booleans: advertised hooks, advertised session stream, required AI-powered
review, and required influence measurement. Optional unsupported/not-run rows remain listed in the
result instead of disappearing into an aggregate green status. A row excluded by scope must be
`unsupported` for an unadvertised host capability or `not_run` for optional AI-powered
review/influence work; an out-of-scope pass, failure, or block is inconsistent evidence and
invalidates the report.

## 7. Report shape and statuses

The top-level keys are exactly `schema`, `identity`, `scope`, `observed`, `normal_target`, and
`facets`; the current schema is `yoetz.codex-dogfood-parity/4` (version 1 lacked FinishUP isolation
identity; version 2 lacked host-child binding proof; version 3 named path-identity digests
ambiguously as `*_digest` and had no byte-content lane; none is accepted). `normal_target` is
`null` or `{"files": [...]}` with 1–32 entries of exactly `slot`, `before`, and `after`; each
observation has exactly `path_digest`, `presence`, `content_digest`, `size_bytes`, and
`observed_at`, and only a `present` observation carries a digest and size. `observed` retains only closed states/counts:
activation state, FinishUP isolation state (`isolated|shared|ambient|unknown`), MCP registration state,
MCP isolation binding, MCP child state (`ready|failed|unknown`), exact/primary consent states,
workspace-match boolean, mapping presence, accepted envelope count, undelivered count, drain
success, hook coverage, and stream coverage. The validator rejects a passing
`service_isolation` row whose observed state is not `isolated`, whose identity mode is not
`isolated`, or whose digests show any shared identity root; it rejects a passing
`mcp_child_isolation` row unless the registration is owned, the binding is exact, and the child is
ready.

Every facet is reported even when unsupported or not run. The validator rejects extra top-level,
identity, scope, observed, or facet-row fields; this is the privacy boundary that keeps paths and
transcripts out. Its output includes the preflight and full outcomes, launch decision, every
non-pass facet by class, and a digest of the bounded report.

Final reporting walks the cells rather than replacing them with “integration passed”: packaging,
installation, discovery, activation, skill delivery, MCP runtime, model authorability/use, hooks,
consent, mapping, observation, session stream, AI-powered review dispatch/provenance, receipt,
corrective influence, rollback, and normal-target isolation.

## See also

- [Codex integration](codex-integration.md) — plugin, skill, MCP, and observation surfaces.
- [AI-powered review dogfood](semantic-dogfood.md) — route profiles and the provenance gate.
- [Influence dogfood](influence-dogfood.md) — attributable work-product change.
- [Dogfood CI](dogfood-ci.md) — the unattended mechanics lane that runs on every push to `main`.
