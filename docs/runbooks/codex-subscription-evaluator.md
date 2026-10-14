# Codex subscription AI-powered evaluator

This runbook owns the `codex-chatgpt-subscription@1` endpoint profile. It is an external AI-powered
evaluator behind the ordinary Yoetz privacy gateway, not the Codex host integration and not an
OpenAI Platform API profile.

## Capability admission (2026-10-13)

The evaluator uses the newest installed Codex that passes Yoetz's capability check; it no longer
pins one Codex build per platform (ADR-006, *Capability-checked evaluator admission*). Updating
Codex is enough: the next `setup` or `repair` adopts the newer release without a Yoetz release.

| Fact | Value |
|---|---|
| Eligible releases | stable OpenAI Codex npm `X.Y.Z` at or above the floor `0.157.1`; prereleases are never eligible |
| Platforms | macOS arm64 (`@openai/codex-darwin-arm64`), Linux x86_64 (`@openai/codex-linux-x64`); x86_64 WSL2 Linux userspace follows Linux (WSL smoke pending); no native Windows |
| Capability profile | `codex-evaluator/capability/v2` |
| Isolated config SHA-256 | `c11ecc6c60e5618ca1b988760ef643250527757a34ef2cbb9d393306236593da` (`support/codex-evaluator/config.toml`) |
| Evidence expires | `2026-11-30T00:00:00Z` (this Yoetz release's reviewed subset and probe) |
| Transport | app-server v2, stdio JSONL |
| Credential authority | `external_runtime_oauth` |
| Upstream-body observability | `unavailable` |

### The check

`setup`, `repair` and `runtime install` first retain the candidate in Yoetz's owner-private store,
then check those retained bytes. A failure is one closed token, and no case, sign-in or model
request is involved:

1. **Release floor.** For an npm wrapper the release comes from its manifests; for a native path,
   from `codex --version` under a throwaway scratch home. Below `0.157.1`, or a prerelease:
   `codex_runtime_version_unsupported`.
2. **Code-mode host.** `codex-code-mode-host` must sit beside the native executable:
   `codex_runtime_code_mode_host_missing`.
3. **Reviewed protocol subset.** The binary writes its app-server v2 schema with
   `codex app-server generate-json-schema --out <scratch>`. Yoetz checks structurally that every
   request it sends (`initialize`, `account/read`, `model/list`, `account/login/*`,
   `account/logout`, `thread/start`, `turn/start`, `turn/interrupt`) and every response,
   notification field, JSON type and value it reads is still there. Additive methods,
   notifications and fields pass. A closed value the evaluator interprets (agent-message phases)
   must not gain an unreviewed member. A request must not require a field Yoetz does not send,
   and each closed value Yoetz sends (`approvalPolicy` `never`, `sandbox` `read-only`,
   `personality` `none`, `summary` `none`) must still be admitted by its field; both enter the
   subset digest. Failure: `codex_runtime_protocol_incompatible`; a binary
   that cannot write the schema is `codex_runtime_protocol_unavailable`.
4. **Zero-inference probe.** One app-server session runs under a scratch home holding only the
   isolated config, with Yoetz's exact argv, `--strict-config`, overrides and environment
   allowlist:
   - `initialize` must name exactly the release being checked and the home
     (`codex_runtime_version_mismatch`);
   - `account/read` must answer;
   - `thread/start` must return an ephemeral, read-only, network-off thread in the new empty cwd
     with no instruction sources (`codex_thread_isolation_unproven`);
   - a barrier `account/read` then reads past everything Codex already wrote (stdout is in
     order), so an event buffered right behind the `thread/start` reply is still inspected;
   - every notification seen must be in the reviewed pre-disclosure allowlist
     (`codex_app_server_predisclosure_event_forbidden`,
     `codex_app_server_remote_control_not_disabled`, `codex_app_server_tool_request_forbidden`).

   No `turn/start` is sent. The scratch directory is deleted afterwards. On Linux, Codex emits a
   pre-disclosure `configWarning` when no system `bwrap` is on the fixed `PATH`
   (`/usr/bin:/bin`), so the check fails closed there until bubblewrap is installed and
   unprivileged user namespaces work.
5. **Model.** The dedicated home's readiness probe (`account/read`, then `model/list`, then the
   same barrier and allowlist check) must list the configured model with every configured
   effort; a release that warns only under the signed-in home is passed over. A home Codex reports signed in whose model
   no admitted release lists fails with `codex_model_unavailable`, without opening a sign-in.
   Update Codex, choose another `--model`, or pass `--switch-account`.

A passed check commits `capability.json` (`yoetz.codex-evaluator-capability/1`) beside the
retained copy. It holds the profile, floor, release, source identity, platform, executable and
code-mode-host SHA-256, the checked-subset digest, the isolated-config digest and the checks. The
binding commits to its digest (`capability_cell_sha256`). Receipts record the release, executable
SHA-256, profile and record digest in `runtime_evidence` as provenance. The launch fence re-hashes
both files against the record before every child, and every attempt re-proves the release, login,
model, thread posture and pre-disclosure events before the case crosses stdin.

### Newest first, falling back to the previous good release

Candidates are Yoetz's retained releases, the binding's own host installation, and every
discovered everyday Codex install, or the one `--executable` given. Yoetz keeps one per release
(its retained copy first) and tries them newest first. A candidate that fails the check, or whose
catalog lacks the model for a signed-in home, is passed over. `runtimes_passed_over` in the result
lists those tokens. When no candidate passes, the first candidate's token is the refusal and
nothing is written. Earlier retained releases stay available as fallbacks until
`runtime remove`.

Every check subprocess (`codex --version`, schema generation, the probe and the readiness probe)
runs as the leader of its own process group. Whether it exits, times out or fails, Yoetz kills
that whole group, so a descendant the candidate started is killed too, and then confirms no
member remains. When that cannot be confirmed, the result is
`codex_capability_probe_cleanup_unconfirmed`, even if the check had already failed for another
reason (that reason is kept as its cause). This token is not a fallback: selection and discovery
stop there, no further candidate is launched, and nothing is written. Inspect running processes,
stop any leftover Codex check you own, then retry.

Updating the everyday Codex (`npm install -g @openai/codex@latest`) never changes a working
binding by itself. The retained copy and its record keep serving until the owner runs `repair`
(or `setup`), which adopts the newer release when it passes.

### Tradeoff

There is no exact binary identity anymore. The record proves which bytes were checked and
launched, not that a new release is benign; a release can change behaviour that its schema and a
zero-inference probe cannot show. Every attempt still keeps:
- the dedicated home and environment allowlist;
- `--strict-config` with the critical deny overrides;
- the proven read-only, network-off thread;
- fail-closed tool, item, phase and event allowlists.

An unreviewed event that appears only after `turn/start` still fails closed: the review ends
`unavailable`, and nothing beyond the approved case was sent.

### Protocol review and evidence (2026-10-13)

Release-to-release changes in the reviewed subset:

- **0.157.1 to 0.159.0.** `PlanType` adds `promax`. `CodexErrorInfo` adds `flexUnavailable`
  (classified `provider_outage`) and `tooManyDenials` (transport). Methods and notifications are
  unchanged.
- **0.159.0 to 0.162.1.**
  - `MessagePhase` adds `partial_answer`, discarded like `commentary`, so only `final_answer` is a
    judgment;
  - the `thread/prediction/updated` notification is new and stays outside every allowlist;
  - `TurnStartParams` and `Turn` add the optional `parentTurnId` and `rootTurnId`;
  - `CodexErrorInfo` gains a catch-all variant.
- **Every release.** Rate-limit `planType` is now accepted as any bounded identifier and
  discarded, so a new plan cannot fail pre-disclosure validation.

Unauthenticated, zero-inference evidence on macOS arm64:

- The real check admitted npm `0.157.1`, `0.159.0` and `0.162.1`, and the global `0.162.1` install
  (same bytes as the npm package). A `0.153.4` install was refused by the floor.
- Each release passed the real probe the same way: `remoteControl/status/changed` with `disabled`,
  then `account/read` with no account, then a read-only, network-off ephemeral `thread/start`.
- The bundled (signed-out) catalog of 0.162.1 lists `gpt-6.1-sol` with efforts `low` to `ultra`;
  the 0.159.0 bundled catalog does not. The signed-in 0.159.0 catalog was reported to list it, but
  that was not reproduced here.
- Pending: authenticated Yoetz review through any capability-admitted release, Linux, WSL2, and a
  packaged installed wheel.

### Superseded pinned cells

The tables below are the historical pinned cells. A binding written under them reports
`codex_runtime_profile_outdated`; run `yoetz provider codex-subscription repair`, which re-checks
and rebinds while keeping the sign-in, model, efforts, budgets and dedicated home.

#### macOS arm64 (pinned until 2026-10-13)

| Fact | Required value |
|---|---|
| Distribution | OpenAI Codex npm `0.157.1-darwin-arm64` (`@openai/codex-darwin-arm64`) |
| Platform | macOS arm64 |
| Native executable | `vendor/aarch64-apple-darwin/bin/codex` |
| Native executable SHA-256 | `27ceb5f9b957b43a519efe4eaa3816a0bffb0a531a2c89af18840c0a3c016a7d` |
| Code-mode host | `vendor/aarch64-apple-darwin/bin/codex-code-mode-host` |
| Code-mode host SHA-256 | `80fdf166c3da068282d5692f67a852715a327ae7dc1913abb93b8c3d3030103f` |
| App-server schema SHA-256 | `2719fccd25a97a7ce355497ca5e9123a63f6dce7f9f83724a5b73fd927811f59` |
| Isolated config SHA-256 | `c11ecc6c60e5618ca1b988760ef643250527757a34ef2cbb9d393306236593da` |
| Capability-cell SHA-256 | `af37da789fd12c401870768845bd73ac99c7fbffb2c5ae81c6a0ecd3c27dfd1f` |
| Capability profile | `codex-evaluator/0.157.1/v2` |

#### Linux x86_64 (pinned until 2026-10-13)

| Fact | Required value |
|---|---|
| Distribution | OpenAI Codex npm `0.157.1-linux-x64` (`@openai/codex-linux-x64`) |
| Platform | Linux x86_64; WSL2 uses this cell only inside its Linux userspace (WSL smoke pending) |
| Native executable | `vendor/x86_64-unknown-linux-musl/bin/codex` |
| Native executable SHA-256 | `3e2584f3f3829a43a0495011a1cecb2facbe64a2403e2b682351fd9c2983f970` |
| Code-mode host | `vendor/x86_64-unknown-linux-musl/bin/codex-code-mode-host` |
| Code-mode host SHA-256 | `67b86142bac5cead11b8420cf32d3a2bf88c8868d71733f351ed7c5d95a953e0` |
| App-server schema SHA-256 | `2719fccd25a97a7ce355497ca5e9123a63f6dce7f9f83724a5b73fd927811f59` |
| Isolated config SHA-256 | `c11ecc6c60e5618ca1b988760ef643250527757a34ef2cbb9d393306236593da` |
| Capability-cell SHA-256 | `fa6a65e47fb7c7f647a31ae47625a3e99e80247cd412e4fdfe1922975f2fafa3` |
| Capability profile | `codex-evaluator/0.157.1/v2` |

#### Codex 0.157.1 admission (2026-09-27, issue #871, superseded)

Codex 0.150.1's ChatGPT model catalog does not list `gpt-6-luna`, the new-binding default since
#870. On a ChatGPT account, `codex exec --model gpt-6-luna` returns HTTP 400 there. Codex 0.157.1
lists `gpt-6-astra`, `gpt-6-sol` and `gpt-6-luna`, and it ran `gpt-6-luna`/high and
`gpt-6-sol`/medium (plain Codex, operator Modal Linux x86_64 runs, 2026-09-27). This release
therefore admits the exact 0.157.1 cells above in place of 0.150.1. ADR-006 still admits one
reviewed executable per platform.

Evidence recorded for this admission:

- **npm metadata.** `npm pack` tarball integrity for `@openai/codex@0.157.1-darwin-arm64` and
  `@openai/codex@0.157.1-linux-x64`, and the native executable digests in the tables.
- **App-server schema.** The pinned digest is the SHA-256 of
  `codex_app_server_protocol.v2.schemas.json` written by
  `codex app-server generate-json-schema --out <dir>` (no `--experimental`). The darwin binary
  (locally) and the Linux binary (disposable Modal sandbox) wrote identical bytes. The same recipe
  reproduces the pinned 0.150.1 digests.
- **Unauthenticated probe.** Run with Yoetz's exact argv, `--strict-config` and isolated config.
  - The unchanged config is accepted.
  - `initialize` reports 0.157.1 and is followed by `remoteControl/status/changed` with
    `status: disabled`.
  - `account/read` returns no account, plus a new `workspaceRouting` key that Yoetz does not read.
  - The bundled `model/list` includes `gpt-6-luna` (`high`, `medium`) and the earlier `gpt-5.6-*`
    models.
  - On macOS, Yoetz's own adapter ran wrapper resolution, retention, `verify_local_binding`,
    `account/read` and a logout probe, each with `cleanup: terminated`.

No authenticated Yoetz AI-powered review has run through either 0.157.1 cell yet. The packaged
Linux smoke is pending, no macOS authenticated run is claimed, and release evidence stays
`pending`.

Schema review, 0.150.1 to 0.157.1 v2, limited to what the evaluator reads:

- **Unchanged.** `initialize`, `account/read`, `model/list`, login/logout, `turn/interrupt`, token
  usage, warning/error, remote-control and `configWarning` shapes, and the server-request set.
- **Accepted, not retained.** `RateLimitSnapshot.normalModelSlug` (nullable string) is accepted as
  bounded bookkeeping of at most 128 characters and discarded. Without this, the pre-disclosure
  validator would have rejected it.
- **Classified.** `CodexErrorInfo.rateLimitExceeded` maps to `provider_rate_limited`, like HTTP
  429.
- **Not read.** Additive `ThreadStartResponse`, `Thread`, `TurnError`, `Model` and `agentMessage`
  fields.
- **Still fail closed.** The new `modelProvider/authRecoveryStarted|Completed`,
  `account/gatewayOAuth/changed` and `thread/attachment/updated` notifications, and the new
  `functionCallOutput` item, stay outside every allowlist. If a live run shows one of them during
  an ordinary review, file it against this cell; do not widen the allowlist locally.

**Moving an existing binding.** A binding written under 0.150.1 reports
`codex_runtime_capability_unsupported`, with continuation `repair`.

- With an everyday Codex 0.157.1 installed, `repair` discovers it. Otherwise run
  `runtime install --download` first.
- `repair` retains Yoetz's own copy at
  `external-runtimes/codex-evaluator/openai-codex-npm-<platform>-0.157.1/codex`.
- It keeps the sign-in, model, efforts, budgets and dedicated home when Codex's own probe reports
  the home signed in with the exact model. 0.157.1 still lists `gpt-5.6-luna` and `gpt-5.6-sol`,
  so those bindings keep their model. Pass `--model gpt-6-luna` to setup to move to the new
  default.
- The superseded copy under `openai-codex-npm-<platform>-0.150.1/` is no longer used, and nothing
  removes it automatically: `runtime remove` addressed only the admitted cell (since 2026-10-13 it
  deletes every retained release the binding does not use). That follow-up is
  tracked in #871.
- The default dedicated home directory, `external-runtimes/codex-0.150.1`, is a stable sign-in
  location, not the runtime version, and does not change.

On Linux, Codex 0.157.1 emits a pre-disclosure `configWarning` when no system `bwrap` is on the
evaluator's fixed `PATH` (`/usr/bin:/bin`). The guard still fails closed before disclosure, so
install bubblewrap and run where unprivileged user namespaces work.

#### Retained code-mode host (2026-09-27, issue #874)

Codex 0.157.1 starts a sibling helper, `codex-code-mode-host`, from beside its own executable at
`turn/start`. When the helper is missing it emits the `warning` notification: "Code Mode is
unavailable because failed to spawn code-mode host …". The evaluator correctly fails closed on
that warning.

The `v1` cell retained only `codex`. Its packaged Linux smoke therefore acknowledged the turn and
stopped at `runtime_warning` (`gpt-6-luna`, `case_disclosed=true`, `process_cleanup=terminated`).
A plain npm install, where the helper sits beside `codex`, emitted no Code Mode warning.

Profile `codex-evaluator/0.157.1/v2` makes the helper part of the cell:

- **Cell identity.** Each cell pins the helper's SHA-256, and the capability-cell digest covers
  it. The native executable, schema and isolated config digests are unchanged, so existing
  dedicated homes and sign-ins keep working.
- **Resolution.** Every supported selection must have the admitted helper beside the resolved
  native executable: nested npm wrapper, hoisted npm prefix, or the native path itself. A missing
  helper fails as `codex_runtime_code_mode_host_missing`; other bytes fail as
  `codex_runtime_capability_unsupported`.
- **Retention.** Setup, repair and `runtime install` copy both files into the retained store, and
  `runtime remove` deletes both. Every launch re-verifies both.
- **No config-only fix.** Disabling the helper instead (`features.code_mode_host = false`) is not
  a substitute. On macOS 0.157.1 it only changes the warning to "code-mode host is disabled",
  which still fails closed.

Local macOS arm64 evidence for v2, unauthenticated: Yoetz resolved the npm-prefix wrapper and
retained both files (`0500` in a `0700` store). An app-server turn from that retained pair, with
the unchanged isolated config, emitted no Code Mode warning. Authenticated Yoetz evidence for v2
is pending on both platforms.

**Moving a v1 binding.** A v1 binding's store holds `codex` only. It reports
`codex_runtime_executable_missing`, with a `code_mode_host` diagnosis of `missing` and capability
`profile_outdated`; `runtime status` shows the store as `incomplete`. Run
`yoetz provider codex-subscription repair`:

- It needs an admitted source with the helper beside it: a discovered everyday Codex 0.157.1 npm
  install, `--executable <bin/codex.js>`, or a prior `runtime install --download`.
- It adds the helper to the existing store without rewriting `codex`.
- It rebinds to v2 and keeps the sign-in and every choice.

Follow-up on #874: Codex's bundled `codex-resources/bwrap` is still not retained. On Linux the
evaluator relies on a usable system bubblewrap (see the `configWarning` note above).

#### Historical 0.150.1 evidence

This evidence was recorded on the superseded 0.150.1 cells and does not transfer to 0.157.1.

The 0.150.1 Linux cell was admitted on npm metadata, native executable bytes, the generated
app-server v2 schema, and a plain Codex device-login/Luna-high run in an isolated Modal Linux
x86_64 runtime. A fresh installed Yoetz wheel then ran in an independent Modal Linux x86_64 test
instance:

- the exact wrapper resolved to the pinned native digest;
- preview and `verify_local_binding` accepted the Linux cell;
- unauthenticated `account/read` and logout probes completed with `cleanup: terminated`, reporting
  `runtime_ready: true`, no auth mode, and no model availability.

The authenticated smoke evidence is limited to the Linux acceptance note below. WSL-specific
execution was not tested.

The September 7 v2 correction used the schema generated by the exact npm `0.150.1` CLI, whose
SHA-256 matched that cell's pinned schema. Synthetic fixtures cover sparse rate-limit
notifications, quota/429 errors, final answers, and terminal isolation violations. This does not
refresh the binary/platform evidence or claim new live acceptance. The expiry is unchanged and
release evidence remains pending. Existing v1 bindings fail the capability check with
`codex_runtime_profile_outdated`; review and run `yoetz provider codex-subscription repair` (or the
explicit setup flow) to bind v2 before attempting review. Repair reuses the existing login and
keeps every choice (see *Evaluator runtime retention and repair* below).

`account/rateLimits/updated` is sparse bookkeeping. Omitted/null metadata, nullable window times,
and any bounded string bucket ID are accepted with the pinned schema's types; none is retained.
After turn acknowledgement an unrecognized bookkeeping shape records only the closed
`rate_limits_invalid` diagnostic and reading continues under the same event/byte/deadline caps.
A later native error supplies the terminal stage and failure class. Login and pre-disclosure
validation still reject malformed shapes. The 0.157.1 `normalModelSlug` field is handled the same
way. No method or tool allowlist has changed.

New Codex-subscription setups recommend and preselect `gpt-6-luna`. The final-review reasoning
effort stays independently `high`, and routine checkpoint reviews default to `medium` (see *Routine
and final review budgets* below). When an existing binding is targeted, omitting `--model` preserves its
exact model, including during `--switch-account`; an explicit `--model` (including `gpt-5.6-sol`
when the app-server lists it) is required to change it. OpenAI API-key and other provider-preset
catalogs stay Sol-first. Historical packaged live evidence that names `gpt-5.6-sol` remains Sol
proof; it is not Luna acceptance and does not migrate.

## Luna acceptance boundary (2026-09-05)

[Issue #513](https://github.com/TheGaySupreme123/yoetz/issues/513) records two fresh packaged
`semantic_required` attempts on the exact macOS arm64 Codex `0.150.1` cell using Luna/high.
Both returned schema-valid judgments, distinct one-use authorizations and terminal privacy
receipts, finalized runtime provenance, and verified process cleanup. Their check results also
validate against the policy and strict MCP output descriptors. This is evaluator acceptance on
bounded cooperatively published records, not fresh Cursor activation or source-correctness proof.
A `harness_controlled_model_catalog_unavailable` negative used the same native runtime and
filtered only the Luna entry from its `model/list` response in memory. Yoetz returned
`model_unavailable` before `thread/start` or `turn/start`, with no case disclosure or provider
request and terminated cleanup. This proves the refusal boundary under the controlled catalog;
it does not claim that the upstream account lacks Luna. Historical Sol evidence stays unchanged;
the broader release-support cell remains an implementation candidate with pending evidence for
its full negative-control checklist.

### Linux authenticated smoke evidence (2026-09-13)

One installed Linux VM run used Yoetz wheel
`sha256:252ca337e2f002450fc5ae0649de2dbec29b70c12f1a0a6f768024e7acb4d68d`, the superseded exact
Linux x86_64 Codex 0.150.1 cell, and a fresh dedicated ChatGPT home. The VM had working user
namespaces and bubblewrap. At `2026-09-13 17:22 UTC`, one approved synthetic `Luna/high`
`semantic_required` check completed through the Yoetz privacy gateway with `case_disclosed=true`,
`turn_acknowledged=true`, and `process_cleanup=terminated`; a final task receipt was present. The
receipt conclusion was `insufficient_coverage`, with `completion_scope_declared_none`,
`evidence_content_digest_only`, and `semantic_challenges_rejected` recorded as coverage limits. The
check recorded a privacy-receipt identifier, but the receipt get/list service handlers were
unavailable (`method_forbidden`), so this evidence does not include a retrieved privacy receipt.
This is one authenticated AI-powered review smoke check, not two-check evaluator acceptance; no live
token accounting was captured in this run. The default gVisor sandbox failed closed on the
pre-disclosure `configWarning` because user namespaces were unavailable; do not bypass that guard.
WSL-specific smoke and the full negative and release-acceptance matrix remain pending. After the
probe, the supported tightening operation disabled external AI-powered review; disconnect confirmed
logout and removed the dedicated binding, and rollback was idempotent. Both test sandboxes were then
terminated.

## Setup and reverse operations

Use a dedicated home; never point this route at a normal Codex home or copy authentication from
one.

```text
yoetz provider codex-subscription setup \
  --model gpt-6-luna \
  --reasoning-effort high \
  --routine-reasoning-effort medium

yoetz provider codex-subscription status --json
yoetz provider codex-subscription disconnect --accept
yoetz provider codex-subscription rollback
```

### Login lives once per dedicated home

Codex owns the OAuth state of the dedicated home (`auth.json`, refresh, logout). `setup` therefore
treats a sign-in as something to prove, not something to repeat (#534): after the local preflight
and `prepare_codex_home`, it runs the same structural probe as `status` — app-server
`account/read` with `refreshToken: false` followed by `model/list` — and, when Codex reports a
ChatGPT account with the exact model/reasoning cell available, writes the binding and returns
`login_reused: true` without issuing `account/login/start`. The three non-reuse edges are distinct:
a logged-out home or a home missing the exact model takes the ordinary login path, which still
fails with its existing `codex_subscription_readiness_unproven` token when the login cannot prove
the cell; a probe whose process-group cleanup is unconfirmed fails closed with that same token
*before* any further child launch, never falling through to login; and a dedicated home whose
`config.toml` differs still fails `codex_runtime_config_conflict` before any process starts. A
probe that cannot complete at all — an unreachable or unanswering app-server, an expired
capability cell — fails with its own bounded token rather than silently opening a login.
`--switch-account` (the prompt-loop "switch ChatGPT account" confirmation and the `/provider`
"Switch Codex ChatGPT account" choice) is the explicit override: it skips the probe, logs the home
out through Codex, and signs in again. Yoetz never reads, copies, or moves `auth.json`; readiness
is only what Codex answers.

The dedicated evaluator home may be reused across runs, including isolated dogfood runs, by
passing the same owner-private directory to `--codex-home`. The parity report identifies it by
its existing `codex_home_digest`. It must remain a dedicated home — never the ambient user Codex
home and never the per-run host home — and `disconnect` remains the way to log it out. Because a
reused home outlives the isolation root, its full teardown is `disconnect` followed by the
operator deleting that directory; deleting the isolation root does not remove it (ADR-026).

### Expired or missing sign-in notice (#819)

When an attempt fails at `login_required` (or Codex rejects the ChatGPT token), the service
remembers `sign_in_required` for the binding until a later attempt gets an answer or the service is
recomposed. Codex, Claude Code, and Cursor then receive standing hook advice at session start or
the end of a turn (Cursor: `sessionStart` only) naming `renew_provider_sign_in`: the agent tells
the user and offers to rerun `setup` with the executable and home from `status --json`. The user
completes the browser or device-code sign-in. Nothing probes the login outside an attempt or
`status`, so after a restart the notice returns only when the next attempt fails.

## Selected executable resolution

With no `--executable`, setup and repair choose among the eligible installations as described in
*Newest first* above. To pin one installation, pass one absolute selected path. The supported npm
layouts are:

1. the npm wrapper whose exact platform package is nested below that wrapper's package root:
   `@openai/codex-darwin-arm64` for macOS arm64 or `@openai/codex-linux-x64` for Linux x86_64
   (including a Linux userspace under WSL2); and
2. an npm-prefix wrapper whose matching platform package is hoisted beside `@openai/codex`
   under the same selected prefix.

The third supported form is the native `codex` executable itself, whose release Yoetz reads with
`codex --version` under a scratch home. Resolution follows only the selected wrapper's package
root and, for a prefix install, that same prefix. It never searches arbitrary PATH entries,
unrelated prefixes, or unbounded parent directories. Every form keeps the platform,
package-manifest and release-floor checks; the capability check then decides admission.

Before Codex login, setup shows the runtime, its release, destination, model/reasoning selection,
dedicated home,
unknown plan-specific data-use posture, privacy implication, and reverse commands. Browser and
device-code login are the only accepted methods. The browser window is 600 seconds; the device-code
window is 900 seconds. Cancellation and timeout use bounded process-group termination, pipe close,
and task cleanup before returning one terminal diagnostic.

Every reviewed release (0.150.1 through 0.162.1) emits `remoteControl/status/changed` immediately
after initialization, so
either login method may receive that notification while `account/login/start` is outstanding. The
login waiter follows the same reviewed pre-disclosure method allowlist as the evaluator: accepted
structural notifications are demultiplexed and discarded unread, with the remote-control and rate
limit shapes validated; warnings remain fail-closed. `account/login/completed` remains the only
terminal login event and must carry the exact `loginId` with `success: true`. Unknown, tool, or
otherwise unallowlisted notifications still fail closed. This mirrors the official SDK's separate
login waiter/global-notification routing without introducing a broad ignore or carrying notification
payload content across the adapter.

No partial Yoetz binding is written. A timeout, denial, malformed completion, process exit,
cancellation, or later configuration-write failure leaves a new or replacement Yoetz binding
uncommitted. If Codex completed its own login before the failure, its OAuth state may remain in the
dedicated home because Codex owns authentication, refresh, `auth.json`, and logout. Use
`disconnect` to request Codex logout and then remove the Yoetz binding; use `rollback` to remove
only the Yoetz binding while preserving the home and installation. Guided setup, the prompt-loop
menu, and `/provider` can log out the dedicated home first when switching accounts. CLI, menu, and
`/provider` recompose the local service after setup, disconnect, or rollback so a running daemon
cannot keep dispatching the previous binding.

Service READY composition does not spawn a Codex app-server to prove login. The READY credential
fact is the binding, the retained bytes still matching their capability record, the isolated
config, and the dedicated home. `account/read`
and `model/list` run inside the same `evaluate()` child that will disclose the case, or from
`yoetz provider codex-subscription status`.

That structural fact is memoized per READY generation (#881). The exact binding, a stat
fingerprint of the retained executable, its code-mode host, its capability record, the dedicated
home and its `config.toml` (device, inode, size, mtime, ctime, mode, owner) key the result. Both files are
re-hashed, off the event loop, only when that key changes; evidence expiry is checked against the
clock on every read. The launch fence is not memoized: every `evaluate()` child launch still
hashes both files.

## Evaluator runtime retention and repair

Issue #855. The evaluator runtime is kept separate from the everyday Codex installation. Setup and
repair bind a private copy of the checked release's native executable and code-mode host (#874),
one directory per release:

```text
<data bundle>/external-runtimes/codex-evaluator/openai-codex-npm-<platform>-<release>/codex
<data bundle>/external-runtimes/codex-evaluator/openai-codex-npm-<platform>-<release>/codex-code-mode-host
<data bundle>/external-runtimes/codex-evaluator/openai-codex-npm-<platform>-<release>/capability.json
```

The directory is owner-only (`0700`), each copy `0500` and the record `0400`. Bytes are hashed
while copied; a file that already holds the same bytes is kept as-is, and replacing either file
first removes the record, so a record never vouches for bytes it did not check. The capability
check runs on the retained copy and commits the record only after it passes. Every launch
re-verifies both files against the record with the `verify_local_binding` fence. Updating or
replacing the everyday Codex, for example `npm install -g @openai/codex@latest`, never strands
the binding; the next `repair` adopts it. Each isolated or test instance keeps its own copies in
its own data bundle.

Setup, repair, install, and removal serialize mutations of this store. A concurrent command fails
with `codex_evaluator_runtime_busy`; retry it after the first command finishes. The lock remains
held through setup or repair's readiness probe and binding write, preventing removal from leaving
a newly successful binding pointed at a missing runtime. Service readiness and structural
diagnostics both use the current service clock to reject expired capability evidence.

```text
yoetz provider codex-subscription runtime status --json      # no Codex process, no sign-in check
yoetz provider codex-subscription runtime install --from /absolute/path/to/codex  # retain + check
yoetz provider codex-subscription runtime install --download # newest Codex via npm, after consent
yoetz provider codex-subscription repair                     # adopt the newest passing release
yoetz provider codex-subscription runtime remove             # drop releases the binding does not use
```

- **Selection.** With no `--executable`, setup and repair try the eligible releases newest first
  (see *Newest first* above): Yoetz's retained copies, the existing binding's host installation,
  and discovered everyday installs, one per release with the retained copy first. A release below
  the floor or a prerelease is never offered. Guided setup (first run, the prompt menu,
  `/provider`) offers the newest as the default; accepting it keeps the newest-first fallback,
  and only a different, explicitly typed path pins setup to that one runtime. When nothing
  eligible exists, first-run setup and
  the prompt menu offer a consented download; `/provider` shows
  `yoetz provider codex-subscription runtime install --download` and lets the operator enter a
  local Codex path or return after installing.
- **Download.** `runtime install --download` runs the operator's own `npm install --prefix
  <owner-private staging> --ignore-scripts --no-audit --no-fund --no-package-lock
  @openai/codex@latest` under their registry settings, keeps only the native executable and its
  code-mode host, checks them, and always deletes the staging prefix. npm output is not captured; failures
  are the closed `codex_evaluator_runtime_download_failed|download_timeout|package_manager_unavailable`
  tokens. `--npm` selects an absolute npm; `--from` retains a local copy without any download.
- **Repair.** `repair` rebinds an existing binding to the newest release that passes the check. It
  shows the release change and the fallback candidates, needs `--accept` or an interactive yes,
  reports `changed_fields` and `runtimes_passed_over`, and preserves the provider role,
  model, reasoning effort, timeout, retries, and dedicated home. The login is reused only when
  Codex's own `account/read` / `model/list` probe reports the home signed in with the exact model.
  A signed-out home fails `codex_subscription_login_required`; a signed-in home whose model no
  admitted release lists fails `codex_model_unavailable`. Either way it writes nothing and never
  starts a
  sign-in, logs out, or switches accounts. A missing home, an unsafe home, or a modified
  `config.toml` is refused for the owner to fix first. Only a missing Yoetz-owned `config.toml` is
  restored. The write is checked against the exact preimage, then the service is recomposed.
- **Rebinding keeps budgets.** Re-running setup keeps the existing binding's `timeout_seconds`,
  `max_retries`, and reasoning effort unless the owner passes a new value, so a repair never
  silently lengthens or multiplies review attempts.
- **Reverse operations.** `disconnect` and `rollback` leave the retained copies in place. `runtime
  remove` deletes every retained release the binding does not use and is refused
  (`codex_evaluator_runtime_in_use`) when the bound release is the only one left. A stranded
  binding can still be disconnected: the newest release that passes the check logs the dedicated
  home out in memory for that one probe.

### Structural states

`runtime status`, `provider status` (`external_runtime`), `codex-subscription status`, the prompt
menu, and `/provider` report the same closed state, computed only from the binding, executable
bytes, and dedicated home. A failed check keeps the public `unavailable` /
`credential_unavailable` pair and adds a request-joined `semantic_external_runtime_unready`
owner diagnostic carrying the state.

| State | Meaning | Continuation |
|---|---|---|
| `codex_runtime_executable_changed` | The bound executable, its code-mode host, or its capability record no longer matches what passed the check. | `repair` |
| `codex_runtime_executable_missing` / `_invalid` | The bound executable, its code-mode host, or its record is gone, or a file is not owner-executable. | `repair` |
| `codex_runtime_profile_outdated` | The binding was written under an earlier contract, for example a pinned `codex-evaluator/0.157.1/v2` cell. | `repair` |
| `codex_runtime_version_unsupported` | The binding names a release below the floor. | `repair` (with a newer Codex) |
| `codex_runtime_capability_unsupported` | The binding's identity disagrees with its release or platform. | `repair` |
| `codex_runtime_config_missing` | The dedicated home's Yoetz-owned `config.toml` is absent. | `repair` restores it |
| `codex_runtime_config_changed` | That `config.toml` was modified. | Restore it or remove only that file, then `repair` |
| `codex_home_unsafe` | The home is not owner-only, local, or symlink-free. | Fix permissions, then `repair` |
| `codex_home_missing` | The home and its sign-in are gone. | `setup` |
| `codex_runtime_capability_evidence_stale` | The reviewed evidence expired. | Upgrade Yoetz |
| `codex_runtime_platform_unsupported` | The evaluator does not run on this platform. | `rollback` |
| `codex_runtime_binding_invalid` / `codex_runtime_unavailable` | Malformed binding / unreadable state. | `setup` / `runtime status` |

Only `ready` means structurally usable, and it is reported only when the launch fence agrees. A
`ready` binding that still points at a host installation reports `next_command: repair` as advice,
with no blocker.

The executable tokens cover both retained files. The separate `code_mode_host` field names which
one failed: `admitted`, `missing`, `changed`, `invalid` or `unreadable`. It appears on
`runtime status` (`binding.code_mode_host`, `binding.code_mode_host_path`) and `provider status`
(`external_runtime.code_mode_host`).

`runtime status` (`yoetz.codex-evaluator-runtime-status/2`) lists every retained release in
`retained_runtimes` with its `runtime_version`, `path`, `code_mode_host_path`, recorded
`executable_sha256` and `code_mode_host_sha256`, and a `state`: `verified` (both files match a
current record), `unchecked` (retained, no current record yet), `incomplete` (host absent),
`changed`, `invalid` or `unsafe`. It also reports the `runtime_floor` and `capability_profile`.
`codex-subscription status`, setup and repair report `code_mode_host_path` and the record's
`code_mode_host_sha256`.

### Host and platform coverage (#855)

The retained runtime belongs to the shared provider, so Codex, Claude Code, and Cursor all use the
same commands and `/provider` / prompt-menu entries; no host-specific step exists. The unit and
integration tests use synthetic bytes with stubbed check subprocesses. The real capability check
has run unauthenticated on macOS arm64 against 0.157.1, 0.159.0 and 0.162.1 (see *Protocol review
and evidence*). Native acceptance is still pending for native Linux, WSL2, a packaged installed
wheel, the npm download against a live registry, a live repair of a real pinned-cell binding, and a
post-repair AI-powered check. Record those before claiming release support.

## Isolation contract

Each dispatch launches one process group with the bound, capability-checked executable,
`--strict-config`, the
digest-bound config, and repeated critical deny overrides. The environment allowlist contains only
the dedicated `CODEX_HOME`, fixed locale, fixed system `PATH`, and bounded Rust log level; API-key
and proxy variables do not cross. Analytics and OTel are off.

Before task bytes cross stdin, Yoetz initializes app-server v2, requires a ChatGPT account,
requires the exact model/reasoning cell from `model/list`, and starts an ephemeral thread in a new
empty owner-private cwd. The returned cwd, model/provider, read-only/no-network sandbox posture,
empty instruction-source list, and absence of a persisted thread path must match. The exact
approved case then enters only as `turn/start` text with the digest-bound Codex projection of the
frozen judgment schema. Codex rejects JSON Schema's `uniqueItems` keyword, so that is
the only omitted provider-side constraint; Yoetz's unchanged local normalizer still enforces every
uniqueness rule before accepting a judgment. Any child tool request, tool item, unknown event,
invalid/truncated/refused completion, or configuration mismatch fails closed. Codex tags each
agent message with a phase: `commentary` messages are interim narration and `partial_answer`
messages (0.162.1 and later) are unfinished answer text; both are discarded unread. Only
`final_answer` messages are judgment candidates, and exactly one must remain
(untagged messages from legacy models fall back to the same one-message rule). Informational
notifications — thread naming, moderation metadata, safety buffering, deprecation and
configuration notices, queue and compaction state, plan updates — and the model's own `plan` and
`contextCompaction` items are validated for method/type only and discarded; none of their bodies
is retained. A `model/rerouted` notice ends the turn as `refused`, because the bound model did not
produce the answer. The post-acknowledgement event budget is 4096 notifications, each bounded to
1 MiB, so a content-rich streamed judgment is not mistaken for an unbounded stream. Prompt wording
is not treated as the isolation boundary.

This is application confinement, not a general OS sandbox claim. The capability check proves the
pre-disclosure postconditions for each admitted release, and every attempt proves them again; a
release that cannot prove them is not admitted, and one that later breaks them fails closed.

## Privacy and receipts

The same ADR-009 classifier, minimizer, never-send scanner, composed repository authority,
optional per-request approval, one-use authorization, and terminal receipt govern this route. A
strict MCP route, unapproved repository, missing login, missing model, changed binary/config, or
a release that fails the capability check produces zero task-content disclosure.

`semantic_provenance.runtime_evidence` records only exact digests and bounded structural facts:
the bound Codex release (`runtime_version`), its executable SHA-256, the capability profile and the
capability-record digest (`capability_cell_sha256`) are provenance of which checked bytes ran. It
never retains email, token, credential path, raw account/workspace identity, prompt, reasoning,
stderr, or event log. `disclosed_case_sha256` is the case Yoetz passed to Codex, not Codex's
upstream request. The explicit `upstream_body_observability=unavailable` field is mandatory. When
Codex emits `thread/tokenUsage/updated` for the active thread and turn, current runtime evidence
retains one cumulative total snapshot with the non-overlapping input/output/total counters, cached
input and reasoning-output subsets, and cache-write input as a separate provider counter.
Repeated snapshots replace one another; they are never summed. Missing or unrelated usage stays
absent, while malformed or regressing
matching counters record `token_usage_invalid` without changing an otherwise valid judgment.

Before `turn/start` acknowledgement, a transient may consume a fresh authorization and capped
retry. After acknowledgement, ambiguous transport or unverified process-group cleanup is terminal
`unavailable/outcome_unknown`; do not retry it. Success requires schema-valid output and verified
group disappearance before the terminal receipt.

Structural readiness, privacy authority, and live dispatch remain separate claims. `status` can show
the exact binding, dedicated-home readiness, account mode, or model availability without authorizing
disclosure. The machine privacy ceiling and exact repository grant independently permit or refuse a
case. Only an admitted `evaluate()` child with an AI-powered review attempt and terminal receipt
proves that task bytes were dispatched; login success, model listing, or `semantic_ready: true`
alone never does.

## Diagnosing a failed attempt

`semantic_status` / `semantic_reason` stay the closed public pair. The exact stage is
`semantic_provenance.runtime_evidence.failure_stage` in the receipt JSON, and the service writes
the same token as an owner-only diagnostic line (`semantic_composition` /
`semantic_provider_attempt_invalid`). Stages are registered literals, never provider text:

| Stage | Meaning | Retry posture |
|---|---|---|
| `capability_evidence_stale`, `launch_failed`, `initialize_invalid`, `login_required`, `model_unavailable`, `thread_invalid`, `predisclosure_event_forbidden` | Failed before the case crossed stdin. | Ordinary pre-disclosure transient/unsupported handling; nothing was disclosed. |
| `turn_ack_invalid`, `tool_request_forbidden`, `event_forbidden`, `tool_event_forbidden` | The child broke the isolation contract. | Terminal, unavailable/unsupported profile, never an invalid model answer. A repeated forbidden event means the cell no longer matches Codex behavior: file it, do not widen the allowlist locally. |
| `rate_limits_invalid` | Unrecognized bounded rate-limit bookkeeping. | Before disclosure: terminal unsupported profile. After acknowledgement: nonterminal diagnostic, including on an otherwise successful result; a later terminal stage replaces it. No account fields are retained. |
| `token_usage_invalid` | A matching active-turn usage snapshot was malformed or regressed. | Nonterminal telemetry gap; preserve any earlier valid cumulative snapshot and never invalidate the AI-powered judgment solely for usage bookkeeping. |
| `turn_failed`, `model_rerouted` | Codex reported an authoritative native error or a different bound model. | Usage exhaustion maps to `provider_quota_exhausted`; HTTP 429 maps to `provider_rate_limited`. Only an independently authorized fallback may handle those reasons. Model rerouting remains terminal authorization refusal. |
| `agent_message_count`, `output_empty`, `output_oversize`, `completion_mismatch` | The completion did not yield exactly one bounded, correlated final answer. `output_oversize` also covers a usage snapshot whose visible output tokens exceeded the check's output limit; the turn is interrupted when that happens. | Terminal answer/completion validation (`response_schema_invalid`). Never retried and never a fallback trigger. Raise the profile's `*_output_limit` if valid judgments hit it. |
| `output_not_json` | The final answer was not strict JSON (prose, fenced code, trailing text). | Terminal; not retried. |
| `judgment_envelope_invalid`, `judgment_enum_invalid`, `judgment_refs_duplicate`, `judgment_refs_invalid`, `judgment_conclusion_mismatch`, `judgment_text_bounds`, `judgment_shape_invalid`, `judgment_invariant_invalid` | Strict JSON that failed the frozen judgment contract at the named stage. | Terminal (`response_schema_invalid`); asking again is not a fix. `judgment_refs_invalid` is the model citing an item id instead of a `citable_refs` entry. |
| `request_failed`, `transport_failed`, `deadline_expired`, `cleanup_unconfirmed`, `event_limit`, `runtime_warning`, `unclassified` | Runtime transport, deadline, event-budget, warning, or cleanup ambiguity. | Per ADR-006: pre-acknowledgement transients may retry; post-acknowledgement ambiguity is `outcome_unknown` and is not retried. No invalid-answer classification. |

`semantic_case_content_over_item_limit` is a separate coverage gap on the disclosed case; it is
reported alongside a stage, never inferred from one. `semantic_case_finding_refs_over_limit` is the
same kind of case-composition gap: a local finding cited more than 16 subjects, so its prose and
projected assessment were omitted from the case while the review still dispatched. It is decided
by the service before any evaluator runs, so it applies identically to every host and evaluator,
and it is never a `coordinator_failure`.

## Packaged live-evidence checklist

Use an exact packaged Yoetz build and an isolated logged-in evaluator home. Record these as
separate claims:

1. two `semantic_required` checks complete with distinct AI-powered review attempts, one-use
   authorizations, process groups, runtime evidence, and terminal privacy receipts;
2. the judgments validate against the frozen schema and any corrective finding is handled through
   the normal `respond`/`publish_work`/recheck loop;
3. another unapproved repository and a strict host route launch no child and disclose nothing;
4. logged-out home, incompatible binary, unavailable model/reasoning, modified config, hostile
   project instructions, same-name binary, API/proxy environment, and attempted tool events fail
   before disclosure or record the exact bounded post-disclosure failure;
5. browser and device login timeout, cancellation, malformed completion, process exit, and
   configuration-write failure leave no partial Yoetz binding while process groups and pipes are
   cleaned up within their bounds;
6. disconnect and rollback leave unrelated Codex installations, homes, settings, and sessions
   byte-unchanged.

Do not call login, a model listing, unit tests, or one clean judgment proof of this checklist.

## Long semantic reviews on 0.3

New subscription bindings use a 15-minute review budget. Set `external_runtime.timeout_seconds`
explicitly to select 1–3600 seconds; existing explicit values are preserved. This is the total
review execution budget, not the browser/device login timeout or a host tool's wait timeout.
Retries and recovery do not restart it. No extra retries are enabled.

One check may run up to three more reviews (issue #1047): when the reviewer concludes
`insufficient_packet` naming recorded run output, an exact command or a captured edit the packet had
no room for, the service sends the case again with that content first. Each such round is its own
job with its own attempt budget and its own `timeout_seconds` deadline, under the endpoint and
budget profile frozen with the check's first review job; it is never sent when it would add nothing
new. Count them when planning subscription usage. `status view=operation` reports the live round's
progress, and each round leaves one `semantic_review_follow_up` diagnostic record (round, items,
refs added, parts added) under the check's request ID.

A host tool wait may finish before the review. Keep the same check request and request ID: while
the service-owned check runs, replay reports pending; after completion it recovers the recorded
result. A host disconnect does not cancel an admitted review. Explicit control cancellation while
attached or `yoetz service stop` stops the owned execution; service stop affects the selected
installation, including its other active work. The maintenance gate can delay ordinary status
reads during review; `status view=operation` for the running check is the one read admitted
beside it. Parallel review scheduling remains separate work.

### Structural progress phases (#571 A2)

`status view=operation` with the check's request ID reports `semantic_progress` for the running
or finished review. For this runtime the phases map to native steps as follows:

| Phase | Reported when |
| --- | --- |
| `queued` | the service claims a physical attempt (ordinal increments on retry) |
| `case_admitted` | the privacy audit consumes the egress authorization, before launch |
| `runtime_starting` | before the isolated app-server child is launched and initialized |
| `account_model_validation` | after `initialized`, before `account/read`, `model/list`, `thread/start` |
| `provider_sampling` | after `turn/start` is acknowledged `inProgress` |
| `response_validation` | when `turn/completed` arrives, before the judgment is parsed and recorded |
| `cleanup` | before the interrupt (on failure) and process-group cleanup, on every launched path |
| `terminal` | derived from the terminal job row, with its outcome and reason |

A launch or pre-sampling failure goes straight to `cleanup`, so `status` distinguishes a stalled
start from a long sampling turn. Token-usage, rate-limit, delta, plan, and commentary notifications
do not produce phases and nothing from them is recorded. `overdue` means the frozen deadline passed
without a terminal row; replay the same check request to reclaim and terminalize it. To diagnose a
failed attempt, keep using `yoetz service diagnostics --request-id req_…` for failure stages;
progress is the live view, not the failure record.

## Routine and final review budgets (#571 item A1)

Each check selects one budget profile from its frozen case. A check whose frontier carries an
effective completion claim, or a check requested with `final_review: true` (the closing review,
issue #976), is `final`; every other check is `routine`. The profile is frozen with the job, so
retries, a disclosure-wait resume, recovery and in-check follow-up rounds all dispatch with the
same effort and output limit.

| Profile | Effort key | Output limit key | New-binding default |
| --- | --- | --- | --- |
| `final` | `reasoning_effort` | `final_output_limit` | `high`, 8192 tokens |
| `routine` | `routine_reasoning_effort` | `routine_output_limit` | `medium`, 4096 tokens |

- **Legacy bindings.** A binding written before this change has no `routine_reasoning_effort`,
  so routine checks keep its single effort. Status reports this as `effort_source:
  legacy_single_effort`.
- **Changing effort.** Re-running setup keeps existing final and routine choices. Pass
  `--reasoning-effort` or `--routine-reasoning-effort` to change the corresponding choice. Repair
  preserves both efforts, both output limits, timeout and retries. Setup and status require the exact model to list
  every configured effort; one attempt requires only its selected effort.
- **Output limits** count output tokens (1–8192) and are edited in `[external_runtime]`.
  Re-running setup carries them over. The app-server protocol has no per-turn output ceiling,
  so Yoetz compares each `thread/tokenUsage/updated` snapshot's visible output
  (`output_tokens − reasoning_output_tokens`) with the selected limit and interrupts the turn as
  `output_oversize` when it is exceeded. When Codex reports no usage, the limit is recorded but
  not measured.
- **Provenance.** `runtime_evidence.reasoning_effort`, `sampling_params.max_output_tokens`, and
  `semantic_provenance.model` name the exact selection per check, and `selection_sha256`
  commits to it together with the profile name. Receipts, `yoetz provider status`,
  `yoetz provider codex-subscription status`, and `/provider` in the terminal interface show
  both profiles.
- **Comparing final-review effort (issue #1051).** To run final reviews at a higher effort while
  routine checkpoints stay as they are, re-run
  `yoetz provider codex-subscription setup --reasoning-effort xhigh` (the routine choice and
  everything else are preserved; setup refuses an effort the model does not list). Each recorded
  check then carries what served it: `semantic_provenance.model`,
  `semantic_provenance.runtime_evidence.reasoning_effort`, and the phase in
  `review_input_manifest.review_phase` (`routine` or `final`), so the two arms can be compared from
  `check_recorded` rows alone. A different *model* for final reviews only is not configurable: the
  approved review channel authorizes exact destinations (provider, model and endpoint; one primary
  and at most one fallback), so a second model needs its own owner-approved destination, a privacy
  consent change that has not been made. A comparison that also moves routine reviews to the other
  model can run as two separately configured installations; a final-only model switch cannot.

No disclosure, retention, deadline, retry, or fallback rule changes with the profile. The only
per-request choice is `final_review: true`; otherwise a check reaches the final profile through a
completion claim.
Per-profile latency, output size, judgment validity, and cleanup on an installed Luna cell have
not been benchmarked here; that needs an authorized live run.
