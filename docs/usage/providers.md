# Providers and credentials

Binding a provider is nonsecret configuration. Provisioning a credential is a separate, deliberately
awkward ceremony. The two never mix.

## Reviewed presets

To inspect the reviewed providers and suggested models bundled in the installed package without
making a network request or changing configuration, run:

```text
finishup provider catalog --json
```

The catalog includes the custom-model escape hatch. Its entries are structural support, not proof
of account entitlement, configured readiness, or live provider interoperability.

```text
finishup provider endpoint --provider openai            # or: fireworks, anthropic, gemini,
                        --model <model-id>           #     openrouter, grok, vercel-ai-gateway
                                                    #     grok aliases: xai, x-ai
```

Shorthands: `--official`, `--fireworks`, and `--grok` (Grok / xAI).

The Grok / xAI preset binds xAI's OpenAI-compatible Chat Completions endpoint. xAI documents that
endpoint as legacy and says new features reach its Responses API first; it publishes no sunset
date. FinishUP keeps the preset on Chat Completions: the route is still documented and served, and it
is the route whose data-use posture FinishUP reviewed. Giving the preset a Responses route would
change the endpoint it binds, so that is a separate change with its own review — refreshing the
suggested models does not depend on it.

Reviewed presets use each provider's documented compatible wire style where applicable. **Every
reviewed preset resolves to a real runtime factory** — a preset you can select is a preset FinishUP can
dispatch.

That is not the same as verified. FinishUP does not advertise any non-official preset as a confirmed
working endpoint. A prior one-off Fireworks dogfood dispatch is useful provenance for that run but
does not close the release capability gate. That claim stays gated by the exact evidence described
in [ADR-006](../adr/ADR-006-semantic-provider-profile.md).

## Codex with a ChatGPT subscription

This is a different credential authority from every API provider above. Choose it in first-run
setup, the prompt-loop provider menu, `/provider`, or run:

```text
finishup provider codex-subscription setup --executable /absolute/path/to/codex
```

New setups suggest `gpt-6.1-sol` with reasoning effort `medium` for final reviews and `medium`
for routine checkpoints. The suggestion is bound only when the Codex that FinishUP runs lists
`gpt-6.1-sol` with those efforts. An older Codex such as `0.157.1` does not, so setup uses
`gpt-6-luna` instead and says so before the sign-in. A model you type yourself is never
substituted, and upgrading never changes the model an existing setup already uses. The
suggestion is checked against Codex's model list only; no authenticated AI-powered review with
`gpt-6.1-sol` has been recorded yet.

A check counts as final when your task has recorded a completion claim; every earlier check is a
routine checkpoint, which can use a lower effort than final reviews. Use
`--reasoning-effort` and `--routine-reasoning-effort` to choose each one. When an existing
subscription binding is targeted, omitting `--model` preserves its exact model. Omitting
`--reasoning-effort` and `--routine-reasoning-effort` preserves its final and routine choices,
including during account switching. A
binding created before routine checkpoints existed keeps using its single effort for every check
until you choose a routine effort. Pass `--model` to change the model intentionally.

Each profile also has an output limit in tokens: 4096 for routine checkpoints and 8192 for final
reviews, adjustable from 1 to 8192. A review whose answer exceeds its limit is stopped and
reported as an invalid answer, and it is not retried. The check result and receipt name the
exact model, reasoning effort, and output limit each review used.

The selected executable can be an npm wrapper with the matching native package nested below that
wrapper (`@openai/codex-darwin-arm64` on macOS arm64 or `@openai/codex-linux-x64` on Linux x86_64),
an npm-prefix wrapper with that same platform package hoisted beside the wrapper package in the
same prefix, or the exact native `codex` executable itself. FinishUP resolves only those bounded
locations derived from the selected path: it does not search PATH, unrelated prefixes, or arbitrary
parent directories. Every form still requires the supported platform, package version, native
executable, and exact SHA-256 digest; a direct native path does not bypass those checks.

Before opening a browser, FinishUP shows the resolved native executable and SHA-256 digest, Codex
version, dedicated evaluator home, model and reasoning effort, OpenAI destination, unknown
plan-specific data-use posture, privacy implications, and the reverse commands. After the explicit
confirmation, FinishUP first asks Codex whether that dedicated home is already signed in with the
selected model available; if it is, the binding is written without a new sign-in and the result
reports `login_reused: true`. Otherwise the confirmation starts Codex's documented browser login,
which may remain open for its full 600-second window. `--switch-account` always logs the
dedicated home out and signs in again. Add `--device-code --no-open-browser` to use Codex's
device-code flow instead; that flow may remain open for its full 900-second window. Cancellation
and timeout use bounded process-group, pipe, and task cleanup and return one closed diagnostic.
Codex owns the login, refresh, credential file, and logout; FinishUP neither receives nor stores the
OAuth credential.

A timeout, denial, malformed completion, process exit, cancellation, or later write failure never
persists a partial FinishUP binding. If Codex completed login before a later failure, Codex may retain
its own authentication in the dedicated home; that is separate from FinishUP configuration. Use
`disconnect` when you want Codex to log out, or `rollback` when you want to remove the FinishUP
binding while preserving the home and installation.

The exact evaluator cells are Codex npm `0.157.1-darwin-arm64` on macOS arm64 and
`0.157.1-linux-x64` on Linux x86_64. An x86_64 WSL2 Linux userspace follows the Linux cell when run
there, but WSL-specific smoke evidence remains pending. Both use capability
`codex-evaluator/0.157.1/v2`. FinishUP's own verified copy includes Codex's `codex-code-mode-host`
helper, which Codex needs beside its executable. A binding set up with Codex `0.150.1` reports
`codex_runtime_capability_unsupported`. A binding set up with the earlier `0.157.1` `v1` cell,
whose copy lacks the helper, reports `codex_runtime_executable_missing`. In both cases, run
`finishup provider codex-subscription repair` with a current Codex installed, or after
`finishup provider codex-subscription runtime install --download`. Your sign-in, model and settings
are kept.
The selected native binary digest, app-server v2 schema digest,
capability-cell identity digest and evidence expiry, strict configuration digest, model, reasoning
effort, and dedicated owner-private `CODEX_HOME` are bound in nonsecret config and rechecked before
every attempt. Expired capability evidence fails before a child starts. A shell alias, neighboring
version, moved binary, modified evaluator config, API key, proxy variable, or ambient Codex home is
not a fallback. Native Windows has no evaluator cell. The only fallback is an API provider you
explicitly pair with it (see
[Pairing a fallback endpoint](#pairing-a-fallback-endpoint)). Guided first-run, the prompt-loop
provider menu, and `/provider` can log out the
dedicated home first when you choose to switch ChatGPT accounts.

On Linux, Codex's read-only sandbox needs bubblewrap (`bwrap`) and unprivileged user
namespaces. A container or VM without them fails closed before any case is disclosed. Use an
environment that provides both and keep the sandbox checks enabled. See the
[evaluator runbook](../runbooks/codex-subscription-evaluator.md#linux-authenticated-smoke-evidence-2026-09-13)
for the current acceptance evidence and remaining release checks.

Read structural state without sending a task case:

```text
finishup provider codex-subscription status --json
```

It reports only runtime readiness, `chatgpt` auth mode, allowlisted plan type when Codex returns
one, exact model availability, and process cleanup. It discards account email. To reverse setup:

```text
finishup provider codex-subscription disconnect --accept  # Codex logout, then remove binding
finishup provider codex-subscription rollback             # remove binding; preserve home/install
```

### Keeping the evaluator working when Codex updates

Your everyday Codex can stay on any version. Setup keeps its own verified private copy of the one
Codex release the evaluator admits, in FinishUP's data directory, and binds that copy instead of your
Codex installation. Updating or replacing your everyday Codex therefore leaves AI-powered review
working. `--executable` is optional: setup uses FinishUP's copy first, then any installation that
already holds the admitted release. It never offers a newer Codex that the evaluator does not
admit. When nothing eligible is found, first-run setup and the prompt menu offer to download the
admitted release. The terminal interface's `/provider` shows the download command. You can also
run it yourself:

```text
finishup provider codex-subscription runtime status              # what is bound, and what to do next
finishup provider codex-subscription runtime install --download  # uses your npm; asks first
finishup provider codex-subscription runtime install --from /absolute/path/to/codex
finishup provider codex-subscription runtime remove              # only when no binding uses it
```

The download runs your own npm with install scripts disabled. FinishUP keeps only the executable whose
SHA-256 matches the reviewed evaluator and deletes the rest. It sends no task content, credential,
or account data, and it does not change your Codex installation, settings, or sign-ins.

If AI-powered review stops working after a Codex update or a FinishUP upgrade, `runtime status`,
`codex-subscription status`, and `finishup provider status` name the exact cause, for example
`codex_runtime_executable_changed` or `codex_runtime_profile_outdated`, and the command that fixes
it. For those, run:

```text
finishup provider codex-subscription repair
```

Repair shows what will change and asks first. It keeps your model, reasoning effort, timeout,
retries, dedicated home, fallback role, and privacy permissions. It reuses your existing ChatGPT
sign-in only when Codex reports the dedicated home still signed in; it never starts a new sign-in,
logs out, or switches accounts. If the home is not signed in, repair changes nothing and tells you
to run `setup`. Re-running `setup` also keeps an existing binding's timeout, retries, and reasoning
effort unless you pass new values.

When an attempt fails after the case was disclosed, the receipt keeps the closed
`semantic_status` / `semantic_reason` pair and adds `runtime_evidence.failure_stage`: one fixed
token such as `output_not_json`, `judgment_refs_duplicate`, `judgment_conclusion_mismatch`,
`agent_message_count`, or `event_limit`. It tells you where validation stopped without keeping
any of Codex's text. A `response_schema_invalid` result stays final and is not retried. One
stage, `token_usage_invalid`, can also appear on a successful review: Codex reported a token count
that was malformed or went backwards, so the receipt keeps the judgment and leaves usage unknown.

Setup, disconnect, and rollback recompose the local service afterwards. The subscription endpoint
has unknown data-use posture, so FinishUP does not mark it as the Assisted recommendation. You may
still explicitly approve a bounded external-review policy. Login, plan name, and model listing are
readiness facts collected by status or by the evaluate child—not privacy consent and not proof that
an AI-powered review turn ran. `semantic_ready: true` means the structural provider, machine-policy,
and repository conditions are present. Privacy authority is a separate disclosure gate, and live
AI-powered review dispatch is a separate runtime event evidenced by the check/evaluate result and
receipt. See the [exact evaluator runbook](../runbooks/codex-subscription-evaluator.md).

## Pairing a fallback endpoint

AI-powered review can bind one primary endpoint plus exactly one fallback. The pair is always the
two authorities above — an API provider and the Codex ChatGPT subscription — in either order;
two API providers cannot pair, and nothing becomes a fallback implicitly. The fallback serves only
after the primary could not: two timeouts, connection failures, or rate limits in a row, one quota
exhaustion, a used-up retry budget, or a primary whose credential is missing before the first
attempt. An answer the primary actually gave — malformed, refused, rejected, or ambiguous — stays
with the primary; a second provider is never asked to repair a content answer.

Subscription first, API provider as the fallback:

```text
finishup provider codex-subscription setup --executable /absolute/path/to/codex
finishup provider endpoint --provider anthropic --model <model-id> --as-fallback
finishup provider credential set
```

API provider first, subscription as the fallback:

```text
finishup provider endpoint --provider anthropic --model <model-id>
finishup provider credential set
finishup provider codex-subscription setup --executable /absolute/path/to/codex --as-fallback
```

`--as-fallback` requires the other authority to be bound already and reports `endpoint_role:
fallback`; without the flag, binding one authority replaces the other as before. The fallback needs
its own credential — the API key ceremony, or the digest-bound Codex login — and its own privacy
approval: run `finishup privacy setup` afterwards, which shows the second endpoint as `Fallback
destination (after the primary cannot serve)` and asks you to approve both destinations together.
Until you do, nothing is sent to the fallback. See [Privacy and AI-powered
review](privacy-and-semantic-review.md#what-the-trusted-approval-screen-shows).

To reverse or rearrange:

```text
finishup provider fallback remove                  # the primary keeps serving alone
finishup provider fallback primary api_provider     # or codex_subscription: swap roles, keep both
```

`fallback remove` restores the exact single-endpoint configuration; re-run `finishup privacy setup`
so the policy stops naming the removed destination — that is a tightening and asks for no
widening approval. `fallback primary` keeps both bindings and both approvals. Disconnecting the
subscription inside a pairing leaves the API provider as the sole endpoint.

Every fallback attempt is a fresh attempt with its own authorization and privacy receipt; under
Metadata only it needs its own foreground approval. Each endpoint keeps its own retry budget and
timeout. When the fallback served, the check result and receipt say so: the provider, model, and
endpoint name the fallback, and `fallback_from` names the primary, how many times it was tried,
and why it was given up — the markdown and text receipts say which endpoint served and why the
primary could not.

## Interactive model choices

On a local terminal, omit `--model` to choose from a short list or enter a custom ID:

```text
finishup provider endpoint --provider anthropic
finishup --set --provider anthropic
```

The endpoint menu, explicit interactive provider selectors, and secure `--set` paths share the same
picker for all seven reviewed presets. Choice 1 is the preset's existing default, preserving the
previous Enter-to-accept behavior. The remaining entries are a repository-reviewed sample of
recent provider-recommended/current model families, never more than ten total, followed by an
explicit **Custom model ID** option. No popularity ranking is claimed.

The catalog was reviewed on 2026-08-10 against the provider-owned model sources: OpenAI
[model guidance](https://developers.openai.com/api/docs/guides/latest-model), Fireworks
[Responses API documentation](https://docs.fireworks.ai/guides/response-api), Anthropic
[models overview](https://platform.claude.com/docs/en/about-claude/models/overview), Google
[latest Gemini models](https://ai.google.dev/gemini-api/docs/latest-model), OpenRouter's
[model catalog contract](https://openrouter.ai/docs/guides/overview/models), xAI's
[model list](https://docs.x.ai/developers/models), and Vercel's
[AI Gateway model catalog](https://vercel.com/ai-gateway/models).
The Grok / xAI entry was re-reviewed on 2026-09-17 against the same xAI model list: `grok-4.6` is
the model xAI now recommends, so it is the preset default and heads the list, and the older Grok
models stay listed while xAI lists them. The Grok entries inside the OpenRouter and Vercel AI
Gateway lists were re-reviewed against those gateways' own published catalogs on the same day and
follow the identifier each gateway publishes today, which is not always the identifier xAI uses.
The Fireworks list also retains `accounts/fireworks/models/minimax-m3`, which has prior
repository-recorded live AI-powered review provenance. The lists are static so setup stays repeatable
and opens no new network or credential channel; they can age, may not match account entitlements,
and do not establish FinishUP's exact structured-output compatibility. Use the custom entry for any
new, private, preview, region-specific, or omitted model.

Scripts remain explicit and noninteractive:

```text
finishup provider endpoint --provider anthropic --model claude-sonnet-5 --no-interactive
finishup --set --provider anthropic --model claude-sonnet-5
```

The first command writes only nonsecret configuration. The second still requires a local terminal
because it continues into hidden credential input; `--model` itself is preserved exactly in both.

## Owner-declared endpoints

For a proxy or self-hosted OpenAI-compatible endpoint
([ADR-014](../adr/ADR-014-toml-settings-and-owner-declared-endpoint.md)):

```text
finishup provider endpoint --https-origin https://llm.example.com:8443 --model my-proxy-model
```

`https://host[:port]` only — no path, no scheme substitution, no plaintext HTTP.

## `config.toml`

Both paths write the same file. It contains no secrets.

Reviewed preset:

```toml
schema_version = "1"
profile = "local-openai"

[provider]
provider_id = "openai"
endpoint_profile_id = "openai-responses"
endpoint_profile_version = "1.0.0"
model = "gpt-4.1-mini"
capability_profile = "openai-responses-structured-1"
```

Owner-declared HTTPS origin:

```toml
schema_version = "1"
profile = "local-openai"

[provider]
provider_id = "openai-compatible"
endpoint_profile_id = "owner-declared-openai-responses"
endpoint_profile_version = "1.0.0"
model = "my-proxy-model"
capability_profile = "openai-responses-structured-1"

[provider.owner_declared_endpoint]
https_origin = "https://llm.example.com:8443"
# no api_key / headers / path / http — credentials stay in the ceremony
```

Codex subscription binding (written by guided setup, not by hand):

```toml
schema_version = "1"
profile = "codex-subscription"

[external_runtime]
provider_id = "openai-codex"
endpoint_profile_id = "codex-chatgpt-subscription"
endpoint_profile_version = "1.0.0"
credential_authority = "external_runtime_oauth"
# exact executable/home paths, SHA-256 commitments, runtime/source/capability identities,
# model, reasoning effort, timeout, and retry cap follow; no OAuth value is valid here
# optional routine/final review budgets (output limits count tokens, 1-8192):
# routine_reasoning_effort = "medium"
# routine_output_limit = 4096
# final_output_limit = 8192
```

Primary/fallback pairing (issue #582): both tables above stay bound and a nonsecret selector names
which serves first — `api_provider` for `[provider]`, `codex_subscription` for
`[external_runtime]`. `profile` follows the primary.

```toml
schema_version = "1"
profile = "codex-subscription"

[semantic_fallback]
primary = "codex_subscription"   # [external_runtime] serves first; [provider] is the fallback

[provider]
# ... the API-provider binding as above

[external_runtime]
# ... the subscription binding as above
```

You can edit API-provider `config.toml` bindings by hand. `/provider` writes the same API binding
or drives the digest-checked Codex subscription setup, status, disconnect, rollback, and optional
account switch; it always shows the destination and privacy posture before asking for an API key or
opening Codex login. Storing either binding does not switch external review on. After a
subscription setup, disconnect, or rollback, FinishUP recomposes the local service so a running
daemon cannot keep dispatching the previous cell.

## Readiness (`finishup provider status`)

Before spending a run on AI-powered review, ask whether the six structural conditions hold:

```text
finishup provider status --json
```

The report names each condition and the exact next command when one is known to be unmet. Five are
**installation capability** conditions, a sixth is the exact current-repository grant, and a
separate verdict describes the Codex agent route.

1. the local service is running and unlocked
2. `verification.semantic` is not `disabled`
3. a provider endpoint is bound in `config.toml`
4. **the bound provider's** authority is connected: a matching vault API credential, or — for a
   Codex subscription — the exact digest-bound executable, isolated config, and dedicated home
5. the machine privacy ceiling enables the `llm_inference` channel
6. the repository derived from the trusted current session has an exact granted row beneath that
   ceiling

Condition 4 is per-provider and per-authority, not "any credential". If you rebind from one API
preset to another, the old vault credential does not carry over. If you switch to the subscription
profile, no vault credential carries over at all: READY composition treats the exact binding,
digest, and dedicated home as credential presence and does not spawn a Codex process to prove
login. ChatGPT `authMode` and the configured model/reasoning cell are proven later, inside the
same `evaluate()` child that will send the case, or by `finishup provider codex-subscription status`.
Failure stays `credential_unavailable`, never a misleading ready state.

Conditions 4 and 5 are independent. Closing only one moves the failure without making AI-powered
review work — the check reason changes, the outcome does not.

With a fallback paired, conditions 3 and 4 are about the primary: `endpoint` reports
`role: primary`, and the report adds `fallback_endpoint` plus `fallback_credential_connected`
with its own `fallback_provider_credential` blocker and next command. A missing fallback
credential never makes the primary not-ready, and `semantic_ready: true` says nothing about the
fallback — read its row separately. The fallback fields are absent on a single-endpoint install.

When the service is locked, credential and privacy state are `unknown`, not incomplete. Unknown
conditions have no remediation command. For `vault_mode=uninitialized`, continue with `finishup setup`;
for an existing locked vault, use `finishup service unlock`; and when the scoped platform entry is stale
or rejected, use `finishup service auto-unlock repair`. The JSON field `readiness_determinable`
distinguishes a known not-ready state from one that cannot yet be read.

`semantic_ready: true` means all six structural conditions hold for this repository-bound service
view. It does not prove live provider dispatch. `repository_grant_state` and
`repository_migration_state` expose the authority inputs separately; an omitted trusted locator
makes repository state unknown and readiness false rather than inheriting the machine ceiling.

### The agent route is a separate verdict

`semantic_ready` covers the six conditions above and nothing else. It says this repository-bound
service view has the provider, machine-ceiling, and exact repository authority needed for AI-powered
review. It does not say the Codex agent gets a route that will dispatch.

FinishUP registers Codex with one of two serve commands, and both classify as `yoetz_owned` — so
registration state alone cannot tell them apart. The report therefore names the route directly:

```json
"mcp_route": {
  "registration_state": "yoetz_owned",
  "registered_profile": "strict",
  "configured_profile": "policy",
  "applied_profile": "policy",
  "drift_since_install": true,
  "observed": true
},
"repository_grant_state": "granted",
"repository_migration_state": "not_applicable",
"agent_route_semantic_ready": false
```

- `registered_profile` — the observed FinishUP route: `policy`, `strict`, or `null`. **`null` has two
  different meanings**, and `registration_state` plus `observed` are what tell them apart: with
  `observed: true` it means no FinishUP route is registered (`registration_state` is `absent` or
  `foreign_present`); with `observed: false` it means the route could not be read. Do not read a
  missing or foreign registration as a probe failure.
- `configured_profile` — what setup would register now. A mismatch is registration drift. Fixing it
  takes both steps of the digest-bound ceremony: `finishup integrate codex mcp preview` produces the
  digest, then `finishup integrate codex mcp install --accept --preview-digest <digest>` applies it.
  Preview alone changes nothing.
- `applied_profile` — the route the last install applied, from the install record. `null` means
  there is no record: nothing was installed through the ceremony, the record was cleared by
  `mcp remove`, or it could not be read. An unreadable record is never reported as drift.
- `drift_since_install` — `true` only when the live registration disagrees with that install
  record. This is a second, independent drift from the one above: `registered_profile` versus
  `configured_profile` compares the registration against what setup would produce now
  (preflight drift — fix with the re-registration ceremony), while `drift_since_install`
  compares the live registration against what the last install applied (post-install drift —
  something changed the route after the install, so if that was not you, re-run the ceremony
  with the policy route and start a fresh session). A strict check served while the last
  install applied the policy route additionally names this in its receipt, with the same
  recovery offered as a conditional.
- `observed: false` — the route could not be read. That is *unknown*, not *absent*, and it is never
  reported as a blocker.
- `repository_grant_state` / `repository_migration_state` — the exact trusted-session repository
  authority inputs. Public `workspace_ref` never supplies them.
- `agent_route_semantic_ready` — `semantic_ready` **and** `registered_profile == "policy"`. An
  unread route therefore makes it `false`: `registered_profile` is `null`, so an unobserved route
  is never treated as a policy route.

**A strict registration does not make this repository-bound service view not-ready.** The strict
route is a
process-local ceiling (ADR-018): it stops that one MCP process from requesting AI-powered review. A
`finishup check` from the CLI, or a check from the terminal interface, still dispatches normally. So
`semantic_ready: true` alongside a strict route is not a contradiction — it means repository-bound
capability exists while that Codex agent route cannot dispatch. A strict route adds a
`mcp_route_profile` blocker marked `scope: "agent_route"`, and leaves the exit code alone.

Neither verdict substitutes for the other. Reading `semantic_ready: true` and expecting AI-powered
review through a strict agent route is exactly the conflation this field exists to prevent; see the
[AI-powered review dogfood runbook](../runbooks/semantic-dogfood.md) for the preflight that
consumes it.

### Where the route verdict is reported

Both verdicts and the repository-authority inputs appear wherever readiness is shown, never merged:

- `finishup provider status` (human and `--json`).
- The terminal interface's readiness layers, as a separate `Codex agent route permits deeper
  review` line beside `Privacy permits external review` and `Deeper review ready`. An unread
  registration or unbound repository renders as unknown rather than as inherited authority.
- `finishup privacy setup` and the terminal interface's `/privacy`: when a committed policy permits
  external review and the registered route is `strict`, the ceremony names the mismatch and the
  command that fixes it. That note is advisory — it never fails the ceremony, changes an exit
  code, or appears when the route cannot be read.

The last one exists because machine ceiling, repository grant, and registration are separate facts
changed by different transitions. Moving from local-only to assisted review with an older strict
registration in place produces a correct policy and a Codex session where every check returns
`blocked_by_policy` / `route_semantic_ceiling` — accurate, and impossible to act on without being
told which of the two is the cause.

The service derives repository identity from the client's actual/configured working directory,
resolves Git's common root, commits it under the installation key, and discards the raw path.
Branches and linked worktrees share a grant; independent clones do not. Upgrades preserve accepted
machine bytes and may only consume the bounded legacy carry-forward described in ADR-009. None of
these structural verdicts substitutes for the installed-wheel two-repository AI-powered review and
receipt proof still outstanding under issue #139.

## The credential ceremony

```text
finishup provider credential set
```

The API credential is provisioned through a confidential terminal ceremony and stored by the trusted
local service. It is **never** a command-line flag, a file path, an environment variable, a config
value, a log line, a trace, a transcript, or anything reachable from LLM context
([ADR-015](../adr/ADR-015-elevated-bootstrap-consent.md),
[ADR-016](../adr/ADR-016-human-review-non-default-actions.md)).

If you find yourself wanting to pass a key as a flag, that is the design working as intended.

`/provider` in the terminal interface uses this exact ceremony and has no credential path of its
own. It asks for explicit consent, then suspends the full-screen interface and hands the
controlling terminal to the ceremony, which opens `/dev/tty` and disables echo itself. No secret
byte enters the interface's state, transcript, logs, or any snapshot. Where an environment cannot
suspend, the interface says so and names this command rather than offering to take the key through
the window.

## Binding a provider does not enable egress

A bound provider plus a stored credential still sends nothing until privacy policy permits it. See
[Privacy and AI-powered review](privacy-and-semantic-review.md). Every network channel is
independently authorized.

**Configuration is also not readiness.** Storing a binding and a credential are two facts; a
working provider is a third, and it is only established by a successful probe. The terminal
interface reports them separately and always has:

```text
✓ Provider binding saved
✓ API key stored securely
! Live provider connection has not been tested
! External AI-powered review is not yet proven ready
```

This build exposes no bounded live provider probe from the local service, so a connection test in
the interface reports itself as unavailable rather than reporting a pass
([ADR-017](../adr/ADR-017-full-screen-terminal-interface.md), *Known limitations*). A provider
that fails never downgrades local-check readiness.

## Checking what you have

```text
finishup setup status        # read-only posture, mutates nothing
finishup service status      # is the service up, is the vault unlocked
finishup version --json      # installed package and runtime identity
```


## Background review frequency

Background AI-powered advice is **on by default** whenever AI-powered review is `optional` or
`required`. It reviews rule and coverage-gap codes between explicit checks. You can turn it off
below; your choice always wins over the default. To see whether it is on and why, run
`finishup provider status` (the `background_advice` line), `finishup setup status --next --operation
review`, or `/status` in the terminal interface (run `finishup` at a terminal).

Background AI-powered advice uses the routine review budget. With Codex, it uses your configured
routine effort, or `low` when none is set; API-key providers keep their normal (effort-free)
request, which is already capped at 2,048 output tokens. A review is reused while the set of
advice candidates and coverage gaps is unchanged, even as more evidence for them arrives. New
advice is reviewed at most once every three minutes per session by default; advice waiting for
that interval shows `advice_semantic_deferred` and is reviewed automatically when it elapses. A
failed or unavailable review is retried with backoff. Explicit checks continue to use their
normal review policy.

Background advice only runs when AI-powered review can actually reach your provider: a provider
is connected, your privacy policy allows the AI-powered review channel, the provider's
credential or sign-in is in place, and this repository has been granted AI-powered review for the
task with that exact provider and for review. Background advice uses only your primary endpoint; a
paired fallback serves explicit checks, never background advice, so a primary that cannot serve
pauses background advice even when the fallback could. Otherwise nothing is queued and nothing
leaves your machine;
advice shows `advice_semantic_unavailable` instead of `advice_semantic_pending`, and receipts no
longer say AI-powered advice is pending. Signing in or enabling the channel takes effect on the
next observation; connecting or disconnecting a provider takes effect when FinishUP restarts its
service, which setup does for you. Your coding session keeps running either way.

To turn background advice off, add `semantic_advice_enabled = false` to the existing
`[observation]` table in your FinishUP configuration:

```toml
[observation]
semantic_advice_enabled = false
semantic_advice_min_interval_seconds = 180
```

This stops background reviews while keeping local advice and explicit AI-powered checks
available. Set it to `true`, or remove the line to return to the default, to turn it back on.
FinishUP writes this line only when you choose it, so a later default change still reaches you
when you have not. Background reviews that were queued before advice was switched off are
discarded when the service starts, without being sent, so turning advice back on never sends old
work. Restart the FinishUP service after changing these settings. The interval accepts 1–86400 seconds. The same
settings work with Codex, Claude Code and Cursor on macOS, Linux and Windows through WSL 2.
