# AI-powered review dogfood runbook

This runbook governs sessions that use FinishUP on FinishUP and then report a finding about it. Its
purpose is to fix, **before** the first task action, which claim the run is allowed to make — so a
result is never read as evidence for a question the run's configuration made unanswerable.

It exists because of the 2026-08-03 codex-testing postmortem (a private drafting input under the
gitignored `docs/postmortems/`, not shipped; this runbook is self-contained without it), which
scored "did AI-powered feedback help?" against a session whose MCP route was `strict`. FinishUP
behaved correctly and reported honestly — `semantic_status=blocked_by_policy`,
`semantic_reason=route_semantic_ceiling`, `semantic_provenance: null`, zero egress. The run simply
could never have measured AI-powered review usefulness. Nothing in the tooling said so in advance.

Three facts this runbook keeps apart:

- **Registration is not activation.** A registered MCP entry says what Codex would launch, not that
  it launched or that a model was shown anything.
- **Availability is not usefulness.** A route that *can* dispatch AI-powered review is not evidence
  that the review helped.
- **A clean AI-powered judgment is not proof the implementation is correct.**

## 1. Pick the profile before you start

Choose one profile and record it. Do not switch profiles mid-run; a run that changes route posture
partway through has no single claim it can make.

### Profile A — strict / local-only

**Preconditions:** `mcp_route.observed == true` **and** `registered_profile == "strict"`.

Both halves are required. An unread route (`observed: false`) reports `registered_profile: null`,
which is *unknown*, not *strict* — it is no basis for a zero-egress claim. Observation is also what
separates a strict route from `absent` or `foreign_present`, which report `registered_profile: null`
with `observed: true` and are likewise not Profile A.

Claims this run may make:

- zero external AI-powered review egress through the FinishUP agent route
- local-check behaviour
- receipt honesty — that the refusal is recorded with the exact status/reason and no promoted
  local-check outcome

Claims this run may **not** make: anything about AI-powered review quality, usefulness, or
influence. Record AI-powered review usefulness as **not tested**. Never record it as "poor", "weak",
or "absent" — the route declined to attempt it, which is not a measurement of it.

### Profile B — policy-enabled

**Preconditions, all three:**

1. `registered_profile == "policy"`
2. `agent_route_semantic_ready == true`
3. human authorization obtained through the existing ceremony — either the API credential
   ceremony (`finishup provider credential set`) or the Codex-managed subscription setup — with the
   privacy policy already in place before the run starts

Claims this run may make: everything in Profile A, plus observations about AI-powered output,
subject to the provenance gate in §3.

Explicitly: previewing a registration change from inside the session is allowed
(`finishup integrate codex mcp preview`). **Widening privacy policy from the agent channel is not.**
Policy widening is a human ceremony; if a run finds it needs wider policy, the run stops and is
re-planned, it does not widen and continue.

## 2. Preflight sequence

For Codex runs launched from a disposable worktree, first complete the stricter [Codex dogfood
parity preflight](codex-dogfood.md). Its exact-worktree activation, consent, host delivery,
observation, and rollback cells are not implied by the five AI-powered review checks below.

Run all five before the first task action and record the output verbatim. Every command here is
read-only and already exists — this runbook adds no command.

```text
finishup version
finishup service status
finishup provider status --json
finishup integrate codex mcp status --json
finishup privacy show
```

Fields to record from `finishup provider status --json`:

| Field | What it settles |
|---|---|
| `semantic_ready` | Whether **this installation** can dispatch AI-powered review at all. Installation-local; unchanged by route posture. |
| `mcp_route.registered_profile` | Which route the Codex agent actually gets: `policy`, `strict`, or `null` when unread. |
| `mcp_route.configured_profile` | Which route setup would register now. |
| `mcp_route.observed` | `false` means the route could not be read — **not** that none is registered. |
| `agent_route_semantic_ready` | Whether the **registered Codex route** can dispatch AI-powered review. This is the field that selects the profile. |
| `endpoint.role`, `fallback_endpoint` | Which bound endpoint is the primary and whether a fallback is declared (issue #582). `fallback_endpoint` absent means a single-endpoint install; when present, record both identities (provider, model, endpoint profile) — a later `fallback_from` in provenance must match. |
| `fallback_credential_connected` | Presence-only credential state of the fallback (`true` / `false` / `null` when unknown), mirrored by the `fallback_provider_credential` blocker. It never moves `semantic_ready`: a primary can be ready while its fallback is not, and vice versa. |

`registered_profile != configured_profile` is registration drift: the registered entry no longer
matches what this installation's configuration would produce. Record it and resolve it before
starting, through a fresh digest-bound re-registration — `finishup integrate codex mcp preview`, then
`finishup integrate codex mcp install --accept --preview-digest <digest>` (ADR-018 decision 7). Do not
assume the configured value is what the agent will get.

A second, independent drift signal compares the live registration against the last applied
install rather than current configuration (issue #537). `finishup provider status --json`
`mcp_route` carries `applied_profile` (the route the installer last applied, from the
state-root record) and `drift_since_install` (true when the live observed registration
disagrees with it). Record both at preflight alongside the table above. A ceiling check served
while the Codex applied record says `policy` additionally carries the
`optional_semantic_review_registration_drift` coverage gap only when the serving command declares
`--host codex`. Its receipt names the recovery: re-run `mcp preview` / `mcp install --route-profile
policy` and start a fresh Codex process. Generic, Claude, and Cursor serving identities cannot be
attributed to the Codex applied-route record, so their strict ceiling remains the terminal result
without this drift gap. The MCP bridge emits a closed `registration_drift` hook diagnostic under
the `mcp_serve` event only for explicit Codex identity when the route it starts on disagrees with
the applied record, so read `hook_diagnostics.reasons` there too — a drift that appears mid-session
invalidates the profile the run declared in §1. The hook events themselves emit nothing here: they
have no serving route to compare, and probing the host from a hook costs more than the hook budget
allows.

`mcp_route.observed: false` is disqualifying for **both** profiles. An unread route is not a policy
route, and it is not a strict route either — it is no route at all until it is read.

`finishup integrate codex mcp status --json` reports `route_profile` alongside `registered_profile`,
`applied_profile`, and `drift_since_install` for the same reason, and is the narrower check when
you only need the route and its post-install drift.

### Pairing a fallback endpoint

Since issue #582 the two external authorities — an API provider and the Codex ChatGPT
subscription evaluator — may be bound together as one primary plus exactly one fallback. The
commands below mutate configuration and policy; run them before the five read-only checks, never
mid-run, and treat the policy step as the human ceremony it is.

Subscription primary, API provider as fallback:

```text
finishup provider codex-subscription setup --executable /absolute/path/to/codex   # if not bound yet
finishup provider endpoint --provider <preset> --model <model-id> --as-fallback
finishup provider credential set                                                 # fallback's API key
finishup privacy setup                                                           # approve both destinations
```

API provider primary, subscription as fallback:

```text
finishup provider endpoint --provider <preset> --model <model-id>                # if not bound yet
finishup provider credential set
finishup provider codex-subscription setup --executable /absolute/path/to/codex --as-fallback
finishup privacy setup                                                           # approve both destinations
```

`--as-fallback` refuses (`semantic_fallback_endpoint_missing`) unless the other authority is
already bound; without the flag the ordinary single-endpoint rule replaces the existing binding.
The result reports `endpoint_role`, and `config.toml` gains a nonsecret `[semantic_fallback]`
table whose `primary` is `codex_subscription` or `api_provider`. Two API providers cannot pair.

Binding the fallback does not authorize it. `finishup privacy setup` reads both endpoints and prints
the second as `Fallback destination (after the primary cannot serve)`; committing it is a
widening of exactly one more destination, shown in the trusted `before -> after` view as
`Fallback provider and model` right after the primary row, and goes through the ordinary
propose → decide ceremony. Until that decision, egress admits the primary only. Record the
committed `finishup privacy show` output at preflight so a fallback-served attempt can be matched
against the approved set.

Reverse and swap:

```text
finishup provider fallback remove                       # primary keeps serving alone
finishup provider fallback primary api_provider          # or codex_subscription: swap roles, both kept
finishup provider codex-subscription disconnect --accept # inside a pairing: API provider becomes sole endpoint
```

`fallback remove` restores the exact single-endpoint `config.toml`; the policy still names the
removed destination until `finishup privacy setup` is re-run, which is a tightening and needs no
widening ceremony. A swap keeps both bindings and both approvals.

What engages the fallback is closed and service-side, identical on every host: the primary is
abandoned only after two `provider_timeout` / `transport_unavailable` / `provider_rate_limited`
failures, one `provider_quota_exhausted`, an exhausted primary retry budget, or a primary that
could not be resolved before dispatch (`credential_unavailable`). Content-shaped outcomes
(`response_content_invalid`, `response_schema_invalid`, `refused`,
`semantic_judgment_rejected`), policy or human outcomes, and `outcome_unknown` stay with the
primary. Each endpoint keeps its own retry budget and timeout, and each fallback attempt is a
fresh physical attempt with its own authorization and privacy receipt — under
`confirm_every_request` that means its own foreground decision.

**Caveat (issue #584).** A Codex subscription quota exhaustion is currently mis-parsed as
`invalid/response_schema_invalid`, which is content-shaped and never licenses the fallback. Until
#584 is fixed, a subscription primary that runs out of quota does **not** hand the case to its
API-provider fallback; record such a run as a primary failure with no fallback attempt, not as a
fallback defect.

## 3. The provenance gate

Whether a run may score AI-powered review usefulness is derived from the check result, never
asserted from configuration. The rule is protocol-enforced by `validate_semantic_provenance_binding`
(`src/finishup/protocol/models.py`) and its totality is locked by test.

**Read provenance together with `semantic_status` and `semantic_reason` — never alone.** Null
provenance means *no provider attempt was made* only on the branches where the protocol forbids
provenance (rows 1 and 3 below). `failed` is unconstrained: it may carry provenance or not, and
either way the attempt is indeterminate. Nor does the converse hold — provenance being *present*
proves an attempt happened, not that it was useful.

| `semantic_status` | `semantic_provenance` | May score AI-powered review usefulness |
|---|---|---|
| any pre-dispatch status — `not_requested`, `not_configured`, `blocked_by_policy` (incl. `route_semantic_ceiling`), `blocked_forbidden_data`, `classification_uncertain`, `awaiting_human`, `human_denied`, `approval_expired` | `null` (enforced) | **No** — not attempted |
| `succeeded`, `refused`, `timeout`, `invalid`, `late`, `stale`; or `unavailable` with `transport_unavailable` / `provider_rate_limited` / `provider_quota_exhausted` / `outcome_unknown` | present (enforced) | Yes; `outcome_unknown` proves an acknowledged attempt, not its outcome or usefulness |
| `unavailable` with `credential_unavailable`, `endpoint_profile_unavailable`, `retry_budget_exhausted`, `audit_reservation_unavailable`, `receipt_persistence_unknown` | `null` (enforced) | **No** — not attempted |
| `failed` / `coordinator_failure` | either — unconstrained | **No** — attempt indeterminate |
| any row above whose attempt the **declared fallback** served | present, with `fallback_from` naming the primary's provider/endpoint/model, its `attempted_count` before engagement, and its closed `reason`; the top-level provider/model/endpoint name the fallback | Same as the row it lands in, scored **against the endpoint that served**. Record the primary's `fallback_from.reason` as a separate primary-failure cell, never as the fallback's outcome |

`failed` is the one status where provenance presence proves nothing in either direction. Record it
as **attempt indeterminate**, never as "not attempted".

With a declared fallback (issue #582), `fallback_from` on the provenance is what says the
fallback served; its absence on a present provenance means the primary served, whatever the
pairing. Match the top-level identity against the `fallback_endpoint` recorded at preflight and
the approved policy before scoring, and report the run as two cells — the primary's closed
failure and the fallback's outcome. A fallback-served `succeeded` proves an attempt at the
fallback, not that the primary's failure reason was correctly classified (see the #584 caveat in
§2). The JSON receipt carries the same `fallback_from`; the markdown and text receipts name the
endpoint that served and the primary's closed failure reason.

Read the gate off the result, not off preflight. Passing preflight makes an attempt *possible*; only
the result says whether one *happened*.

## 4. What passing preflight does not prove

- It does not prove an AI-powered review ran. That is the gate in §3.
- It does not prove the review was useful. Availability is not usefulness.
- It does not prove the implementation under review is correct. A clean AI-powered judgment is one
  observation, not a verdict.
- It does not measure whether feedback changed the agent's behaviour. Influence measurement is
  governed by the [influence dogfood runbook](influence-dogfood.md) (issue
  [#133](https://github.com/TheGaySupreme123/finishup/issues/133)): four separate evidence streams,
  seeded-defect and miss taxonomy, and a forbidden-summary rule so zero influence cannot be sold as
  improvement.

## 5. Report hygiene

A dogfood report is shared material. It carries:

- credential state as **presence only** (`connected` / `not stored` / `unknown`) — never a value,
  prefix, length, or any property of the stored secret
- no absolute paths, usernames, or machine identifiers
- no transcripts
- no unredacted provider request or response payloads
- versions, bounded status/reason tokens, digests, and structural state

Report the declared profile, the preflight output, the resulting `semantic_status` /
`semantic_reason` / provenance presence, and the gate row those land in. State the claim the run was
authorized to make and stop there.

## See also

- [Codex dogfood parity](codex-dogfood.md) — exact-worktree preflight, postflight, and rollback.
- [Codex integration runbook](codex-integration.md) — installing the skill and registering MCP.
- [Privacy and AI-powered review](../usage/privacy-and-semantic-review.md) — the durable policy that
  authorizes disclosure.
- [Providers](../usage/providers.md) — the readiness conditions behind `semantic_ready`.
- [Codex subscription evaluator](codex-subscription-evaluator.md) — exact runtime cell, weaker
  observable boundary, negative controls, and packaged proof checklist.
- [ADR-018](../adr/ADR-018-host-declared-mcp-route-egress-ceiling.md) — why the strict route is a
  process-local ceiling and not a privacy policy.
- [Dogfood CI](dogfood-ci.md) — the unattended lane that records `semantic_status`, reason, and
  provenance presence per (host, OS) cell without scoring usefulness.
