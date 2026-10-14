# Privacy setup and policy-change contract

This page freezes the experience and security contract for creating or widening Yoetz privacy
policy, independent of any one graphical toolkit. The v0.1 CLI trusted-control flow satisfies this
contract today; a future desktop UI must present the same questions, examples, preview, and
confirmation semantics — it cannot hide, merge, or weaken a question, and Yoetz (not the rendering
surface) always validates and commits policy.

## Setup session shape

A setup session exposes closed actions `begin`, `answer`, `review`, `propose`, `tighten`, and
`cancel`, moving through closed states `recipe`, `network`, `local_models`, `provider`,
`review_context`, `categories`, `agent_context_categories`, `local_model_categories`,
`request_confirmation`, `channel_consents`, `scope`, `review`, `decision_required`, `complete`, and
`cancelled`.

The current contract version also reports the service-bound repository-backed workspace scope,
composed policy, authority digest, repository grant state, and bounded legacy-migration state. These
are service-derived session facts, not answers supplied by the renderer.

## The thirteen settings

These thirteen settings are the complete configurable surface. The `question_id` token and answer
type are protocol, not UI copy — a future UI localizes labels but cannot rename or reshape them.

They are **settings, not a mandatory question sequence.** Accepting the recommendation or choosing
a named recipe fills all thirteen from that recipe without asking; only `custom` presents them for
editing, and then in the five grouped sections below rather than as a flat list. What a surface may
never do is commit a value the user did not see: every path renders the exact resulting boundary
before proposing.

| # | `question_id` | Meaning | Answer type |
|---:|---|---|---|
| 1 | `network_egress` | Global ceiling: whether any Yoetz network egress may be permitted at all | boolean |
| 2 | `local_models` | Whether local models are permitted | boolean |
| 3 | `external_provider` | Which external provider/model/endpoint profile is trusted, and whether current data-use evidence is required | `{binding, require_current_provider_data_use_evidence}` or `none` |
| 4 | `review_context` | Which deterministic selection strategy builds AI-powered review cases | `{profile, selection}` |
| 5 | `content_categories` | Which categories/classes may be sent to the external LLM binding | `{categories, data_classes}` |
| 6 | `agent_context_categories` | Which categories/classes results may release to an agent-capable host, for material that host did not author | `{categories, data_classes}` |
| 7 | `local_model_categories` | Which categories/classes the selected local model runtime may receive | `{categories, data_classes}` |
| 8 | `request_confirmation` | Whether every external LLM request needs preview/confirmation | boolean |
| 9 | `product_telemetry` | Whether product telemetry is permitted | boolean |
| 10 | `crash_diagnostics` | Whether crash diagnostics are permitted | boolean |
| 11 | `update_checks` | Whether update checks are permitted | boolean |
| 12 | `capability_testing` | Whether capability testing is permitted | boolean |
| 13 | `authorization_scope` | Machine ceiling, exact repository-backed workspace, task, or this request | full-ancestor-chain scope |

The setup UI never accepts a credential, key, recovery secret, provider token, or vault passphrase.

### The five custom sections

`custom` — and only `custom` — presents the settings for editing, grouped so a person can hold the
decision in mind. Every section is announced even when its questions do not apply, so a section
that is skipped reads as "off" rather than as hidden:

| # | Section | Settings |
|---:|---|---|
| 1 | External and local destinations | `network_egress`, `external_provider`, `local_models` |
| 2 | What an external reviewer may see | `review_context`, `content_categories` |
| 3 | Local visibility: agent host and local model | `agent_context_categories`, `local_model_categories` |
| 4 | Per-request confirmation and authorization scope | `request_confirmation`, `authorization_scope` |
| 5 | Package updates and unsupported channels | `update_checks` (yes/no, default yes); `product_telemetry`, `crash_diagnostics`, `capability_testing` (read-only off) |

Section 5 asks a real yes/no for **package update checks** (default yes): structural PyPI package
identity only, no task/user content. Product telemetry, crash diagnostics, and capability testing
remain **read-only unsupported/off** — no transport ships for them, and `propose` still rejects a
`true` value for those three with `channel_unavailable`.

The enclosing first-run setup may ask that update-check question before selecting a recommended or
named recipe. Its explicit boolean replaces only the recipe's `update_checks` answer before the
exact candidate is rendered; `None` preserves the recipe default, and `custom` continues to own its
section-5 question. This is input to the existing preview/proposal/decision path, never authority or
a way to bypass confirmation.

The pre-policy zero-egress statement is limited to a fresh, unconfigured installation before its
first policy commit. Rerunning setup does not suspend, narrow, or revoke the currently committed
policy; ordinary service activity continues under that authority until the trusted decision
ceremony commits a replacement.

## Recipes are transparent drafts, never consent

The five convenience labels — Private, Metadata only, Assisted review, Expanded review, and Custom
— map exactly to protocol `recipe_hint` tokens `private`, `metadata_only`, `assisted_review`,
`expanded_review`, and `custom`. Every surface uses these exact names; a graphical or terminal UI
may not rename them, because a policy with two names is a policy a user cannot reason about. A
named recipe materializes directly into the exact draft and goes to review — it does not open
field-level configuration. **Selecting a recipe never commits a widening, provisions a credential,
or skips the review/decision step.**

### The one recommendation rule

First run, `yoetz --privacy`, and the terminal interface's `/privacy` all apply the same rule, from
one function:

- **No external provider binding configured → `private`.** External LLM egress stays off.
- **Exact route has current evidence of no default training and retention no longer than 30 days
  → `assisted_review`.** The reviewed draft is exact-repository-scoped and does not require a
  prompt for each ordinary request after the trusted widening ceremony commits it.
- **Unknown, stale, account-unqualified, or router-unconstrained provider posture → `private`.**
  The user may still choose Assisted once, but the exact review shows the unfavorable or unknown
  facts and that the runtime evidence guard is off; no reviewed-provider assurance is displayed.

The recommendation is rendered first, as an exact draft, with both what it buys and what it costs.
Accepting it goes straight to proposal and asks nothing further. Declining it opens the recipe list,
positioned on the declined recommendation. Credential possession is never disclosure consent.

A surface must not offer the recommendation as a change when the current policy already matches it.

### The fail-safe default draft

With no answers, the draft is `local_only`, `review_context=structural`, `network_egress=false`, all
five network channels disabled, no local model, no external or local-model content categories, and
`agent_context_categories={categories:[bounded_structural_metadata, declared_file_type],
data_classes:[public_structural]}`. Under this default, an unwidened agent still receives its own
published prose and the local findings computed solely from it — withholding a writer's own
words protects nothing and would break the `check → respond → recheck` loop. What the default
withholds is exactly what the agent did not author: another writer's or subagent's material,
imported events, and AI-powered reviewer prose, plus every `sensitive_confidential` item and the
entire never-send set, which no provenance ever unlocks. The owner's own view is the separate
`local_human_view` sink and is not gated by question 6 at all. Since ADR-009 round 3 a terminal no
longer selects it (an agent's pseudo-terminal passes every terminal test); only the reauthenticated
`owner_receipt_view` grant does.

### The recommended `assisted_review` recipe

Deliberately different from the default: `PrivacyProfile=trusted_provider`,
`ReviewContextProfile=assisted`, exact repository scope, `request_confirmation=false`,
`include_finding_prose=true`, `include_exact_command_text=false`,
`require_current_provider_data_use_evidence=true`, data classes
`public_structural|ordinary_user_content`, and the canonical `assisted` external category set
(bounded structural metadata, declared file type, task description, claim text, obligation text,
decision excerpt, evidence excerpt, finding summary, command metadata, diff metadata, repository
excerpt). It excludes `sensitive_confidential`, transcript excerpts, broad source selection, and
exact command text; it keeps the v0.1 16 KiB/item and 256 KiB/case hard caps. It is displayed as
recommended only for an exact installed endpoint whose current, versioned data-use record states
training `prohibited` and retention `none|bounded` with a ceiling of at most 30 days. Provider human
access and safety, legal, support, and abuse-monitoring exceptions remain prominent disclosure
facts. Unknown or stale posture removes the badge; a user can still pick Assisted or configure the
route through `custom`, but the UI must not carry the recommendation's claim into that policy.

### Agent-guided AI-powered review intent

The general first-run recommendation above optimizes for disclosure minimization. A conversational
agent has an additional explicit signal: when the current user says the desired outcome is
AI-powered review depth, it recommends `expanded_review` first and explains `assisted_review` as the
lower-disclosure AI-powered review option. That recommendation is advisory and does not prepare or
approve a grant. The agent explains all named recipes, records the user's selection, prepares one
exact combined candidate, renders the complete substantive before/after diff, and asks for one final
approve/deny decision bound to that candidate.

An authority-capable agent may relay that exact current-chat decision. Preparation freezes the
current and candidate policy bytes and binds the repository commitment, authority generation,
provider/model/endpoint, recipe, policy and diff digests, target, and expiry. A different repository,
policy generation, configured route, target, expired action, replay, or unsupported host cannot
reuse it. A host without the declared chat-authority capability gives the shortest trusted-local
continuation without substituting another recipe or provider.

Existing approved machine-policy bytes are never rewritten by this recommendation or by package
upgrade. An existing
`confirm_every_request` user receives an explicit Assisted offer and keeps the current policy until
the complete trusted before-to-after widening ceremony is approved.

An upgrade may automatically clone previously accepted machine authority beneath an eligible
pre-upgrade repository route, consuming one bounded entitlement, or use one first-repository
carry-forward when no such route existed. The machine row remains byte-identical and later
repositories inherit nothing, so this is narrowing and requires no reapproval. Grant and migration
state remain visible in setup.

Router profiles whose downstream provider and fallback set are not represented in the binding are
not exact standing grants. They remain available only with per-request confirmation; Assisted or
Expanded standing authority fails closed until the binding constrains that set and receipts report
the actual selected provider route.

## What each question governs

Question 1 maps to the global `network_egress_permitted` ceiling: `false` forces all five channels
denied; `true` enables none by itself and only unlocks later channel-specific choices. Choosing
network egress is not consent to a provider, channel, or content class; choosing a provider is not
consent to telemetry, diagnostics, updates, or capability testing.

Question 4 chooses only the context-selection *strategy*, granting no category, class, scope, or
sink by itself. `assisted` may select only problem-local excerpts already captured or
agent-published at the frozen frontier — v0.1 has no live Git or filesystem browser, and the review
shows `not_recorded` rather than implying missing code was inspected.

Question 5 governs external-LLM content only. Questions 6 and 7 are **independent** local-disclosure
ceilings — authorizing content for an external provider does not authorize an MCP host or a local
model, and vice versa; `local_model_categories` must stay empty while local models are off.

For questions 5–7, an item is allowed only when **both** its category and its data class are
selected. `data_classes` may contain only `public_structural`, `ordinary_user_content`, and
`sensitive_confidential` — `secret_or_cryptographic` is never selectable at all.
`sensitive_confidential` is off by default, shown as its own high-impact widening, and requires
strong reauthentication; selecting a category alone never silently authorizes its sensitive
instances.

Settings 9–12 are the four non-LLM channels. **`update_checks` (setting 11) is a real yes/no**
(product default yes) for structural package version checks only. The other three
(`product_telemetry`, `crash_diagnostics`, `capability_testing`) remain read-only `unsupported`
and off: `propose` rejects a `true` answer for those three with `channel_unavailable` without
changing durable policy or making any I/O. A later Yoetz release cannot silently activate an old
stored draft or answer for those capabilities — it always requires a fresh local-human capability
confirmation first.

## Review, propose, and commit

`review` displays the machine ceiling, bound repository grant, effective destination, purpose,
scope, categories, and every channel independently, the review-context profile and its exact
compiled selector, the recipe expansion, the editable data-use runtime guard, the endpoint's
data-use profile ID/version/evidence digest, whether
per-request preview applies, the complete non-overridable never-send set, and a semantic diff from
the current policy. Widening is visually highlighted and **cannot commit through `review` alone.**

`tighten` commits immediately after the ordinary explicit confirmation, but only when the service
independently proves every policy dimension is no broader than the current one. `propose` never
commits a widening by itself: loosening any dimension returns `decision_required` with a
`privacy_proposal_id`, an exact draft digest, the current authority digest, an expiry, and — when an
external provider is selected — the exact reviewed data-use profile ID/version/evidence digest. A
separate foreground human-control surface then confidentially renders the pending proposal,
reauthenticates the local human, and commits internally; the ordinary setup schema itself has no
decide/confirm method, and no MCP, agent, import, or provider schema can reach that authority.

A new-repository proposal may contain two members: widening the machine ceiling when necessary and
inserting the first exact repository row. One preview shows both and one authority-digest-bound CAS
commits both or neither. Older setup/propose decoders remain readable, but cannot create or migrate a
repository grant and fail closed with upgrade guidance under repository-grant mode.

**That trusted-terminal ceremony is the default authorization for a widening, and the allowlisted
`yoetz consent` lane described above is its only exception.** No other surface may take its own
approval for one first. A selecting surface may show a proposal or hand one over, but a second "do
you approve?" outside the trusted terminal is not a second gate — it only teaches users that
consenting in an untrusted surface is what changes privacy. The consent lane is not that second
gate: it is one exact prepared, expiring, single-use target whose complete substantive diff is
rendered before the one decision, and the catalog states that Yoetz cannot independently
authenticate the relayed chat provenance.

What the ceremony renders is the **complete substantive diff**, as `before → after` steps derived
from the same comparison that classified the proposal as a widening, so a recognized widening cannot
reach approval without appearing on screen. Simultaneous tightenings are shown too, marked as not
widening, because the human is deciding about the whole change and not its worst half. Labels are
fixed by the trusted client; the service transmits structured field/value records and never
explanatory prose a proposal author could write. The diff digest is displayed as integrity evidence
and explicitly labelled as not being the description of the change. See
[`../INTERFACES.md`](../INTERFACES.md) for the exact `PrivacyPolicyChange` shape and its bounds.

For `confirm_every_request`, the same renderer shows the exact post-minimization, post-redaction,
post-secret-scan excerpts immediately before every dispatch. Approval binds one physical dispatch of
the outbound-case digest; every retry — even of identical bytes — needs a fresh preview and
decision, while resume before authorization consumption continues the same dispatch rather than
creating a new one.

After a standing policy like `assisted_review` is committed once, ordinary checks, automatic
retries inside that policy, reviewer challenges, and agent responses/rechecks proceed without a
human prompt. Each physical attempt still gets its own fresh one-use authorization and receipt.
Human presence remains required only for policy widening, credential mutation, an explicit
`confirm_every_request` attempt, or a finding waiver. Never-send and out-of-scope material cannot be
approved under any profile.

Provider-credential setup separately asks whether to authorize one `credential-probe` request after
the secret is stored. The privacy draft names that purpose alongside `semantic-review`; declining
leaves it out, so the egress gateway blocks verification rather than treating external-review
consent as an implicit probe grant. The probe body is a fixed bounded structural literal, never the
credential or task content, and its authorized/blocked/attempted outcome is receipted through the
ordinary egress path.

## Errors and edge cases

- Closing, disconnecting, or crashing before `review`/`tighten`/decision commits nothing.
- A missing trusted locator leaves repository authority unbound; public `workspace_ref` is never a
  fallback.
- A locked service may show status and confidential-unlock guidance but cannot expose policy
  content that requires decrypted state, and never accepts an ordinary-channel secret.
- An unavailable provider profile is selectable only as an explanatory `unsupported` value — never
  committable as ready.
- Headless setup may use the trusted local control protocol, never an ordinary flag, environment
  variable, config secret, MCP tool, or stdin stream shared with an agent.
- `network_egress=false` with any enabled channel is an invalid draft; `network_egress=true` with
  every channel disabled is valid and performs no network work at all.
- A proposed enabled non-LLM row always renders `unsupported in v0.1` and cannot commit.

## See also

- [`data-egress-and-privacy.md`](data-egress-and-privacy.md) — the enforced policy/dispatch
  protocol this wizard configures.
- [`../../PRIVACY.md`](../../PRIVACY.md) — the user-facing privacy summary.
- the versioned `schemas/privacy/setup-wizard-contract-*.schema.json` set — the wire schemas for
  this contract; older decoders remain fail-closed for repository authority.
- `yoetz privacy setup` / `yoetz privacy show` / `yoetz privacy propose` / `yoetz privacy tighten`
  — the v0.1 CLI surface implementing this contract.
