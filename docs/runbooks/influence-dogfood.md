# Influence dogfood runbook

This runbook governs sessions that measure whether FinishUP **changed the agent's work product**, not
merely whether FinishUP was healthy, authorable, or able to emit feedback. Its purpose is to force four
questions to be answered **separately**, so a zero-influence run with a healthy service and an honest
receipt is never summarized as “FinishUP improved the agent.”

It exists because of the 2026-08-03 codex-testing postmortem (a private drafting input under the
gitignored `docs/postmortems/`, not shipped; this runbook is self-contained without it), which
recorded operational health and receipt honesty while demonstrating little attributable work
revision. The postmortem's P1.6–P1.8 remediation items (policy-enabled qualitative route, seeded
defect, intervention timing) are the experiment contract this runbook operationalizes.

AI-powered review eligibility and the provenance gate stay in the [AI-powered review dogfood
runbook](semantic-dogfood.md) (#132). This runbook **consumes** that profile and gate; it does not
redefine them.

For the 0.2 multi-round workflow and recovery follow-up, use
[native guidance-use acceptance](native-guidance-acceptance.md). It adds fresh/stale-memory variants,
feedback scope, evidence reuse, repair qualification, safe recovery, and final-receipt agreement to
each named host cell while keeping package delivery separate from actual guidance use.

**Issue:** [#133](https://github.com/TheGaySupreme123/finishup/issues/133).  
**Design gate:** docs/test-only evaluation protocol — no public runtime behavior change.  
**Out of scope here:** product fixes owned by #128–#132 (schema authorability, nested errors,
undeclared scope, evidence provenance, AI-powered review route preflight).

---

## 1. Purpose and non-conflation rules

Record and score these as **independent** claims. Do not collapse them into one “FinishUP helped”
sentence.

| Claim class | Must not be inferred from |
|---|---|
| Operational health | Tool listing, registration alone, or a successful dry-run |
| Authoring / corrective UX | Service uptime without first-call success or public repair |
| AI-powered review quality | A strict route that never attempted review; availability without a scored attempt |
| Work-product influence | Receipt wording, honesty-only rewrites, registration, or zero findings |

Hard rules:

1. **Registration / tool listing is never activation or influence.** A registered MCP entry or a
   successful `tools/list` says what the host *could* launch, not that the agent used FinishUP, that a
   model was shown anything, or that any work changed.
2. **Operational health ≠ authoring UX ≠ AI-powered review quality ≠ work-product influence.** Score
   each stream on its own evidence. A pass on A does not raise D.
3. **Receipt-wording changes are honesty influence (Stream A / integrity), never Stream D.**
   Softening a conclusion to match weakest coverage is integrity success, not proof the
   implementation improved.
4. **Strict-route runs mark Stream C AI-powered review quality `not_tested` (privacy pass), never
   “poor AI-powered feedback.”** The route declined to attempt review; that is not a measurement of
   review quality. See [AI-powered review dogfood](semantic-dogfood.md) Profile A and §3 provenance
   gate.
5. **A zero-influence run with healthy service and honest receipt must not be summarized as “FinishUP
   improved the agent.”** Enforce the forbidden-summary check in §5.

Closed vocabulary for stream scores (use only these tokens):

| Token | Meaning |
|---|---|
| `pass` | Evidence supports success for that stream's question |
| `fail` | Evidence shows the stream's question was answerable and failed |
| `not_demonstrated` | No positive evidence of success (default for Stream D without attribution) |
| `not_tested` | Configuration or design made the question unanswerable (e.g. Stream C on strict) |
| `indeterminate` | Attempt happened but outcome cannot be scored honestly |

For Stream D work-product influence specifically, prefer `demonstrated` | `not_demonstrated` on the
boolean metric `work_product_influence`, and keep stream score aligned (`pass` only when
`demonstrated`).

---

## 2. Four evidence streams (required report sections)

Every influence dogfood report **must** contain four separately scored sections. Do not merge scores.

| Stream | Question | Counts as success only when… |
|---|---|---|
| **A Operational health** | Was FinishUP healthy? | Service completed intended ops honestly: listing/registration posture recorded, six tools visible when expected, start/attach, write accept/reject, dry-run non-evidential, status/check/receipt, latency/errors within experiment bounds |
| **B Authoring / corrective UX** | Could the agent use it efficiently? | First-call success where required, rejection rate (excluding resource reads), identical structural retries bounded, source-inspection detours recorded, repair from **public** feedback alone, time-to-valid-plan / first obligation |
| **C AI-powered review availability & quality** | Did the reviewer produce valid feedback? | **Only when** the [provenance gate](semantic-dogfood.md#3-the-provenance-gate) says an attempt happened: eligibility/preflight, dispatch + status/reason, packet coverage, finding specificity/actionability, FP/miss |
| **D Agent influence** | Did that feedback **materially improve** the work? | Attributable work-product revision bound to a FinishUP output (finding, status frontier, or local check outcome), with before→after action + evidence + recheck — or explicit `not_demonstrated` |

### Stream A detail

Record that the service did what the experiment asked without lying about coverage. Typical
checklist: attach/start, publication accept and reject paths exercised as designed, dry-run not
treated as evidence, status/check/receipt available, structural errors and latencies noted.
Registration alone does **not** pass Stream A as “agent used FinishUP”; it only establishes that a
route *could* exist.

### Stream B detail

Authoring UX is about the public surface (descriptors, examples, rejection messages), not about the
agent reading product source. Count resource reads separately from write rejections. Identical
retries on the same structural error are a UX failure signal. Time-to-valid-plan and
time-to-first-obligation are primary timing metrics (see §4).

### Stream C detail

Follow the AI-powered review dogfood profiles:

- **Profile A (strict):** Stream C = `not_tested`. Do not score quality.
- **Profile B (policy):** Stream C is eligible only after the provenance gate allows scoring. A
  `blocked_by_policy` / null provenance result is not a quality failure.

### Stream D detail

Work-product influence requires a **causal attribution record** (§3 step 5). Without it, Stream D is
`not_demonstrated` even if findings exist. Findings the agent ignored are Stream D
`not_demonstrated` with miss class `agent_response_miss` when a seeded defect was in play.
Honesty-only receipt rewrites never promote Stream D.

---

## 3. Experiment design (must-do steps)

Execute in order. If a step fails, record the failure class and continue only if the remaining
streams remain answerable; do not reframe the run to claim Stream D success after an early gate fail.

### 3.1 Control or recording-only arm

Where feasible, run a **control** (no FinishUP, or FinishUP recording-only without mid-work checks) on the
same seeded task. If a control is not run, state that limitation explicitly in the report metrics
(`control_run: not_run`) and do not invent incremental cost/time deltas.

### 3.2 Seed one known qualitative defect

Seed **one** known qualitative defect **unknown to the working agent**. Examples (from the
postmortem / issue):

- uncovered UI string or evidence source kind;
- claim broader than tests support;
- open obligation left undeclared when a coherent outcome needs one.

Record the seed id and intended miss class if not remediated. Do not use an uncontrolled historical
task as the sole basis for causal certainty.

### 3.3 Early structured publication gate (before first source edit)

Before the first source edit of the work product under test, require:

1. a **valid plan**;
2. **≥1 bounded obligation per coherent outcome**, **or** a typed `no_obligations_reason` (product
   already supports `no_obligations_declared` + typed empty-scope reasons — the protocol must *use*
   it, not re-implement it);
3. requested items + evidence expectations;
4. experiment profile + AI-powered review eligibility (link the [AI-powered review
   dogfood](semantic-dogfood.md) preflight and profile A/B).

If authoring prevents this gate → record **`authoring_early_publication_gate: failed`** (Stream B
fail contribution). **Do not** silently switch to end-of-task publication and still claim Stream D
success. End-of-task-only publication may still inform Streams A/C and honesty, but Stream D remains
`not_demonstrated` for “mid-work assistance” claims unless the run **explicitly** declares a
terminal-review-only design (§3.4).

Boolean metric (required): `plan_and_obligation_before_first_source_edit: true | false`.

### 3.4 Meaningful mid-work check

While revision is still possible, run at least one check (unless the run **explicitly** tests
terminal-review-only). Record check timing relative to first source edit and first attributable
revision. Terminal-review-only runs must say so in established facts; they may score honesty and
late findings but cannot claim mid-work Stream D assistance.

### 3.5 Causal attribution record (per claimed influence)

For **each** claimed work-product influence, record:

| Field | Content |
|---|---|
| `finishup_output_ref` | Finding id, status frontier, check id, or other bounded token (no freeform transcript) |
| `agent_decision_before` | Closed token or short enum of the pre-finding state (e.g. `no_revision_planned`) |
| `bounded_action_after` | What changed (obligation respond, source revision, evidence republish) |
| `new_evidence_ref` | Digest-bound evidence id if any |
| `counterfactual` | `would_have_happened_without_finishup`: `yes` \| `no` \| `uncertain` |
| `recheck_result` | `passed` \| `failed` \| `not_run` \| `not_applicable` |

Without this record, do not mark `work_product_influence: demonstrated`.

### 3.6 Miss taxonomy (mandatory when seeded defect not remediated by influence)

When the seeded defect is **not** remediated via attributable FinishUP influence, classify exactly one:

| Class | Meaning |
|---|---|
| `case_construction_miss` | Defect absent from the published/selected case (experiment built the wrong case) |
| `checker_or_reviewer_miss` | Defect present in the case, but no rule/finding surfaced it |
| `agent_response_miss` | Valid finding existed; agent ignored it |

Do not invent other miss classes in shared reports. If the defect **was** remediated with attribution
and recheck, record `seeded_defect_outcome: remediated` and leave miss class null/omitted.

---

## 4. Required metrics (closed fields)

Reproduce metrics from **bounded artifacts only**: operation results, status snapshots, finding ids,
digests, enums, integers, booleans. **No** full transcripts, prompts, secrets, absolute paths,
usernames, machine identifiers, or unredacted provider payloads.

Include at least:

| Field | Type / notes |
|---|---|
| `op_counts` | Per-op integers (`start`, `publish_work`, `check`, `respond`, `status`, `receipt`, …) |
| `resource_read_count` | Integer; exclude from rejection rate denominator |
| `write_rejection_rate` | Rational or pair `(rejects, write_attempts)` excluding resource reads |
| `identical_structural_retries` | Integer |
| `wall_ms_start_to_valid_plan` | Integer ms or `null` if never |
| `wall_ms_start_to_first_obligation` | Integer ms or `null` |
| `wall_ms_start_to_first_evidence` | Integer ms or `null` |
| `wall_ms_start_to_first_check` | Integer ms or `null` |
| `wall_ms_start_to_first_finding` | Integer ms or `null` |
| `wall_ms_start_to_first_attributable_revision` | Integer ms or `null` |
| `wall_ms_start_to_receipt` | Integer ms or `null` |
| `plan_and_obligation_before_first_source_edit` | Boolean |
| `authoring_early_publication_gate` | `passed` \| `failed` \| `not_applicable` |
| `findings_deterministic_count` | Integer |
| `findings_semantic_count` | Integer (score only if Stream C eligible) |
| `findings_accepted` / `disputed` / `ignored` / `false_positive` | Integers |
| `material_revisions_attributable_to_finishup` | Integer |
| `material_revisions_rechecked` | Integer |
| `seeded_defect_outcome` | `remediated` \| `missed` \| `not_seeded` |
| `seeded_defect_miss_class` | Miss taxonomy token or `null` |
| `receipt_conclusion` | Bounded token from receipt |
| `weakest_coverage` | Bounded coverage token |
| `control_run` | `run` \| `not_run` |
| `incremental_wall_ms_vs_control` | Integer or `null` if control not run |
| `incremental_tool_calls_vs_control` | Integer or `null` if control not run |
| `work_product_influence` | `demonstrated` \| `not_demonstrated` |
| `honesty_influence` | `yes` \| `no` |
| `stream_a` … `stream_d` | Closed stream score tokens from §1 |
| `experiment_profile` | `strict` \| `policy` (AI-powered review dogfood Profile A/B) |
| `semantic_scoring_eligible` | Boolean from provenance gate |
| `activation` | `none` \| `tools_listed` \| `registered_only` \| `session_ops` — registration/list alone is not session use |

---

## 5. Report template

Required final report shape:

```text
1. Established facts
2. Inferences
3. Unresolved hypotheses
4. Stream A…D scores (separate)
5. Forbidden summary check: if Stream D = not_demonstrated (or work_product_influence =
   not_demonstrated), final prose must not say FinishUP improved work quality / agent quality /
   implementation quality
```

### 5.1 Section rules

1. **Established facts** — only what bounded artifacts support (ops, timings, findings counts,
   gate outcomes, attribution records present/absent).
2. **Inferences** — labeled as such; never presented as facts.
3. **Unresolved hypotheses** — including counterfactuals left `uncertain`.
4. **Stream scores** — four lines or a four-row table; no combined “overall success” that hides D.
5. **Forbidden summary check** — boolean `forbidden_summary_violation`. Set `true` if final prose
   claims work-product improvement while `work_product_influence` is `not_demonstrated`. A
   violation fails the dogfood report even when Streams A–C pass.

### 5.2 Privacy hygiene

Copy the AI-powered review dogfood report hygiene (§5 there). A dogfood report is shared material.
It carries:

- credential state as **presence only** (`connected` / `not stored` / `unknown`) — never a value,
  prefix, length, or any property of the stored secret;
- no absolute paths, usernames, or machine identifiers;
- no transcripts;
- no unredacted provider request or response payloads;
- versions, bounded status/reason tokens, digests, and structural state only.

---

## 6. Relationship to AI-powered review dogfood

| AI-powered review profile | Stream C | Stream D |
|---|---|---|
| **A — strict / local-only** | `not_tested` (privacy pass; never “poor”) | May still score from **local** findings, status frontiers, and closure — never from AI-powered review |
| **B — policy-enabled** | Eligible only after provenance gate | May cite AI-powered findings only when the gate allows scoring those findings |

Influence dogfood always runs the AI-powered review preflight when Stream C or a Stream D that cites
AI-powered findings is in scope. For strict Profile A runs that only care about local-check
influence, still record `experiment_profile: strict` and `stream_c: not_tested`.

Retained negative-control shape (historical reference task
`019fc915-a0bd-7803-b5d9-d8cbb9c65981`): start early, plan after first edit, zero obligations,
terminal-only completion graph, zero local findings, AI-powered review blocked by strict route,
honesty-only final wording — Stream D `not_demonstrated`, Stream C `not_tested`, forbidden summary
if prose claims improvement.

---

## 7. Explicit non-goals

- No protocol field, ADR, privacy, storage, or MCP surface changes in the name of this protocol.
- No requirement that every task use FinishUP.
- No live dogfood execution required to merge the protocol (operator live run is optional follow-up).
- No claim of causal certainty from one uncontrolled historical postmortem.
- Do not re-implement #128–#132 product work under this runbook.

---

## See also

- [AI-powered review dogfood runbook](semantic-dogfood.md) — profiles A/B, preflight, provenance
  gate.
- [Codex integration runbook](codex-integration.md) — skill install, MCP registration, route profile.
- [Privacy and AI-powered review](../usage/privacy-and-semantic-review.md) — durable policy that
  authorizes disclosure.
- The 2026-08-03 codex-testing postmortem — root evidence and the P1.6–P1.8 remediation items —
  is a private drafting input under the gitignored `docs/postmortems/` and is not shipped; the
  experiment contract above restates everything this runbook needs from it.
