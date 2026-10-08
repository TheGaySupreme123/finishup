# Receipts and coverage

A receipt says what was checked and how well. It is deliberately narrow, and reading it correctly
matters more than any other single thing in Yoetz.

The agent-facing rules are [`guidance/coverage-and-receipts.md`](../../guidance/coverage-and-receipts.md),
which ships with the product. This page is the human's version.

## Coverage is a vector, not a score

Six independent dimensions. Strength in one never compensates for weakness in another, and they
never collapse into a number:

| Dimension | Asks |
|---|---|
| participation | How did the work reach the ledger? (`cooperative_mcp`, `local_cli`, `codex_jsonl_import`, …) |
| authorship | How well is the author established? (`self_asserted`, `harness_observed`, …) |
| artifact observation | Did anything observe the artifacts, or only the published claims? (`published_only`, `hook_observed`, …) |
| content visibility | How much content was actually looked at? (`none`, `digest_only`, `targeted_excerpt`, …) |
| provenance | Local check, AI-powered review provider, imported, or participant-asserted? |
| freshness | Is the evidence bound to the current state? (current, stale, unknown, redacted) |

**The weakest material dependency bounds the conclusion.** Use the exact enum values the protocol
returns.

## Getting one

```text
yoetz receipt --request '{"request_id":"req_...","format":"markdown", ...}' --json
```

Formats are `json`, `markdown`, and `text`. All three project under the default agent-context
policy. `json` carries the structured receipt in `document` with `human_text` null. `markdown`
and `text` keep `document` null by format and project the canonical sections (summary, findings,
limitations, versions, section items, and coverage notes) in `human_text`. If that projection
exceeds the wire bound, `human_text` carries an explicit truncation marker. Under a deliberately
stricter owner policy, digest-bound
`json` can fail closed with `PRIVACY_AUTHORITY_REQUIRED` (`receipt_json_projection_blocked`) —
re-request `markdown` or `text`, or widen agent-context policy from a local terminal. If a
human format cannot project those sections, the result names the omission; it does not return
an accepted receipt with an empty body and no pointer.

**The durable receipt is recorded even when projection is blocked.** A projection failure is a
disclosure decision, not a lost receipt.

## Reading one

Read these together, never in isolation: the frontier, the verdict, the coverage vector, the finding
disposition, evidence provenance, freshness, suppressed counts, and limitations. Derived Markdown is
a human view of the same structured record.

Honest:

> Yoetz found no local-check issue in the cooperatively published record at the stated frontier;
> artifact observation remained published-only.

Not honest:

> Yoetz proved the implementation is complete and correct.

## The trap: a clean local-only check

A clean `deterministic_only` check is **not** an implementation review. When mode is
`deterministic_only`, or AI-powered review status is `not_requested`, the coverage includes
`semantic_review_not_requested`. A clean result means “no issue detected within deterministic
coverage”; it does not remove that limitation from the receipt. Where AI-powered review is not
required (it is optional or off), the check records `semantic_route_required: false` and the
limitation is disclosed without keeping the receipt from a clean conclusion; where review is
required, it still keeps the receipt at `insufficient_coverage`. The receipt leads with its scope,
review status and material limitations, followed by the finding count and frozen check totals.

Omit `mode` to retain the configured verification default. Use `semantic_if_configured` only when
review is known to be optional. If the user, policy, or acceptance requires AI-powered review,
select `semantic_required` for the final check and subsequent final rechecks. Reserve
`deterministic_only` for explicitly local or structural checks, or a user-authorized deliberate
no-egress choice; disclose the limitation and keep any required review unmet.

When you fall back to `deterministic_only` because an AI-powered review attempt was blocked or
unavailable, that earlier gap is carried forward next to `semantic_review_not_requested`, so the
receipt records that the environment refused rather than that the review was never asked for.

## Prose the reviewer will not see whole

Publish accepts up to 8192 bytes of prose per field. One AI-powered review case item carries at most
4096 bytes. Text between those bounds records cleanly and then reaches the reviewer shortened — or,
for a whole event payload, replaced by a marker carrying only its digest. Coverage names this with
`semantic_case_content_over_item_limit`. Keep prose you expect a reviewer to read under 4096 bytes.

A local finding can name up to 64 subjects, but one review case item links at most 16. A wider
finding — typically `ledger_stale_or_incomplete` after many unresolved coverage gaps — stays in your
check result and receipt in full. The reviewer receives the other findings; this one is listed as
omitted rather than trimmed, and coverage names it with `semantic_case_finding_refs_over_limit`.
Resolving the underlying gaps narrows the finding and lets the next review carry it.

## Completion scope is declared, not inferred

Yoetz reads completion scope only from the effective plan chain. It never invents obligations from
the prompt, source tree, workspace, or completion prose.

When a completion claim exists and the effective plan has zero declared obligations, the check is
coverage-incomplete in both cases:

- no typed reason: `completion_scope_undeclared` — the receipt says scope was never declared;
- a typed reason: `completion_scope_declared_none` — the receipt says the plan declared none and
  names only the closed reason value.

The typed declaration clears the status readiness blocker; it does not buy a clean verdict. A
positive declared count whose obligations are all resolved is the distinct resolved-scope state.
Redacted or unreadable scope remains unknown and never becomes zero.

When a plan changes after an effective completion claim, the claim and the current plan are still
compared independently:

- `completion_claim_outside_plan` means the claim names an obligation the current plan no longer
  declares;
- `completion_plan_not_claimed` means the current plan declares an obligation the claim omits.

An explicit waiver removes an obligation from the current plan; it does not supersede or rewrite a
historical completion claim. The relation remains a coverage limitation until the claim is replaced
or the plan is deliberately restated to match the intended scope.

Two findings stop a completion from reading clean until the agent answers them:

- `task_requirement_unmet` — a task statement is recorded and the plan declares obligations, but
  none of them cites the statement, or the agent claims completion with no plan or an explicitly
  empty one. The agent decomposes your request into obligations that cite it, or, when your request
  needs no material work and nothing was edited, records that decision with a reason. Yoetz checks
  only that link, not that every requirement was captured. Repeating your unchanged request when a
  session resumes does not count as a new request.
- `claim_without_admissible_evidence` (observed-verification form) — the hooks saw the agent edit
  or run checks, but the completion claim cites no observed verification run after the last edit.
  The agent reruns its verification and cites that observed run.

Running the check again without changing the record returns the same finding. Neither finding
means the work is wrong, and clearing them does not prove it right.

## Candidate findings are not a check

`status` with `view=candidate_findings` is an advisory read. No verdict, no IDs, no receipt, and the
read records nothing. An empty list means no rule fired at that frontier — it is not
`no_issue_detected`.

Permitted after a candidate read: "I saw an unresolved attempt and went back to it."
Forbidden after a candidate read: "I checked and found nothing."

## Things that do not strengthen coverage

- Installing a harness integration.
- Firing a trigger-only hook. A proven trigger may prompt a bounded `status` re-grounding; it
  observes nothing and changes no coverage.
- Storing imported evidence. Imported evidence never gains cooperative authorship because Yoetz
  stored it.
- A digest. It records identity, not content inspection. A digest your agent publishes stays
  caller-asserted: it raises no finding, and the receipt's limitations say once, with a count,
  how many cited evidence items carry caller-asserted digests Yoetz did not verify, keeping
  digest-only items (the bytes were not retained) apart from withheld items (your agent recorded
  the bytes as withheld). No response, recheck, or further publication changes that.
- Constructing TOML, a path, or metadata. That is not proof of wire dispatch or AI-powered review.

Only a capability-proven, consented observation arm with real observation evidence earns
`hook_observed`. Absent, empty, paused, or degraded observation status does not.

## Findings and responses

Choose one recorded response per finding: accept and act, provide additional evidence, revise the
claim, dispute with evidence, or state an unresolved limitation. Then recheck after material change.

A response never deletes the original challenge. That is the point — the record keeps the
disagreement visible.

No disposition resolves a finding. Agents can record `acknowledged`, `acknowledged_not_done`,
`self_verified`, `provenance_disputed`, or `rejected`; `waived` is reserved for an authorized local-CLI human. Each records what was decided
and what evidence was attached; none clears the finding for receipt purposes. A readable response
does clear the status surface's `unanswered_finding_count`, while the actionable finding remains in
`receipt_blocking_finding_count` (except `self_verified`, below).

Observation-authored, non-actionable findings (such as "Observation coverage is incomplete or
stale") are disclosed coverage limitations: they never count in `unanswered_finding_count` and need
no response, and they stay listed in status and on the receipt. Acknowledging one is optional, and
it never resolves the finding.

What does resolve a finding is proof: a later check that tested the repaired record and found the
same issue absent. That check must cover the finding — the whole case, or a scope that names the
finding's subject — with the owning policy pack run to completion, nothing suppressed, and its
proof inputs readable. Case-wide host-observation limitations (`captured_object_unavailable`,
`content_unselected`, `host_outcome_unavailable`, and `unpaired_event`) do not veto a local
finding's otherwise clean structured-ledger proof; they remain receipt coverage limitations. This
exception requires the finding's own recorded coverage to have been readable; host-observation
gaps on a hook-derived finding remain tolerated, and the exception never applies to an AI-powered
finding. Redacted or unavailable event payloads, redacted objects, missing references,
unknown events, weak original finding coverage, suppression, stale state, scoped-away work, or a
failed pack still change nothing, and a check that reports the same issue again keeps it current.

For an AI-powered finding, the recheck's reviewer also rules on each earlier finding it was shown.
A `fixed` ruling resolves that finding on that check even when the review could not assess the rest
of the case, but only if it cites evidence or a result recorded after the finding and every other
rule above still holds. A `fixed` that cites nothing newer counts only as unassessable, any other
ruling except `withdrawn`, which leaves the ordinary rules, keeps the finding current and names
why, and a ruling is never inferred from silence. An earlier finding the review was not shown (the
section was full or trimmed), or whose ruling was dropped as malformed, stays current on that check.

In a long session the AI-powered review sees a bounded part of the record, and coverage says so
with `semantic_reference_scope_reduced`. That limitation stays on every check, status view, and
receipt. It does not stop a repaired local finding from resolving, because the local check still
reads the whole record. An AI-powered finding raised under the same bounded review can resolve
once you repair it and a later AI-powered review completes without returning it. That review
must have actually sent the reviewer the finding itself (what was found, what it named and your
answer), the repair evidence your response cites, and the change you made. Each item the finding
named must also be accounted for: shown again, replaced by a corrected claim the review was shown,
or an early record that long work pushed out of the review's recent-history window. Correcting the
claim a reviewer criticised therefore does not keep the finding open. A mention, a link, or a note
that the item was left out or withheld does not count; a record shown through the event that
recorded it, or any part of a multi-part captured excerpt, does. Captured tool output counts only
when its own excerpt was shown. Cite your repair's evidence rather than only a result:
a result without evidence stays in a bounded review only while it is recent, while cited evidence
is selected first. If it did not send them, the finding stays current and names
`finding_material_outside_reduced_review_scope`. If the check also shows
`semantic_included_refs_not_recorded`, Yoetz could not record what that review sent. Make sure the
repair evidence is recorded and cited in your response, then run one new check. If it shows the
same code again, stop rechecking, keep the finding open and disclose it. While a finding stays
open, its explanation names the latest check that could have resolved it; a later check scoped to
other work, or one without a completed AI-powered review, cannot. A review whose scope became
bounded only after the finding was raised, or a clipped payload (`truncated_payload`), still leaves
the finding current.

A resolved finding is not erased. Status still lists it (`resolved: true`, shown when
`include_resolved` is requested), the receipt still carries it as history, and the receipt wording
says how many earlier findings were resolved by a later qualifying check, apart from any findings
that are still current and from any coverage limitations. Its own recorded coverage no longer lowers
the receipt's coverage; current findings, the current record, and the applicable check still do. One
exception is fixed by the released status wire: a finding whose latest response is
`provenance_disputed` stays current even after such a check.

Findings are a to-do list that ends. Each one is `open` or in a final state: `verified_resolved`
(proved absent as above), `acknowledged_not_done` (the agent said, with a required reason, that it
will not do it), or `rejection_accepted` (the agent rejected an AI-powered finding with a reason and
a later review withdrew it; a withdrawal wins over the same review not raising it again, so such an
item never reads as proved absent). A final item never changes again and is not reviewed again; a
later `respond` to it records nothing and answers `finding_terminal`. New evidence about the same
problem comes back as a new finding. `acknowledged_not_done` is an honest "not done": it keeps the
receipt from reading clean and appears in its own "Acknowledged, not done" section.

`self_verified` is the final state for a finding you repaired that Yoetz cannot prove repaired
because of its own limits (a *Yoetz limit*: content it could not capture or had to redact, lost
observations, a review packet that could not show the repair). You verify the repair yourself,
record that evidence, and respond `self_verified` with how you verified it and the evidence ids.
Yoetz accepts it only after a later check of the finding and only when that check no longer sees
the issue itself (`finding_not_rechecked` and `finding_not_proof_limited` otherwise). The item stops
being your work and never counts as receipt-blocking, but it is never resolved: closure readiness
lists `finding_self_verified` as a standing limitation, the receipt names it in its own
"Self-verified by the agent; Yoetz could not prove the repair" section, and the receipt's
conclusion is at best `insufficient_coverage`. A Yoetz limit is never a `yoetz-blocker`.

Three more things the receipt discloses in their own sections, by id only:

- **Assumptions and verification limits.** When you make a best-effort choice, or a check is
  inherently out of reach (a hidden verifier, a private trace), that is not a blocker: finish the
  work and record a decision whose statement holds the line `yoetz-assumption:<obligation id>` or
  `yoetz-verification-limit:<obligation id>`, with the assumption or limit as the rationale. Closure
  readiness lists `assumption_disclosed` or `verification_limit_disclosed` as standing
  limitations, and the receipt names each one under "Assumptions and verification limits the agent
  disclosed". Nothing is blocked or resolved by it; supersede the decision to withdraw it.
- **Obligations acknowledged as not done.** For an obligation you truly will not do, after
  trying to repair it, publish it again with `status: "acknowledged_not_done"` and an
  `acknowledged_not_done_reason` (event version 1.1.0). It is no longer open work, readiness lists
  it under `acknowledged_not_done`, and the receipt names it under "Obligations acknowledged as not
  done" and never reads clean. Publishing the obligation again as `open` (or `resolved` with
  evidence) takes it back.
- **Findings the review says the task requires.** A finding you answered `acknowledged_not_done`
  whose review challenge says the task itself requires the work is listed as
  `finding_premise_disputed` and under "Not done although the review says the task requires it".
  A Stop asks you about it once.

`duplicate_of` is only for a genuine restatement: a new finding of the same origin and kind that
names the same issue as an earlier finding you already answered. It is not a final state of its own
and never resolves the new finding: the finding stays open until its own check proves it absent,
and it is counted once with the earlier finding meanwhile. It carries over only the earlier
finding's never-clean answers (acknowledged not done, self-verified), and the receipt lists each
link by ids in a "Linked duplicates" section. A later check that raises the finding again, or a
review that says it is still present, breaks the link; it then needs its own answer.
`rejection_accepted` no longer blocks the receipt's conclusion but is listed in its own "Rejection
accepted" section. Both sections name finding ids only. A review that restates a recorded AI-powered
finding without anything recorded since does not add a second item: it is seen again and suppressed,
and the check discloses `semantic_restatements_suppressed`.

The check result's `finding_checklist` and `status` with the `findings` view show each item's state
and how many later reviews left it open, against the owner's budget
(`verification.finding_attempt_budget`, default 5), for example `[ ] F-3 open (2/5)`. At the budget
Yoetz asks for a decision: repair with new evidence; if you repaired it and only a Yoetz limit keeps
it unproven, verify it yourself and respond `self_verified`; respond `acknowledged_not_done` with
the reason only if you truly will not or cannot do it. It never limits checks and never closes or acknowledges anything on anyone's behalf.

Repairing the record is therefore the way back to a stronger receipt: repair, recheck, and read the
finding's `resolved` state rather than assuming that absence alone qualified. If the issue re-fires,
or it does not re-fire but remains current because the recheck did not qualify, stop rechecking the
unchanged state; request the bounded receipt and disclose the current finding and limiting coverage.
Neither case supports a clean completion receipt.

Responding does not throw the check away. A recorded check still counts toward a later receipt when
the only events between the two are responses to findings that check itself returned,
acknowledgements of observation-authored non-actionable findings, and/or a finding-free suffix made entirely of service-stamped observation records. The receipt folds the
check's coverage, including `semantic_model_derived`, and carries the gap
`check_current_as_of_earlier_frontier` naming the subject frontier that was tested. The verdict is
current as of that earlier frontier, not the receipt's, so the receipt is still coverage-incomplete.
The limitations text says which kind of record followed the check: responses to its findings (or
to observation-authored coverage limitations), finding-free host observations, or both. Observation records are retained but were not evaluated by
that check; a re-check evaluates them, and routine observation can move the ledger again afterwards.

Any other material event after the check — published work, a new finding (including an
observation-authored finding), any other response to a finding the check did not return (a
rejection of an observation-authored finding included), or a response whose payload is redacted or
unreadable (it cannot prove which finding it answered) — requires a re-check first. The receipt
reports `check_not_applicable` and the check contributes nothing until it is re-run at the current
frontier. `status` applies the same rule, so status and a receipt at the same frontier never
disagree about what was checked. Lifecycle records such as `work_closed` are not material and never
require a re-check.

The cheapest finding is the one that never fires. Before the first `check`, confirm that every
requested item has an exact `attempted_items` entry on the `action_recorded` event that attempted
it — `attempted_items` belongs to that family alone, never a claim, and each entry copies the
obligation's `requested_items` `value` string exactly — that every claim has linked evidence, and
that every open obligation is either resolved or deliberately left open with a stated reason.
