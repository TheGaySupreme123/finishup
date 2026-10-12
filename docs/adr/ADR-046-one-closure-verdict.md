# ADR-046 — One closure verdict, printed by every surface

**Status:** Accepted for [issue #1026](https://github.com/TheGaySupreme123/yoetz/issues/1026)
(tb4n3 core issue RC-3, lane W2-A: sixteen of sixteen successful runs ended on "Nothing further to
do" and then received a receipt below clean, and the same finding read four different ways on four
surfaces). Maintainer acknowledgement (TheGaySupreme123, 2026-10-11 owner decisions Q1-Q4 on the
RC-3 design): the predicted conclusion is a separate sentence appended after the owner-approved
stop sentence, which stays byte for byte; Yoetz's own review-packet budgets are a disclosure only
when the review succeeded and reported no insufficiency; `evidence_content_digest_only` keeps
bounding; and a reviewer's request to state a limitation needs one agent acknowledgement before it
settles. It adds optional fields to the unreleased `status-result` 1.4.0, `check-result` 1.4.0,
`respond-result` and `receipt-document` 1.3.0, adds values to two closed enums
(`request_ruling`; `disclose_limitations`, 2026-10-12), and changes no released wire shape. It grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/yoetz/kernel/closure_class.py` (the classifier),
`src/yoetz/kernel/gap_effect.py` (the gap table), `src/yoetz/kernel/receipt_prediction.py`,
`src/yoetz/kernel/closure_verdict.py`, `src/yoetz/application/closure_basis.py`,
`src/yoetz/kernel/closure_readiness.py`, `src/yoetz/kernel/receipt_builder.py`,
`src/yoetz/kernel/deterministic_scope.py`, `src/yoetz/kernel/finding_todo.py`,
`src/yoetz/kernel/receipt_capacity.py`, `src/yoetz/kernel/ranking.py`,
`src/yoetz/kernel/check_totals.py`, `src/yoetz/domain/findings.py`
(`is_limitation_request`, `finding_demands_work`), `src/yoetz/domain/receipts.py`,
`src/yoetz/application/status.py`, `src/yoetz/application/check.py`,
`src/yoetz/application/receipt.py`, `src/yoetz/adapters/memory/ledger.py`,
`src/yoetz/protocol/models.py`, `src/yoetz/protocol/readiness_text.py`, `src/yoetz/mcp/summaries.py`,
`src/yoetz/cli/render.py` (shared by the terminal panel), `src/yoetz/domain/closure.py`,
`src/yoetz/domain/compaction_recap.py`, `scripts/generate_schemas.py`.
**Relates to:** ADR-032 (closure readiness checklist), ADR-033 (task facts and the Stop-time gate),
ADR-034 (proof-limited findings), ADR-035 (declared delivered set), ADR-040 (reviewer
disagreement), ADR-041 (obligation status re-derived), ADR-043 (bounded agent-facing text),
ADR-045 (derived facts carry lineage).

## Context

Roughly fourteen places answered the question "does this item still bound closure?" with their own
rule. They agreed only by accident, and tb4n3 (28 real Codex runs) measured the accident failing:

| Surface pair | What disagreed |
|---|---|
| status vs receipt | Status read `ready_with_limitations` / "Nothing further to do" while the receipt read `unresolved_findings_remain` (cargo D, ks S) or `insufficient_coverage` (music D, html D, payments D). Sixteen of sixteen successful runs; none of the sixteen receipts was clean. |
| status line vs status line | The MCP text said "receipt-blocking findings: 1 ... Nothing further to do" in one breath. An acknowledged requirement was settled for readiness and blocking for the counter. |
| readiness vs check next step | The check's next step called an acknowledged obligation open work (`review_recorded_work`) while status called it settled. |
| status vs Stop gate | The gate offered repair or acknowledgement for a rejected finding that only a reviewer ruling could settle (ks S), and asked a re-read the status text never announced. |
| receipt vs check verdict | A gap a full check tolerated bounded the receipt, and a Yoetz-side budget bounded the conclusion although the agent could do nothing about it (`check_time_change_truncated` and others). |
| receipt vs lineage vs recap | Child-task rollups and the post-compaction recap re-derived "blocking" again. |

No surface was wrong about its own question. The defect is that nothing computed the receipt's
question before the receipt existed, and nothing owned the answer.

## Decision

### 1. Two axes: who owes the next move, and what it does to the receipt

Every current finding and every effective obligation has a **class** and an **effect**, both
derived from the ledger prefix by `kernel/closure_class.py` (nothing is stored; a ledger replays to
the same verdict after a restart, a reattach or an upgrade).

* The **class** says who owes the next move: `agent_work` (the agent can still act),
  `awaiting_ruling` (a finding only: the agent rejected it with a reason and a reviewer ruling is
  owed), `settled_unmet` (the agent acknowledged a requirement as not done), `settled_disclosed`
  (final, and the receipt discloses it) or `resolved`.
* The **effect** says what it does to the receipt: `none`, `insufficient_coverage` or
  `unresolved_findings_remain`.

Class and effect are separate on purpose: *settled is not harmless*. A settled item can still hold
the receipt below clean, and an item that is agent work can carry no receipt effect. The pair is
looked up in two closed tables (`FINDING_BASES`, `OBLIGATION_BASES`); a `basis` token names the
row, so a surface can say why.

| Finding basis | Class | Effect |
|---|---|---|
| `open_unanswered`, `open_answered`, `reopened` | agent_work | unresolved_findings_remain |
| `limitation_requested` | agent_work | insufficient_coverage |
| `rejected_awaiting_ruling` | awaiting_ruling | unresolved_findings_remain |
| `rejected_review_unavailable` | settled_disclosed | insufficient_coverage |
| `acknowledged_not_done_requirement`, `limitation_acknowledged_not_done` | settled_unmet | unresolved_findings_remain |
| `acknowledged_not_done_bookkeeping`, `self_verified`, `disputed_after_rebuttal`, `limitation_disclosed` | settled_disclosed | insufficient_coverage |
| `rejection_accepted` | settled_disclosed | none |
| `absence_proved`, `absence_proved_after_acknowledged_not_done`, `absence_proved_after_self_verified` | resolved | none |

| Obligation basis | Class | Effect |
|---|---|---|
| `open`, `blocker_claimed`, `resolved_deliverable_emptied` | agent_work | insufficient_coverage |
| `acknowledged_not_done` | settled_unmet | insufficient_coverage |
| `blocker_confirmed`, `externally_evaluated` | settled_disclosed | insufficient_coverage |
| `resolved` | resolved | none |

Rules the tables encode:

* **A reasoned rejection of an AI-powered finding awaits a ruling.** It is not agent work: the next
  move is a check (the review rules), so status says `request_ruling` and the gate never offers
  repair or acknowledgement for it (ks S). When the review cannot rule (the route recorded no
  review, or the review is undeliverable), the rejection is `rejected_review_unavailable`, settled
  and disclosed, instead of waiting for a ruling that cannot come. `review_can_rule` is derived from
  the latest check's recorded route and semantic status.
* **A reviewer's request to state a limit is answered by the agent, and the answer decides what it
  means (owner decisions Q4 and 2026-10-12).** A `state_unresolved_limitation` challenge on a
  requirement-shaped kind is agent work with the single next action `acknowledge`, counted as
  "to disclose" and never as receipt-blocking work. A reasoned `acknowledged` (or a reasoned
  `self_verified`, or a `yoetz-verification-limit:<obligation>` decision covering the obligation the
  finding concerns) says the requirement may be met but cannot be verified here: the item is
  `limitation_disclosed`, settled, and the receipt discloses it under "Verification limits" at
  `insufficient_coverage`. It is named once, as disclosed: never under "Acknowledged, not done",
  never in `closure_readiness.acknowledged_not_done`, and its explanation says what was disclosed,
  never "repair it, then check". `acknowledged_not_done` says the requirement is NOT met: the item is
  `limitation_acknowledged_not_done`, `settled_unmet`, receipt `unresolved_findings_remain`, listed
  like any requirement acknowledged as not done and never under "Verification limits". (The Q4
  reading "any respond acknowledgement settles it" is replaced: it moved the lake S finding
  `fnd_8bdad2d0`, whose accuracy really was unmet, from unresolved to `insufficient_coverage`.)
  A decision line never turns an `acknowledged_not_done` answer into a disclosure; the agent takes
  the answer back with `reopened` and then discloses. The decision line still marks the obligation
  `externally_evaluated`, whatever the finding's answer was. Before any answer nothing changed:
  `limitation_requested`, "to disclose", next action `acknowledge`, never repair work. Guards: an
  `act` challenge never qualifies, and the agent's own words never make a finding a limitation.
  The check continuation for a request nobody answered is its own value, `disclose_limitations`
  (next bullet).
* **A bookkeeping finding the agent acknowledged is disclosed, not unmet.** `action_without_result`
  is the one work-integrity kind that records bookkeeping; acknowledging it as not done is
  `acknowledged_not_done_bookkeeping`. Every other kind keeps `acknowledged_not_done_requirement`.
* **Duplicates count once.** A `duplicate_of` chain reads under the earliest finding
  (`counts_as`), so counters and reasons never count a link twice. The group is represented by
  its most severe member, chosen by one function (`counted_findings`) that the counters, the
  receipt-blocking count, readiness and the prediction all read: receipt effect first
  (`unresolved_findings_remain`, then `insufficient_coverage`, then `none`), then class
  (`agent_work`, `awaiting_ruling`, `settled_unmet`, `settled_disclosed`, `resolved`), then the
  lowest finding id. A group therefore never reads cleaner than its worst member, and
  `to do + unmet` always equals `receipt_blocking_finding_count`.
* **The check continuation reads the class.** The checklist `next` and the overall `next` treat
  only `agent_work` as work; `awaiting_ruling` is `request_ruling`; a settled basis such as
  `limitation_disclosed` or `rejected_review_unavailable` keeps its `open` to-do state but is never
  work. A limitation request nobody answered is agent work that asks for a disclosure, not a repair
  (owner decision 2026-10-12): when it is the only remaining agent work the value is
  `disclose_limitations` on both `finding_checklist.next` and `overall_next.action` (with the
  request ids as `target_refs`), so the JSON and the text agree; mixed with real work the value
  stays `work_open_findings`, all agent-work ids are targets and the text names how a limitation
  request is answered. `disclose_limitations` ranks after `work_open_findings` and before
  `request_ruling`: the agent can disclose now, the ruling needs a check after it. When the closure
  basis cannot be read the check returns without the checklist rather than guess a class.
* **Acknowledged lists follow the class.** An acknowledged obligation that is also
  `externally_evaluated` is listed once, as disclosed, never under "acknowledged not done".
  A `resolved_deliverable_emptied` obligation counts as unfinished work (the prediction says
  "unfinished obligation(s)", not "open"); readiness' "open obligations" counts status-open ones
  only, and the `declared_output_emptied` gap directs the agent to restore the file.
* **`reopened`.** A finding whose latest response is `reopened` has basis `reopened`
  (`agent_work`, `unresolved_findings_remain`).
* **An absence proof wins.** A later qualifying check that proves a finding absent resolves it
  whatever the agent said before.

### 2. One table of what each gap does to a receipt

`kernel/gap_effect.py` holds `GAP_EFFECT_TABLE`: one row per recorded gap code (213) plus three
readiness-only tokens (`finding_rejection_awaiting_ruling`, `finding_limitation_disclosed`,
`finding_rejection_unreviewable`), 216 rows. A row has a readiness group (the unchanged
`GAP_CLASSIFICATION` is now a view of the table, version `"7"`), a per-route effect spec for a
deterministic-only route and a review route, a rule id and a closed `why`. A `GapContext` carries
the facts a context-dependent row needs; every default is the conservative answer. The effect
kinds are `actionable` (an agent action removes it), `standing_bounding` (no action removes it and
it holds the conclusion below clean), `disclosed` (shown, never bounds) and `historical`
(a cleared gap, ADR-032 amendment of 2026-10-08).

| Spec | Effect |
|---|---|
| A | actionable on both routes |
| B | bounding on both routes (today's default) |
| D | disclosed on both routes; D* disclosed on the deterministic route and on a review route that succeeded and reported no insufficiency |
| R | `semantic_review_not_requested`: disclosed when the check recorded that its route did not require review; actionable while required review is not current; otherwise bounding |
| X | `check_current_as_of_earlier_frontier`: bounding exactly when the standing of the check says a later record is unclassified (`kernel/check_standing`, `CheckStanding.bounds_conclusion`); the agent's own answers are a disclosure |
| G | host-observation gaps (`captured_object_unavailable`, `host_outcome_unavailable`, `unpaired_event`, `compound_outcome_unavailable`): disclosed only while the applicable check carried the code and its command counters show no unknown or live-failed command; otherwise bounding |

Of the 213 recorded codes, 35 change; the rest keep today's behaviour under both routes, and a
conformance test freezes that against the table's own predecessor. The changes, each with its rule
(the rule id travels in the table, the test names every changed code):

* **G5 (eight codes, disclosed when the review succeeded).** Yoetz's own review-packet size budgets
  (`check_time_change_truncated`, `semantic_case_content_over_item_limit`,
  `semantic_reference_scope_reduced`, `semantic_review_refs_reduced`, and four more) cannot be
  cleared by an agent action, so they no longer hold a conclusion below clean *when the review
  succeeded and the same check carries no reviewer-reported insufficiency* (owner decision Q2). The
  same code beside a reviewer-reported insufficiency, or without a successful review, stays
  bounding.
* **G5b, G5c, G5d, G6 (twenty codes, disclosed).** The background advice pipeline's bounds, routine
  read summarisation bounds, the prior-findings section's own bound and an owner privacy choice or
  placeholder redaction are not agent tasks and never hold a conclusion below clean.
* **G7 (four codes).** `optional_semantic_review_blocked_by_policy`,
  `optional_semantic_review_registration_drift`, `semantic_relevance_review_not_run` and
  `semantic_review_not_configured` are disclosed on a deterministic-only route (the check asked for
  no review) and stay bounding on a route that required one.
* **G3 (`compound_outcome_unavailable`).** Joins the guarded host-observation set: a piped or
  chained command has one exit status.
* **G2 (`check_current_as_of_earlier_frontier`).** Follows `CheckStanding`, not a suffix guess.
* **G1 (`semantic_review_not_requested`).** Follows the route the check recorded.

`evidence_content_digest_only` and `evidence_digest_subject_legacy_unknown` keep bounding (owner
decision Q3): agent-supplied evidence Yoetz could only see by digest bounds what it proves.
An unclassified code (a code this build does not know) is actionable, never clean.

### 3. The receipt's question, asked before the receipt

`kernel/receipt_prediction.predict_receipt_conclusion(ClosureBasis)` is the receipt builder's
conclusion rules, extracted, ordered and named. The first rule that fires selects the conclusion
(the receipt's own order); every rule that fires is kept as a reason, the selecting rule first,
at most eight listed with `reason_total` saying how many fired.

| Rule | Reason codes | Conclusion |
|---|---|---|
| R1 | `completion_scope_gap` | insufficient_coverage |
| R2 | `findings_to_do`, `findings_awaiting_ruling`, `findings_unmet`, `child_findings_actionable` | unresolved_findings_remain |
| R3 | `limitations_to_disclose`, `findings_disclosed` | insufficient_coverage |
| R4 | `obligations_open`, `obligations_acknowledged`, `obligations_disclosed` | insufficient_coverage |
| R5 | `lineage_blocks` | insufficient_coverage |
| R6 | `no_applicable_check` | insufficient_coverage |
| R7 | `check_suppressed_findings` | insufficient_coverage |
| R8 | `check_verdict_insufficient` (a recorded `action_required` whose findings are all settled reads here instead of failing the receipt) | insufficient_coverage |
| R9 | `policy_execution_incomplete` | insufficient_coverage |
| R10 | `live_gap_bounds` | insufficient_coverage |
| else | | no_unresolved_deterministic_findings |

`receipt_builder.closure_basis_from_context` builds the basis from the receipt's own context and
`build_receipt` calls `predict_receipt_conclusion`, so the receipt's label and every prediction are
one function over one context: "status predicted X and the receipt said Y" cannot happen by
construction. A prediction is `provisional` while a live dependency fact a receipt cannot disclose
yet exists or a check is in flight. The status reads the same basis through
`application/closure_basis.load_closure_basis`, which rebuilds the receipt's context at the
frontier (the records, the deterministic case, the check, the gaps judged with the check's
`GapContext`). The derivation is memoized per `(session, frontier)` and reused only while the
adapter's projection object is identical, so it can never be stale; it holds at most eight
frontiers. If the basis cannot be read, status omits the prediction with a diagnostic and never
guesses one.

### 4. Counters, sentences and the wire

* `finding_counts {to_do, awaiting_ruling, unmet, disclosed, to_disclose, self_verify_eligible}`
  and `obligation_counts {open, acknowledged, disclosed}` come from the facts' closures and are the
  same numbers on every surface. `to_do` includes `awaiting_ruling`; `to_disclose` is a limitation
  request not yet disclosed and is never inside `to_do`.
* `receipt_blocking_finding_count` keeps its wire name and meaning: the findings the receipt would
  count as unresolved, `to_do + unmet` (a validator enforces it). No human surface prints the phrase
  "receipt-blocking" any more.
* `closure_readiness.predicted_receipt {conclusion, reasons[], reason_total, basis_frontier,
  provisional}` is the conclusion this frontier would carry, with the reasons (each: reason code,
  rule id, count, at most three referenced ids, the frontier it began at).
* `closure_readiness.awaiting_ruling_findings [{finding_id, since_frontier}]` (at most eight, by
  id) names the rejected findings that wait for a ruling and the frontier of the rejection.
* `closure_readiness.rechecks [{kind, key, subjects, rule, since_frontier}]` are the
  once-per-frontier re-reads the Stop gate may ask (`acceptance`, `acknowledgement`, `blocker`,
  `premise`), computed statelessly from the closures; delivery memory stays in the gate. Every
  surface that says "nothing further to do" announces them in the same sentence
  (`protocol.readiness_text.recheck_note`).
* Status finding rows gain `closure_class`, `closure_basis` and `next_actions`; obligation rows gain
  `closure_class` and `closure_basis`. The check's finding checklist gains the five closure
  counters, items carry the class and basis, and the check's next step gains the actions
  `request_ruling` and `disclose_limitations` and `predicted_conclusion`. The checklist `next`
  gains the same two values. Both were added in place on the unreleased `check-result` 1.4.0.
* **Owner decision Q1.** The predicted conclusion is a *separate* sentence appended after the
  owner-approved `ready_with_limitations` sentence, which stays byte for byte: "The receipt will
  read X: <reasons>." (or, while work remains, "A receipt requested now would read X: ..."). A
  surface that has no prediction prints nothing rather than guess. The counters follow it:
  "Findings to do: N (awaiting ruling: K); unmet (acknowledged requirements): M; disclosed: L; to
  disclose: J."
* **Receipt document 1.3.0 (additive, in place).** `limitation_disclosed_finding_ids`,
  `conclusion_basis {reasons[], reason_total}` and a gap `effect` (`bounds` or `disclosed`). The
  conclusion is never clean beside a disclosed limitation or a bounding gap, and
  `reason_total == 0` exactly when it is clean. Human renderings add a "Verification limits"
  block, a Summary that uses the same counters and a "Why <conclusion>" sentence, and the latest
  check's totals relabelled "Latest check (frontier N)" so they are not read as the final state.
  Earlier artifact versions keep their bytes and their absence reads as "no basis recorded".

### 5. What the consumers read

Every consumer that decided for itself now reads the closure: the readiness split
(`receipt_findings_unresolved` is actionable only for `agent_work`; `awaiting_ruling` raises the
agent-actionable token `finding_rejection_awaiting_ruling`), the finding counter, the check
checklist and next step (`_recorded_work_refs` uses obligation closures; an acknowledged obligation
is never work), the check verdict (`full_check_gaps_clean`, `deterministic_scope_is_clean` and the
scoped local verdict read the table with the check's route; a returned finding that demands no
work keeps a full check from reading complete), `ranking._verdict` and `check_totals`
(`finding_demands_work`), the receipt conclusion and its sections, status, the MCP text, the CLI,
the terminal panel, `closure_prepare` and the post-compaction recap. The Stop gate consumes the
readiness it is given (ADR-033 amendment).

## Alternatives rejected

* **Fix each pair.** Fourteen sites, fourteen rules: the next feature would fork them again. The
  failures were structural, not typographical.
* **Store the verdict.** A stored verdict goes stale on any append, redaction or recovery and
  creates a second source of truth. Everything here is a pure function of the ledger prefix.
* **Edit the owner-approved sentence.** Rejected by decision Q1; the stop sentence is an
  instruction, the prediction is a fact, and they stay in separate sentences.
* **Let the receipt label stay clean beside a disclosed limit.** A disclosed limit is the agent
  saying a requirement was not verified; the honest ceiling is `insufficient_coverage`.
* **Count a limitation request as receipt-blocking work.** It cannot be repaired by work, so the
  agent's only honest move was bookkeeping rounds (vpp S and payments S ran about fourteen). One
  acknowledgement settles it.

## Consequences

* A status that says "Nothing further to do" now also says what the receipt will read and why; the
  re-reads a Stop will ask are announced, so there is no surprise gate.
* Some receipts get less severe labels *for a stated reason*: a reviewer's limitation request the
  agent disclosed with `acknowledged` (or a decision line), and an acknowledged
  `action_without_result` bookkeeping finding, now read `insufficient_coverage` (never clean)
  instead of `unresolved_findings_remain`. A limitation request answered `acknowledged_not_done`
  keeps `unresolved_findings_remain`. Replay of the fifty-five n2 and n3 exports under the
  2026-10-12 decision: two receipts move (cargo-flight-dispatch D and pretrain-shard-corruption D
  in n3, each an acknowledged `action_without_result` bookkeeping finding) and none reaches clean;
  every limitation request answered `acknowledged_not_done` (lake S n2/n3, ks S, vpp S, payments S,
  cargo S) keeps `unresolved_findings_remain`, and pretrain S's self-verified request reads
  disclosed. Under the earlier Q4 reading (any acknowledgement discloses) the same replay had moved
  six.
* The host-observation guard (G) on the receipt now also requires the check's command counters to be
  complete; before, the check carrying the code was the only guard. It moved no label in the
  replayed corpus (the same checks were already below clean).
* `start` results keep the counter semantics they were frozen with (a durable object; their
  `receipt_blocking_finding_count` is not recomputed). Status is the live reading.
* Old ledgers replay unchanged. A receipt already issued is immutable. A new build asked for a
  receipt over an old ledger uses the *recorded* check verdict.
* Residuals: a reasoned rejection reads `awaiting_ruling` until the reviewer-ruling frontier is
  recorded (the lane that owns that reducer fact supplies it); the optional counterfactual "if the
  actionable items were cleared" is not computed.
* **Not switched: lineage rollups stay strict.** A child's findings reach the parent as a frozen
  `ChildFindingSnapshot` in the dependency manifest (`finding_id`, `kind`, `origin`, `priority`,
  `actionable`, `resolved`, `resolution_event_id`, `self_verified`). The snapshot is recorded in the
  parent's ledger and validated against the kind traits on replay; it carries no closure class or
  basis, so the parent cannot tell a child's `settled_unmet` from `settled_disclosed`, and
  `_child_finding_snapshot` (`application/lineage_coordinator.py`) deliberately keeps a child's
  `rejection_accepted` and `acknowledged_not_done` rows actionable and unresolved (issue #905: the
  child's own receipt discloses the terminal state; a rollup must not bend `actionable` or
  `resolved` to mean "withdrawn"). Carrying the class would be a manifest wire change (a
  protocol-gated design area) and would let a parent read a child's disclosure as clean, so the
  rollup keeps the strict reading and `lineage_blocks` / `child_findings_actionable` stay the
  reasons R2 and R5 name. A follow-up that wants the class on the manifest owns that wire bump.
* **`resolved_deliverable_emptied` is produced.** An obligation recorded `resolved` whose declared
  deliverable the newest applicable check found emptied or truncated (the path-keyed fact
  `declared_output_emptied`, ADR-045, not accepted by a `yoetz-assumption` decision) reads
  `resolved_deliverable_emptied` (agent work, `insufficient_coverage`) instead of `resolved`. A
  later material record (the file refilled by an edit tool or a shell write, the decision that accepts the path) supersedes that
  check, so the stale fact is not read and the obligation returns to `resolved` until the next
  check re-reads the file. The reviewer cannot approve around it: the fact is actionable on both
  routes (section 2), so a review that raises nothing still leaves the check below clean.

## Host and platform decisions

The verdict is computed in the service from the ledger and printed by the MCP status text, the
CLI and the terminal panel, which the three supported hosts (Codex, Claude Code, Cursor) share on
macOS, Linux and Windows through WSL 2. Nothing in it is host-shaped: no host adapter changes, and
the per-host runbooks need no new entry. The Stop gate is the one host-specific consumer; it reads
`closure_readiness` (the token `finding_rejection_awaiting_ruling`, the counters, `rechecks` and
`awaiting_ruling_findings`) in each host's own gate and is decided in ADR-033's amendment and the
three host runbooks.

## Amendment 2026-10-12 (owner decisions, issues #1024, #1031)

Recorded from the maintainer's decisions of 2026-10-12 (TheGaySupreme123):

1. **The agent's answer decides what a limitation request means.** `acknowledged` (with a reason), a
   reasoned `self_verified` or a `yoetz-verification-limit:<obligation>` decision say the
   requirement may be met but cannot be verified here: `settled_disclosed` / `limitation_disclosed`,
   receipt at best `insufficient_coverage`, listed under "Verification limits".
   `acknowledged_not_done` says the requirement is not met: `settled_unmet` /
   `limitation_acknowledged_not_done` (a new basis on the `closure_basis` enum and a third value of
   `respond` `closure_after.limitation`, both added in place on unreleased wire), receipt
   `unresolved_findings_remain`. The decision keeps lake S (`fnd_8bdad2d0`, reward 0, accuracy
   unmet) honest. Implemented once, in `kernel/limitation.py` (`limitation_standing`, state
   `limitation_acknowledged_not_done`) and `kernel/closure_class.py`; every consumer reads the class.
2. **The check says "disclose" in its own word.** `disclose_limitations` on `finding_checklist.next`
   and `overall_next.action` when the only remaining agent work is undisclosed limitation requests;
   mixed with real work the value stays `work_open_findings` and the text names both.
3. **Lineage rollups stay strict (owner decision, record only).** A child's limitation, disclosed or
   unmet, is read by the parent through the frozen `ChildFindingSnapshot`, which carries no closure
   class; the owner keeps the strict reading described under "Not switched: lineage rollups stay
   strict" above. No behavior changed. The Stop-gate decisions of the same date are recorded in the
   ADR-033 amendment.

## Amendment (tb4n4, issue #1044): one more row becomes agent work

`deliverable_references_undeclared_file` (a delivered file that loads a file the change created and
no item declares, ADR-035) moves from the `G4` disclosure family to its own rule `G0c`: readiness
`A`, actionable on both routes. It is the 36th changed row (`changed=True`, so the frozen
base-behaviour test names it); `GAP_CLASSIFICATION_VERSION` is `"8"` (status-result 1.4.0 admits
it, unreleased, in place). Nothing else in the tables changes: the obligation stays `resolved` (the
dependency is a delivery gap, not a withdrawn file), the receipt reads `insufficient_coverage`
through `live_gap_bounds` (R10), status reads `action_required`, and the Stop gate continues the
agent on the new `STOP_GATE_TOKENS` entry, so check, status, gate and receipt agree through this
one row. A disclosure decision is not an exit.

## Verification

`tests/unit/kernel/test_gap_effect.py`, `test_closure_class.py`, `test_receipt_prediction.py`;
`tests/unit/application/test_tb4n3_closure_consistency.py` (the moved tb4n3 repros);
`tests/unit/mcp/test_tb4n3_closure_verdict_text.py`;
`tests/integration/closure/test_closure_shapes.py` (`assert_surfaces_agree` over status in every
view, the MCP text, the CLI and terminal lines, `closure_prepare`, the check's next step and the
receipt in three formats, for each tb4n3 shape and its controls);
`tests/property/test_closure_verdict_properties.py`;
`tests/integration/application/test_closure_basis_cost.py`;
`tests/conformance/honesty/test_gap_classification_completeness.py`.
