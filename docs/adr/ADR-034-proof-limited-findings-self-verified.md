# ADR-034 — Proof-limited findings: the `self_verified` respond disposition

**Status:** Accepted for [issue #984](https://github.com/TheGaySupreme123/finishup/issues/984). The
owner chose this design on 2026-10-07 while reviewing TB4 run tb4n1: "I prefer this even if yoetz
can't find, let the agent respond and populate it." This counts as the maintainer
acknowledgement for this design-gated protocol change. It grants no runtime, credential,
disclosure or destructive-action authority.
**Implemented by:** `src/finishup/kernel/self_verification.py`, `src/finishup/kernel/finding_resolution.py`
(`finding_resolution_attempt`, `UNRESOLVED_FINDING_NEXT_STEPS`, `finding_is_resolved`),
`src/finishup/kernel/finding_todo.py`, `src/finishup/kernel/closure_readiness.py`
(`finding_self_verified`), `src/finishup/application/respond.py`, `src/finishup/domain/findings.py`,
`src/finishup/domain/events.py`, `src/finishup/domain/receipts.py`, `src/finishup/kernel/receipt_builder.py`,
`src/finishup/protocol/models.py`, `src/finishup/cli/render.py`, `src/finishup/mcp/descriptors.py`,
`src/finishup/mcp/summaries.py`, `scripts/generate_schemas.py`, and
`fixtures/canonical/review-dialogue-1.3.0.case.json`.
**Relates to:** ADR-032 (closure readiness), ADR-033 (Stop-time closure gate and blockers), and
issue #905 (`acknowledged_not_done` and terminal to-do states).

## Context

A finding is resolved only when a later qualifying check proves it absent
(`kernel/finding_resolution.py`). FinishUP's own limits can keep that proof out of reach for good:

- capture and observation loss (`command_attempt_uncorroborated`, `content_redacted`,
  `observation_input_loss`);
- review-packet limits (`semantic_packet_insufficient`, `semantic_reference_scope_reduced`, clipped
  diffs, content types the reviewer cannot see).

In tb4n1, readiness kept `receipt_findings_unresolved` agent-actionable in every case. The
Stop-time gate (ADR-033) then gave the agent two exits: repair, or stop for a `finishup-blocker`. The
agent could not repair a FinishUP limit, so it filed a blocker on finished work:

- 38 attempts declared a blocker, and every one of them had been gated first.
- 27 to 30 attempts blamed FinishUP for work they had already finished.
- Those blockers claimed "authority", "consent" or "dependency unavailable".
- The time spent after the work was done was a median of 4.8 minutes in D and 10.4 in S, against
  0.4 minutes in V.
- 38 receipts read `unresolved_findings_remain`, and none read clean.

`acknowledged_not_done` (#905) means "I will not do it". That is the wrong statement for work that
is finished.

## Decision

`respond` gains a terminal disposition, `self_verified`. The agent states three things:

- it repaired the finding;
- FinishUP cannot prove the repair because of a FinishUP limit;
- it verified the repair itself.

**Required fields.**

- `reason` (non-blank, at most 4096 bytes): how the agent verified the repair.
- `evidence_refs`: 1 to 64 ids of evidence or results recorded in this task.
- No waiver fields.

Any recorded `evd_`/`res_` id is accepted, whatever its evidence version, strength or content
availability. That includes a `digest_only` artifact row, the shape an image or binary
deliverable gets. Only the field rules are schema-enforced. Admission refuses with a typed
`INVALID_REQUEST` reason:

- `response_fields_invalid`: the reason is blank or there is no evidence;
- `finding_terminal`: the item is already final;
- `finding_not_rechecked`: no later check has tested the finding;
- `finding_not_proof_limited`: FinishUP still sees the issue, or names work the agent can do.

**Wire.** These versions change in place; all are unreleased on 0.3:

- respond-request/result 1.1.0;
- `response_recorded` 1.1.0, the event version shared with `acknowledged_not_done`;
- status-request 1.2.0 and status-result 1.4.0 (finding filter, row `todo_state`, readiness
  `gap_classification_version` "3");
- check-result 1.3.0 and 1.4.0 (`finding_checklist.counts.self_verified`);
- receipt-document 1.3.0 (`self_verified_finding_ids`, plus a rule that forbids
  `no_unresolved_deterministic_findings` beside it);
- closure-prepare-request 1.0.0.

**Effect.**

- **To-do state.** The terminal state is `self_verified`. `finding_is_resolved` never reports such
  a finding as resolved, even after a later absence proof. This is the same invariant
  `acknowledged_not_done` has: the item stays the agent's own verification and never becomes a
  FinishUP-proven row afterwards.
- **Agent work.** It is not agent work. `finding_blocks_receipt` is false for it, so it leaves
  `receipt_blocking_finding_count` and `receipt_findings_unresolved`. The Stop gate does not fire
  on it.
- **Readiness.** Readiness discloses the standing code `finding_self_verified`, which is new in
  gap classification version 3.
- **Receipt.** The receipt lists the ids in their own section, "Self-verified by the agent; FinishUP
  could not prove the repair", in JSON, markdown and text. Its conclusion is at best
  `insufficient_coverage`. This is a separate early-return in `receipt_builder._conclusion`.
- **Review.** The item is not reviewed again. A reviewer restatement folds onto it, as it does
  for `acknowledged_not_done`.

### Eligibility

The rule lives in `kernel/self_verification.py`: `self_verification_refusal(state, finding_id,
records) -> str | None`, `finding_proof_limited(...)`, and the pure
`reasons_proof_limited(reasons, origin)`. It reads only recorded checks, never response prose. It
does not change any proof rule.

1. Take the newest later check that could resolve the finding (`_could_resolve`), or else the newest
   later check (`finding_resolution_attempt`, the same choice the explanation makes). If there is
   none, or that check tested a frontier before the finding, refuse with `finding_not_rechecked`.
2. Compute that check's resolution reasons. The finding is **not proof-limited** when any of these
   holds:
   - the reasons are empty;
   - they name agent work: `finding_not_in_checked_frontier`, `matching_policy_not_completed`,
     `subject_outside_checked_scope`, `no_material_change_since_finding`, `findings_suppressed`
     (the check's ranking cap withheld findings, so whether the issue fired again is unknown), or
     an unreadable check or unreadable returned findings;
   - `semantic_review_not_completed`, unless that check's review could not complete for a durable
     reason (not requested, not configured, blocked by policy or forbidden data, classification
     uncertain, human denied, approval expired); a timeout, rate limit or unavailable transport is
     transient, so the agent runs `check` again;
   - they include a `coverage:<code>` that `GAP_CLASSIFICATION` does not class as standing
     (agent-actionable, route-dependent or unknown);
   - for a deterministic finding, `issue_returned_again`;
   - for an AI-powered finding, `issue_returned_again`, `reviewer_verdict_still_present` or
     `reviewer_verdict_answered_not_fixed`, unless the same check also carries a *packet* limit:
     `semantic_packet_insufficient`, `reviewer_assessment_incomplete`,
     `finding_material_outside_reduced_review_scope`, or a packet-side `coverage:` code (reduced
     reference scope, reduced refs, item or capacity limits, withheld or redacted review content,
     unselected, redacted or truncated content, a truncated or redacted check-time change). An
     unrelated capture or observation loss, or unproven freshness, never overrides a reviewer that
     saw the repair and still sees the issue.
3. `respond` also requires at least one cited evidence or result id recorded after the finding:
   evidence from before the repair cannot show that the repair was verified.
4. Every other reason is a FinishUP limit, so the finding is eligible. Because a standing code counts
   as a limit, a new gap code becomes self-verifiable as soon as `closure_readiness` classifies it
   standing.

### Texts

Every text that tells the agent what to do with an unresolved finding uses the same order:

1. Repair it, then check.
2. If you repaired it and FinishUP cannot prove it, verify it yourself, record that evidence, and
   respond `self_verified`.
3. Respond `acknowledged_not_done` only if you truly will not or cannot do it.

These texts are the finding explanation suffix (`UNRESOLVED_FINDING_NEXT_STEPS`), the CLI
budget hint and the `respond` descriptor. The shared sentence is
`domain.findings.SELF_VERIFIED_GUIDANCE`, and it says that a FinishUP limit is never a
`finishup-blocker`.

## Consequences

- **Gate and blockers.** A repaired finding blocked by a FinishUP limit no longer keeps readiness
  `action_required`. The gate stops pushing agents toward false blockers.
- **Receipts.** A receipt never reads clean on the agent's word alone. It discloses each
  self-verified id and stays at best `insufficient_coverage`.
- **Older artifacts.** A receipt artifact older than 1.3.0 has no terminal sections. There a
  self-verified item still counts as unresolved, as `rejection_accepted` does.
- **Lineage (owner decision, 2026-10-07: "carry it as self-verified").** A child task's
  self-verified finding rolls up to the parent as "self-verified by the child agent; FinishUP could
  not prove it". The frozen `child-dependencies-recorded` row keeps `actionable` and `resolved`
  honest (actionable by kind, never resolved) and adds `self_verified: true`, emitted only when
  true so every other manifest keeps its bytes. The parent evaluator keeps such a row out of its
  actionable set, so the parent never reads `unresolved_findings_remain` for work it cannot do,
  and names the same standing code `finding_self_verified` on an accepted child, which keeps the
  parent from reading clean: the parent receipt is at best `insufficient_coverage`. The
  receipt-document `1.3.0` child row carries `self_verified` and markdown/text render it, so the
  parent and child receipts agree. A pending or rejected child stays an annotation. The #905
  states `rejection_accepted` and `acknowledged_not_done` still read as actionable and
  unresolved in the snapshot.
- **Agent misuse.** An agent can still call a repair verified when it is not. The answer is
  attributable, carries the agent's own evidence ids, and is listed by id. The eligibility rule
  limits it to cases where FinishUP's newest check no longer positively sees the issue.

## Reverse path

A `self_verified` item is final:

- `respond` refuses anything further with `finding_terminal`;
- a replay of the same request (same `request_id`) returns the recorded answer; any other answer on the item is refused with `finding_terminal` and records nothing;
- a later positive sighting is never folded onto the terminal row: a local rule that fires again is allocated a new finding id (`prior_finding_ids` skips `self_verified` rows), and a reviewer restatement of the issue is minted as a new open finding instead of being suppressed.

The disposition never closes another finding and never removes a coverage gap. If the agent
wrongly self-verifies, the receipt still shows the item, its reason and its evidence, and a
reviewer or human reads them there.

## Amendment 1 (issue #996): `duplicate_of` links a re-raised finding to an earlier one

**Status:** Accepted. Owner decision on 2026-10-07 while reviewing tb4n1: "P4-2 (duplicate_of):
APPROVED. Build it after L5's D5 automatic `restates` linking so it covers what that misses." This
counts as the maintainer acknowledgement for this design-gated protocol change on the unreleased
`respond-request`/`respond-result` `1.1.0`, `response_recorded` `1.1.0`, `status-request` `1.2.0`,
`status-result` `1.4.0` and `receipt-document` `1.3.0` wires.

**Context.** In tb4n1 a reviewer concern raised again was minted as a new finding, so agents
answered the same issue repeatedly (music-harmony semantic: 34 publishes and 50 status calls after
the gate). D5 links a re-raise automatically when the reviewer cites the earlier open finding
(`restates`). It misses re-raises minted anyway: prior findings over the packet limit,
deterministic duplicates, and restatements of a terminal item.

**Decision.**

- `respond` gains the disposition `duplicate_of` with a required `duplicate_of_finding_id`.
  `reason` and `evidence_refs` are optional; waiver fields are refused. It is not terminal.
- Admission accepts only a genuine restatement. It refuses, with typed reason codes, a target
  that is the same finding (`duplicate_target_same_finding`), unknown or unreadable
  (`duplicate_target_unknown`), recorded after this finding (`duplicate_target_not_earlier`), of a
  different origin or kind (`duplicate_target_different_issue`: a different kind is a different
  issue), or itself linked as a duplicate (`duplicate_target_is_duplicate`; FinishUP refuses rather
  than re-pointing, and the refusal names the finding to link to). A finding other findings
  already link to cannot become a duplicate itself (`duplicate_has_duplicates`), so no chain forms
  through a later link. A finding whose link a check broke cannot be re-linked
  (`duplicate_link_broken`).
- A link holds while both findings are readable, the target is earlier with the same origin and
  kind, and no remaining readable check broke it (`kernel/projections.duplicate_link_holds`).
  While it holds the duplicate inherits only the earlier finding's never-clean final answers,
  `self_verified` and `acknowledged_not_done`. It never inherits `verified_resolved` or
  `rejection_accepted`: otherwise the duplicate stays `open` but answered, and only its own
  qualifying check resolves it. Readiness counts an open (or inherited) pair once, naming the
  earlier finding (`finding_todo.duplicate_counting_id`); an open duplicate of a resolved,
  rejection-accepted or non-actionable earlier finding is counted on its own.
- A linked duplicate stays in the next review's prior findings even when it inherited a final
  state, with `duplicate_of_ref`, and rulings on it are admitted, so a reviewer can rule
  `still_present` and break a wrong link.
- The link breaks while any later readable check returned the duplicate again, returned a local
  finding with its issue key (the rule fired again), or carried a `still_present` or
  `answered_not_fixed` ruling on it. An AI-powered issue key alone is too coarse to break a link.
  The projection records every such check (`duplicate_link_broken_by_check_event_ids`, emitted
  only when non-empty); redacting one removes only its id, exactly as a full replay over the
  remaining readable checks would. A broken link, or an earlier finding that became unreadable,
  leaves the duplicate needing its own answer.
- Status findings rows carry `duplicate_of_finding_id` exactly while the link holds. Receipts on
  the 1.3.0 artifact list `duplicate_finding_links` by ids in a "Linked duplicates" section.
- Lineage (issue #996, B2): a child's frozen finding rows read `resolved` from the same to-do
  predicate as the child's receipt, and a pair counted once by the child's readiness is one row,
  so a self-verified pair rolls up to the parent once.

**Honesty.** Linking never resolves a finding and never makes a receipt clean: a duplicate reads
resolved only when its own qualifying check proved it absent. An open duplicate keeps
`unresolved_findings_remain`; an inherited `acknowledged_not_done` keeps it blocking; an inherited
`self_verified` keeps the conclusion at best `insufficient_coverage`.

**Reverse path.** The link is not final. The agent can answer the duplicate with another
disposition at any time while it is not in an inherited final state; a later check or a review
breaks the link; redacting every breaking check restores it.

**Status of self-verified children (S2).** Status readiness lists the standing code
`finding_self_verified` when an accepted child holds self-verified findings, and the status lineage
row carries `self_verified_finding_count`, so status agrees with the parent receipt's
`insufficient_coverage` (ADR-027).

## Amendment (2026-10-08, issue #1020): `disputed_after_rebuttal`

[ADR-040](ADR-040-reviewer-disagreement-and-route-derived-review.md) adds a sixth to-do state,
`disputed_after_rebuttal`: the reviewer kept an AI-powered finding open after the agent's reasoned
`rejected` answer and cited nothing recorded after it. FinishUP records it, not the agent. Like
`self_verified` it is final, not agent work and never clean (readiness standing code
`finding_disputed_after_rebuttal`; receipt `disputed_after_rebuttal_finding_ids`); like
`rejection_accepted` it is latched by a check and cleared when that check is redacted.

## Amendment (2026-10-08): task facts are scoped per finding (#1018, ADR-042)

A `coverage:<code>` resolution reason whose code is a task fact no longer refuses `self_verified`
when that fact does not bear on the finding (`kernel.task_fact_scope`): an obligation-scoped fact
about another obligation, or the task-wide `edited_after_last_verification` on a finding that is not
about verification or evidence. When such a fact is the only reason left it still refuses (the
agent clears it by doing that work). Closure readiness, the Stop gate and finding resolution keep
every task fact task-wide. tb4n2 interleaved S: two review findings were refused only because of an
(also false, ADR-042 decision 5) edited-after-verification fact.

## Amendment (2026-10-11, issue #1030, tb4n3 RC-7): the answers are not one-way doors

`acknowledged_not_done` and `self_verified` were final: an agent that gave up (or verified a repair
FinishUP could not prove) and then did the work, or whose work a later check proved, stayed
receipt-blocking or stayed "disclosed" forever (pretrain S, N3-5). The reverse edges:

- **Absence proof after the answer.** `FindingProjectionRecord.resolution_frontier` is the tested
  frontier of the check named by `resolved_by_check_event_id`. `finding_is_resolved` is true for an
  `acknowledged_not_done` or `self_verified` answer when that frontier is later than the answer's
  ledger sequence: a qualifying check that tested the work after the answer proved the issue absent,
  so the finding is `verified_resolved`. A proof recorded before the answer does not resolve it.
- **`reopened`.** A new `respond` disposition takes an `acknowledged_not_done` answer back (reason
  required): the finding is `open` again and the standing position is retracted. It is refused
  (`response_fields_invalid` on `/disposition`) on every other state. `self_verified` takes no answer
  (it is upgraded by the proof above), and `verified_resolved`, `rejection_accepted` and
  `disputed_after_rebuttal` stay absolutely final (`finding_terminal`).
- **`closure_after`.** The `respond` result reports `{todo_state, limitation?}` as the answer leaves
  the finding, so the agent sees whether it settled a limitation request (`limitation_disclosed`),
  recorded it as unmet (`limitation_acknowledged_not_done`, owner decision 2026-10-12) or reopened
  work without a second `status` call.
- **Transitions table** (`kernel/finding_todo.TODO_TRANSITIONS`): `acknowledged_not_done` to `open`
  (`respond_reopened_with_reason`), `acknowledged_not_done` to `verified_resolved`, and
  `self_verified` to `verified_resolved`.

A reasoned `self_verified` over a reviewer's limitation request also discloses it (ADR-040
amendment): it is the agent's final reasoned word, and the request has no other exit once given.
`acknowledged_not_done` over a limitation request does not disclose it: it says the requirement is
not met, so the request is an unmet requirement (ADR-040 amendment of 2026-10-12).
Host decision: the change is in the shared kernel, respond and MCP paths, so Codex, Claude Code and
Cursor behave identically; no host gap.

## Amendment (2026-10-12, issue #1046, tb4n4): a cited `fixed` ruling outranks environment facts

tb4n4 recorded 39 `self_verified` answers in 24 of 61 tasks and 16 `resolution_attempt_required`
rounds after the reviewer had already ruled the finding `fixed`: environment facts on the check
(`verification_only_as_root` in container tasks) kept the AI-powered absence proof from qualifying,
so the agent self-verified work the reviewer had accepted. An admitted `fixed` ruling (which must cite
evidence or a result recorded after the finding) now tolerates every environment task fact, not only
`write_outside_workspace` and `obligation_blocked_outside_agent_control` (#1000):
`verification_only_as_root`, `install_into_private_env`, `install_into_yoetz_runtime` and the
planned-verification observer heuristics. The finding is `verified_resolved`; the facts stay on the
receipt and the resolution explanation names them. Facts about the deliverable, agent-actionable
facts and a silent review keep blocking, and the self-verification eligibility rule is unchanged.
See the ADR-040 amendment of 2026-10-12.

## Amendment (2026-10-13, tb4n5, issue #1049): the command mismatch is scoped too

`coverage:command_attempt_mismatch` follows the same per-finding scope as an obligation-scoped task
fact (ADR-042 amendment of 2026-10-13): it refuses `self_verified` only on a finding about the
mismatched obligation, the action that asserted the item, or the run or cited result linked into
that relation, and the refusal names the obligation, item and run ids it needs. The eligibility
rule is otherwise unchanged.

## Amendment (2026-10-20, issue #1118 V5): task facts come from the newest check that ran the policy

For an AI-powered finding, step 1 picks the newest later check that *completed a review*. After the
reviewer twice could not assess the finding (`unassessable_review_exhausted`) or the packet
(`semantic_review_skipped_insufficient_packet`), every later check skips the review, so that choice
froze on the last review and on the task facts it recorded. In tb4h-smoke10c (bun-sourcemap-leak)
the agent repaired a real reviewer finding, a regression test passed, and the agent then cleared the
failed planned verification the last review had listed; each `self_verified` was still refused with
that stale `coverage:planned_verification_failed`, and the closure loop ran for 51 more FinishUP
calls with the repaired finding formally open.

Task facts (`kernel.task_facts`) and `command_attempt_mismatch` are recomputed by every check over
the whole task. When a newer check than that review ran the finding's policy to completion over its
subject (`finding_resolution_attempt(..., require_review=False)`), eligibility reads those codes from
the newer check and every other reason (the reviewer's verdict and packet limits) from the last
completed review. A fact the newer check still lists, or a new one it lists, keeps refusing, and a
reviewer that still saw the issue on a full packet keeps refusing. Nothing resolves: `self_verified`
stays a disclosed, terminal answer that never makes a receipt read clean. Finding resolution, closure
readiness and the Stop gate are unchanged. Host decision: kernel rule, identical on every host.

The same refresh covers `no_material_change_since_finding` (#1118 V7). That reason is not a
reviewer ruling: each check computes it from its own pre-check projection. After two
`insufficient_packet` reviews with nothing recorded in between, the last review lists it; a repair
through a shell command (an `ActionKind.COMMAND`, which does not re-arm the stopped review round)
and a passing verification then reach only a local check that skips the review. Eligibility now
reads that reason from the newer policy-complete check too, so the repair is no longer stranded on
the old review's view. A newer check over unchanged work still lists it and still refuses.

A review refused as `failed` / `case_capacity_exceeded` (0fb47f325) is likewise a durable
FinishUP limit for this rule: the unchanged case is refused again, so `semantic_review_not_completed`
from it no longer reads as a transient retry; closure readiness ends such a closing review as
`semantic_review_no_judgment` until a material change asks for it again.

The review packet now labels the cut honestly (#1118): whenever the frozen case omits part of the
prior-finding context (finding prose the inner ceiling fallback withheld even though the owner
admitted it, or an earlier finding the section bounds could not carry), its `prior_finding_context`
reads `partial` with `content_unselected` and names the omitted findings; it never reads `complete`.
Not changed here (deferred to #1126): the fallback still drops that prose before unrelated bulk
excerpts. Until the packet keeps bounded finding substance ahead of them, a follow-up review may
still rule such a finding `unassessable`, now knowing its text was cut; this amendment makes the
self-verification exit reachable for the agent, which does hold the finding's substance (status
`findings` shows it).
